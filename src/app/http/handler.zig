const std = @import("std");
const tcp = @import("../../core/tcp.zig");
const parser_mod = @import("parser.zig");

const Parser = parser_mod.Parser;
const Request = parser_mod.Request;
const Connection = parser_mod.Connection;
const HttpError = parser_mod.HttpError;

const logger = std.log.scoped(.http);

pub const Response = struct {
    status: ?HttpError = null,
    content_type: []const u8 = "text/html",
    body: []const u8 = &.{},

    read_fn: ?*const fn () void = null,
    read_ctx: ?*anyopaque = null,

    content_length: usize = 0,
};

pub const RequestHandler = *const fn (req: *const Request, resp: *Response, ctx: ?*anyopaque) void;

pub const ConnectionHandler = struct {
    const Self = @This();

    active: bool = false,
    socket: *tcp.TcpSocket = undefined,

    parser: Parser = .{},
    request: Request = .{ .method = .GET },
    response: Response = .{},

    recv_buf: [256]u8 = undefined,
    recv_len: usize = 0,

    tx_buf: [256]u8 = undefined,

    file: []const u8 = &.{},
    file_offset: usize = 0,
    file_size: usize = 0,

    request_handler: ?RequestHandler = null,
    request_ctx: ?*anyopaque = null,

    pub fn init(h: *Self, sock: *tcp.TcpSocket, handler: RequestHandler, ctx: ?*anyopaque) void {
        h.* = .{
            .active = true,
            .socket = sock,
            .parser = .{},
            .request_handler = handler,
            .request_ctx = ctx,
        };
        h.socket.setCallback(processHttpData, h);
    }

    pub fn processHttpData(sock: *tcp.TcpSocket, ctx: ?*anyopaque, event: tcp.Event) void {
        const h: *Self = @ptrCast(@alignCast(ctx.?));
        switch (event) {
            .connected => {},
            .data_received => {
                logger.debug("HTTP: Data recved -> {d}", .{sock.sport});
                while (true) {
                    const n = sock.recv(h.recv_buf[h.recv_len..]);
                    if (n == 0) break;
                    h.recv_len += n;

                    const result = h.parser.parse(h.recv_buf[0..h.recv_len], &h.request) catch |err| {
                        const e: parser_mod.HttpError = switch (err) {
                            error.MethodNotAllowed => .MethodNotAllowed,
                            error.BadRequest => .BadRequest,
                            error.UriTooLong => .UriTooLong,
                            error.HttpVersionNotSupported => .HttpVersionNotSupported,
                        };
                        h.sendHttpError(e);
                        return;
                    };

                    switch (result) {
                        .NeedMore => {
                            const consumed = h.parser.consumedBytes();
                            if (consumed > 0) {
                                std.mem.copyForwards(u8, h.recv_buf[0 .. h.recv_len - consumed], h.recv_buf[consumed..h.recv_len]);
                                h.recv_len -= consumed;
                                h.parser.compact();
                            }
                        },
                        .Complete => {
                            logger.debug("HTTP: Request Complete -> {d}", .{sock.sport});
                            const consumed = h.parser.reset();
                            if (consumed > 0) {
                                std.mem.copyForwards(u8, h.recv_buf[0 .. h.recv_len - consumed], h.recv_buf[consumed..h.recv_len]);
                                h.recv_len -= consumed;
                            }

                            h.response = .{};
                            if (h.request_handler) |handler| handler(&h.request, &h.response, h.request_ctx);

                            h.sendResponse(&h.response);
                            return;
                        },
                        .Error => h.sendHttpError(.InternalServerError),
                    }
                }
            },
            .tx_available => {
                h.sendFileChunks(h.request.connection);
            },
            .closed, .err => {
                h.active = false;
                h.socket.close();
            },
        }
    }

    fn sendResponse(h: *Self, r: *Response) void {
        if (r.status) |err| return h.sendHttpError(err);

        var length: usize = 0;
        var b = std.fmt.bufPrint(h.tx_buf[length..], "HTTP/1.1 200 OK\r\n", .{}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.tx_buf[length..], "Content-Type: text/html\r\n", .{}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.tx_buf[length..], "Content-Length: {d}\r\n", .{r.content_length}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.tx_buf[length..], "\r\n", .{}) catch unreachable;
        length += b.len;

        const remaining = h.tx_buf.len - length;
        const num_packing = @min(remaining, r.content_length);
        @memcpy(h.tx_buf[length..][0..num_packing], r.body[0..num_packing]);
        length += num_packing;

        _ = h.socket.send(h.tx_buf[0..length]);
        h.file_offset = num_packing;
        h.sendFileChunks(h.request.connection);
    }

    fn sendFileChunks(h: *Self, connection: Connection) void {
        if (h.file_offset < h.file_size) {
            const remaining = h.file[h.file_offset..];
            const sent = h.socket.send(remaining);
            h.file_offset += sent;
            logger.debug("HTTP: chunk {d},{d} -> {d}", .{ h.file_offset, h.file_size, h.socket.sport });
        }
        if (h.file_offset >= h.file_size) {
            if (connection == .Close) {
                h.socket.close();
                h.active = false;
            }
        }
    }

    fn sendHttpError(h: *Self, e: parser_mod.HttpError) void {
        const buf = std.fmt.bufPrint(&h.tx_buf, "HTTP/1.1 {d} {s}\r\n\r\n", .{ @intFromEnum(e), e.reason() }) catch unreachable;

        _ = h.socket.send(buf);
        h.socket.close();
        h.active = false;
    }
};
