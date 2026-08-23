const std = @import("std");
const tcp = @import("../../core/tcp.zig");
const parser_mod = @import("parser.zig");
const http = @import("../http.zig");

const Parser = parser_mod.Parser;
const Request = parser_mod.Request;
const Connection = parser_mod.Connection;
const HttpError = http.HttpError;

const logger = std.log.scoped(.http);

const code = http.code;
const reason = http.reason;
const httpErrorFrom = http.httpErrorFrom;

pub const Response = struct {
    content_type: []const u8 = "text/html",
    body: []const u8 = &.{},

    read_fn: ?*const fn () void = null,
    read_ctx: ?*anyopaque = null,

    offset: usize = 0,
    bytes_sent: usize = 0,
    content_length: usize = 0,
};

pub const RequestHandler = *const fn (req: *const Request, ctx: ?*anyopaque) anyerror!Response;

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
            .response = .{},
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
                        h.sendHttpError(err);
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

                            const handler = h.request_handler orelse {
                                h.sendHttpError(error.NotFound);
                                return;
                            };

                            h.response = handler(&h.request, h.request_ctx) catch |err| {
                                h.sendHttpError(httpErrorFrom(err));
                                return;
                            };
                            h.sendResponse(&h.response);
                            return;
                        },
                        .Error => h.sendHttpError(error.InternalServerError),
                    }
                }
            },
            .tx_available => {
                // TODO: check if we have an actual response. Maybe response should be a ?Response
                h.sendFileChunks(h.request.connection);
            },
            .closed, .err => {
                h.active = false;
                h.socket.close();
            },
        }
    }

    fn sendResponse(h: *Self, res: *Response) void {
        var length: usize = 0;
        var b = std.fmt.bufPrint(h.tx_buf[length..], "HTTP/1.1 200 OK\r\n", .{}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.tx_buf[length..], "Content-Type: {s}\r\n", .{res.content_type}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.tx_buf[length..], "Content-Length: {d}\r\n", .{res.content_length}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.tx_buf[length..], "\r\n", .{}) catch unreachable;
        length += b.len;

        const remaining = h.tx_buf.len - length;
        const num_packing = @min(remaining, res.body.len);
        @memcpy(h.tx_buf[length..][0..num_packing], res.body[0..num_packing]);
        length += num_packing;

        _ = h.socket.send(h.tx_buf[0..length]);
        h.response.offset += num_packing;
        h.response.bytes_sent += num_packing;
        h.sendFileChunks(h.request.connection);
    }

    fn sendFileChunks(h: *Self, connection: Connection) void {
        if (h.response.bytes_sent < h.response.content_length) {
            const remaining = h.response.body[h.response.offset..];
            const sent = h.socket.send(remaining);
            h.response.offset += sent;
            h.response.bytes_sent += sent;
            logger.debug("HTTP: chunk {d},{d} -> {d}", .{ h.response.offset, h.response.content_length, h.socket.sport });
        }
        if (h.response.offset >= h.response.body.len) {
            if (h.response.bytes_sent >= h.response.content_length) {
                if (connection == .Close) {
                    h.socket.close();
                    h.active = false;
                }
            } else {
                // TODO: notify user that we need more data
            }
        }
    }

    fn sendHttpError(h: *Self, e: HttpError) void {
        const buf = std.fmt.bufPrint(&h.tx_buf, "HTTP/1.1 {d} {s}\r\n\r\n", .{ code(e), reason(e) }) catch unreachable;

        _ = h.socket.send(buf);
        h.socket.close();
        h.active = false;
    }
};
