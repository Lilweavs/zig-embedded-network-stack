const std = @import("std");
const tcp = @import("../../core/tcp.zig");
const parser_mod = @import("parser.zig");

const Parser = parser_mod.Parser;
const Request = parser_mod.Request;

const logger = std.log.scoped(.http_handler);

pub const ConnectionHandler = struct {
    const Self = @This();

    active: bool = false,
    socket: *tcp.TcpSocket = undefined,

    parser: Parser = .{},
    request: Request = .{ .method = .GET },

    recv_buf: [256]u8 = undefined,
    recv_len: usize = 0,

    file: []const u8 = &.{},
    file_offset: usize = 0,
    file_size: usize = 0,

    pub fn init(h: *Self, sock: *tcp.TcpSocket) void {
        h.* = .{
            .active = true,
            .socket = sock,
        };
        h.socket.setCallback(processHttpData, h);
    }

    pub fn processHttpData(sock: *tcp.TcpSocket, ctx: ?*anyopaque, event: tcp.Event) void {
        const h: *Self = @ptrCast(@alignCast(ctx.?));
        switch (event) {
            .connected => {},
            .data_received => {
                const n = sock.recv(h.recv_buf[h.recv_len..]);
                if (n == 0) return;
                h.recv_len += n;

                const result = h.parser.parse(h.recv_buf[0..h.recv_len], &h.request) catch |err| {
                    const code: u16, const reason: []const u8 = switch (err) {
                        error.MethodNotAllowed => .{ 405, "Method Not Allowed" },
                        error.BadRequest => .{ 400, "Bad Request" },
                        error.UriTooLong => .{ 414, "URI Too Long" },
                        error.HttpVersionNotSupported => .{ 505, "HTTP Version Not Supported" },
                    };
                    h.sendError(code, reason);
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
                        const target = h.request.target[0..h.request.target_len];
                        if (h.request.method == .GET and std.ascii.eqlIgnoreCase(target, "/")) {
                            h.serveFile(index_html);
                        } else {
                            h.sendError(404, "Not Found");
                        }
                    },
                    .Error => {
                        h.sendError(500, "Internal Server Error");
                    },
                }
            },
            .tx_available => {
                h.sendFileChunks();
            },
            .closed, .err => {
                h.active = false;
                h.socket.close();
            },
        }
    }

    fn serveFile(h: *Self, file: []const u8) void {
        h.file = file;
        h.file_offset = 0;
        h.file_size = file.len;

        var length: usize = 0;
        var b = std.fmt.bufPrint(h.recv_buf[length..], "HTTP/1.1 200 OK\r\n", .{}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.recv_buf[length..], "Content-Type: text/html\r\n", .{}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.recv_buf[length..], "Content-Length: {d}\r\n", .{file.len}) catch unreachable;
        length += b.len;
        b = std.fmt.bufPrint(h.recv_buf[length..], "\r\n", .{}) catch unreachable;
        length += b.len;

        const remaining = h.recv_buf.len - length;
        const num_packing = @min(remaining, file.len);
        @memcpy(h.recv_buf[length..][0..num_packing], file[0..num_packing]);
        length += num_packing;

        _ = h.socket.send(h.recv_buf[0..length]);
        h.file_offset = num_packing;
        h.sendFileChunks();
    }

    fn sendFileChunks(h: *Self) void {
        if (h.file_offset < h.file_size) {
            const remaining = h.file[h.file_offset..];
            const sent = h.socket.send(remaining);
            h.file_offset += sent;
        }
        if (h.file_offset >= h.file_size) {
            h.active = false;
        }
    }

    fn sendError(h: *Self, code: u16, reason: []const u8) void {
        var length: usize = 0;
        var b = std.fmt.bufPrint(h.recv_buf[length..], "HTTP/1.1 {d} ", .{code}) catch unreachable;
        length += b.len;
        @memcpy(h.recv_buf[length..][0..reason.len], reason);
        length += reason.len;
        b = std.fmt.bufPrint(h.recv_buf[length..], "\r\nContent-Length: 0\r\n\r\n", .{}) catch unreachable;
        length += b.len;

        _ = h.socket.send(h.recv_buf[0..length]);
        h.socket.close();
        h.active = false;
    }
};

const index_html = @embedFile("aurora_dashboard_demo.html");
