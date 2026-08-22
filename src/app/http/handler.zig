const std = @import("std");
const tcp = @import("../../core/tcp.zig");
const parser_mod = @import("parser.zig");

const Parser = parser_mod.Parser;
const Request = parser_mod.Request;

const logger = std.log.scoped(.http);

var packet: [25]u8 = undefined;

const GrillmonBinary = extern struct {
    protocol_version: u8 align(1) = 0,
    flags: u8 align(1) = 0,
    time_start: u32 align(1) = 0,
    temperatures: [4]i16 align(1),
    grill_set_point: i16 align(1) = 0,
    battery: u8 align(1) = 0,
    rssi: i16 align(1) = 0,
    battery_voltage: u16 align(1) = 0,
    uptime: u32 align(1) = 0,
};

// * Offset  Size  Type      Field
// * 0       1     u8        protocol version
// * 1       1     u8        flags
// * 2       4     u32       cook start time, Unix seconds
// * 6       8     i16[4]    temperatures, °F × 10
// * 14      2     i16       grill setpoint, °F × 10
// * 16      1     u8        battery percentage
// * 17      2     i16       Wi-Fi RSSI, dBm
// * 19      2     u16       battery voltage, mV
// * 21      4     u32       uptime, seconds

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
            .parser = .{},
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
                            logger.debug("HTTP: Request Complete -> {d}", .{sock.sport});
                            const consumed = h.parser.reset();
                            if (consumed > 0) {
                                std.mem.copyForwards(u8, h.recv_buf[0 .. h.recv_len - consumed], h.recv_buf[consumed..h.recv_len]);
                                h.recv_len -= consumed;
                            }

                            const target = h.request.target[0..h.request.target_len];
                            if (h.request.method == .GET and std.ascii.eqlIgnoreCase(target, "/")) {
                                h.serveFile(index_html);
                            } else if (h.request.method == .GET and std.ascii.eqlIgnoreCase(target, "/api/status")) {
                                const status = GrillmonBinary{
                                    .battery = 80,
                                    .grill_set_point = 225,
                                    .temperatures = .{ 100, 1000, 250, 300 },
                                    .rssi = -50,
                                    .time_start = 3600,
                                };
                                @memcpy(packet[0..], std.mem.asBytes(&status));
                                h.serveFile(&packet);
                                // * Offset  Size  Type      Field
                                // * 0       1     u8        protocol version
                                // * 1       1     u8        flags
                                // * 2       4     u32       cook start time, Unix seconds
                                // * 6       8     i16[4]    temperatures, °F × 10
                                // * 14      2     i16       grill setpoint, °F × 10
                                // * 16      1     u8        battery percentage
                                // * 17      2     i16       Wi-Fi RSSI, dBm
                                // * 19      2     u16       battery voltage, mV
                                // * 21      4     u32       uptime, seconds

                            } else {
                                h.sendError(404, "Not Found");
                            }
                            return;
                        },
                        .Error => return h.sendError(500, "Internal Server Error"),
                    }
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
            logger.debug("HTTP: chunk {d},{d} -> {d}", .{ h.file_offset, h.file_size, h.socket.sport });
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

// const index_html = @embedFile("aurora_dashboard_demo.html");
const index_html = @embedFile("grillmon.html");
