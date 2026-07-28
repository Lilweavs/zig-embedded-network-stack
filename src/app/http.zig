const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const ipv4 = @import("../core/ipv4.zig");
const tcp = @import("../core/tcp.zig");

const logger = std.log.scoped(.http);

const HttpRequestType = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
};

const HttpRequest = struct {
    type: HttpRequestType,
    path: []u8 = &.{},
};

const HttpResponse = enum {};

const HttpState = enum {
    ParseRequestType,
    ParseRequestTarget,
    Invalid,
    Done,
};

var socket: *tcp.TcpSocket = undefined;

pub fn init(sock: *tcp.TcpSocket) void {
    socket = sock;
    socket.bind(7000, processHttpFrame, null);
    socket.listen();
}

var http_buffer: [1460]u8 = undefined;
pub fn processHttpFrame(sock: *tcp.TcpSocket, event: tcp.Event, data: []const u8) void {
    switch (event) {
        .closed => {
            sock.state = .LISTEN; // look for more requests
        },
        .connected => {},
        .data => {
            logger.debug("HTTP Packet Received:\n{s}", .{data});
            var header: []const u8 = &.{};
            var content: []const u8 = &.{};
            if (std.mem.findPosLinear(u8, data, 0, "\r\n\r\n")) |idx| {
                header = data[0 .. idx + 2]; // include the \r\n
                content = data[0 .. idx + 2][0..];
            }

            var iter = std.mem.tokenizeScalar(u8, header, ' ');
            const state: HttpState = .ParseRequestType;
            var request_type: HttpRequestType = .GET;
            var request_path: []const u8 = &.{};
            // first get the request type
            loop: switch (state) {
                .ParseRequestType => {
                    const str = iter.next() orelse continue :loop .Invalid;
                    if (std.ascii.eqlIgnoreCase(str, "get")) {
                        request_type = .GET;
                    } else if (std.ascii.eqlIgnoreCase(str, "head")) {
                        request_type = .HEAD;
                    } else if (std.ascii.eqlIgnoreCase(str, "post")) {
                        request_type = .POST;
                    } else if (std.ascii.eqlIgnoreCase(str, "put")) {
                        request_type = .PUT;
                    } else if (std.ascii.eqlIgnoreCase(str, "delete")) {
                        request_type = .DELETE;
                    } else {
                        @panic("not implemented\n");
                    }

                    request_path = iter.next() orelse continue :loop .Invalid;

                    if (iter.next()) |tmp| {
                        if (std.ascii.eqlIgnoreCase(tmp, "HTTP/1.1")) {} else continue :loop .Invalid;
                    } else continue :loop .Invalid;
                    continue :loop .Done;
                },
                .Done => {},
                else => {
                    logger.debug("request not implemented\n", .{});
                },
            }

            var length: usize = 0;
            if (request_type == .GET and std.ascii.eqlIgnoreCase(request_path, "/")) {
                var b = std.fmt.bufPrint(http_buffer[length..], "HTTP/1.1 200 OK\r\n", .{}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "Content-Type: text/html\r\n", .{}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "Content-Length: 13\r\n", .{}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "\r\n", .{}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "Hello, World!", .{}) catch unreachable;
                length += b.len;
            }

            sock.send(http_buffer[0..length]);
        },
    }
}
