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

var server: *tcp.TcpServer = undefined;

pub fn init() bool {
    if (tcp.requestServer()) |srv| {
        server = srv;
        server.init(7000, serverEventCallback, 3, null);
        return true;
    }
    return false;
}

fn serverEventCallback(srv: *tcp.TcpServer, event: tcp.ServerEvent) void {
    _ = event;
    while (srv.accept(processHttpFrame, null)) |_| {}
}

const index_html = @embedFile("aurora_dashboard_demo.html");

var http_buffer: [1460]u8 = undefined;

const RequestJob = struct {
    file: []const u8 = &.{},
    offset: usize = 0,
    size: usize = 0,
};

var job: RequestJob = .{};

fn processHttpFrame(sock: *tcp.TcpSocket, event: tcp.Event, data: []const u8) void {
    switch (event) {
        .closed => {},
        .connected => {},
        .data => {
            logger.debug("HTTP Packet Received:\n{s}", .{data});
            var header: []const u8 = &.{};
            var content: []const u8 = &.{};
            if (std.mem.findPosLinear(u8, data, 0, "\r\n\r\n")) |idx| {
                header = data[0 .. idx + 2];
                content = data[0 .. idx + 2][0..];
            }

            var iter = std.mem.tokenizeScalar(u8, header, ' ');
            const state: HttpState = .ParseRequestType;
            var request_type: HttpRequestType = .GET;
            var request_path: []const u8 = &.{};
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
                job = .{ .file = index_html, .offset = 0, .size = index_html.len };

                var b = std.fmt.bufPrint(http_buffer[length..], "HTTP/1.1 200 OK\r\n", .{}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "Content-Type: text/html\r\n", .{}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "Content-Length: {d}\r\n", .{job.size}) catch unreachable;
                length += b.len;
                b = std.fmt.bufPrint(http_buffer[length..], "\r\n", .{}) catch unreachable;
                length += b.len;
            }

            // fill the first packet.
            const remaining = http_buffer.len - length;
            const num_packing = @min(remaining, job.size - job.offset);

            @memcpy(http_buffer[length..][0..num_packing], job.file[job.offset..][0..num_packing]);
            length += num_packing;

            _ = sock.send(http_buffer[0..length]);
            job.offset += num_packing;

            if (job.offset != job.size) {
                // now send as much shit as we can
                logger.debug("Attempting to send: {d} bytes to {f}\n", .{ job.size - job.offset, ipv4.fmtIpAddr(sock.daddr) });
                const num = sock.send(job.file[job.offset..]);
                logger.debug("Bytes sent: {d}\n", .{num});
                job.offset += num;
            }
        },
        .tx_available => {
            if (job.offset != job.size) {
                logger.debug("Attempting to send 2: {d} bytes to {f}\n", .{ job.size - job.offset, ipv4.fmtIpAddr(sock.daddr) });
                const num = sock.send(job.file[job.offset..]);
                logger.debug("Bytes sent2: {d}\n", .{num});
                job.offset += num;
            }
        },
    }
}
