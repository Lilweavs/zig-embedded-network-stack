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
    Invalid,
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

const max_connections: usize = 3;

pub fn init() bool {
    if (tcp.requestServer()) |srv| {
        server = srv;
        server.init(7000, max_connections);
        server.accept_callback = accept;
        return true;
    }
    return false;
}

const index_html = @embedFile("aurora_dashboard_demo.html");

var http_buffer: [1460]u8 = undefined;

const RequestJob = struct {
    file: []const u8 = &.{},
    offset: usize = 0,
    size: usize = 0,
};

var connection_pool_backing_buffer: [max_connections]ConnectionHandler = undefined;
var connect_pool: std.ArrayList(ConnectionHandler) = .initBuffer(&connection_pool_backing_buffer);

const ConnectionHandler = struct {
    socket: *tcp.TcpSocket,
    parser: @import("http/parser.zig"),

    pub fn init(h: *ConnectionHandler, sock: *tcp.TcpSocket) void {
        h.socket = sock;
        h.socket.setCallback(h.processHttpData, h);
    }

    pub fn processHttpData(sock: *tcp.TcpSocket, ctx: ?*anyopaque, event: tcp.Event) void {
        const h = @as(*ConnectionHandler, (@ptrCast(ctx)));
        switch (event) {
            .connected => {},
            .closed, .err => {
                _ = connect_pool.addOneAssumeCapacity();
                sock.close();
            },
            .data_received => {},
            .tx_available => {},
        }
    }
};

fn accept(sock: *tcp.TcpSocket) void {
    const handler = connect_pool.addOneBounded() catch return; // silently drop if we are out of connections
    handler.init(sock);
}

fn processHttpFrame(sock: *tcp.TcpSocket, ctx: ?*anyopaque, event: tcp.Event) void {
    const job: *RequestJob = @ptrCast(@alignCast(ctx.?));
    switch (event) {
        .connected => {},
        .closed, .err => {
            _ = job_pool.addOneAssumeCapacity();
            sock.close();
        },
        .data_received => {
            const data = http_buffer[0..sock.recv(http_buffer[0..])];
            // logger.debug("HTTP Packet Received:\n{s}", .{data});
            var header: []const u8 = &.{};
            var content: []const u8 = &.{};
            if (std.mem.findPosLinear(u8, data, 0, "\r\n\r\n")) |idx| {
                header = data[0 .. idx + 2];
                content = data[0 .. idx + 2][0..];
            }

            var kv_iter = std.mem.tokenizeSequence(u8, header, "\r\n");

            const state: HttpState = .ParseRequestType;
            var request_type: HttpRequestType = .Invalid;
            var request_path: []const u8 = &.{};
            while (kv_iter.next()) |kv_str| {
                logger.debug("HTTP: kv -> {s}\n", .{kv_str});
                var iter = std.mem.tokenizeScalar(u8, kv_str, ' ');

                switch (state) {
                    .ParseRequestType => {
                        const str = iter.next() orelse return;
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

                        request_path = iter.next() orelse return;

                        if (iter.next()) |tmp| {
                            logger.debug("HTTP: {s}\n", .{tmp});
                            if (std.ascii.eqlIgnoreCase(tmp, "HTTP/1.1")) {
                                request_type = .GET;
                                break;
                            }
                        }
                    },
                    else => {},
                }
            }

            // TODO: move to an httpGet() function
            if (request_type == .GET) {
                if (std.ascii.eqlIgnoreCase(request_path, "/")) {
                    var length: usize = 0;
                    job.* = .{ .file = index_html, .offset = 0, .size = index_html.len };
                    logger.debug("HTTP: new job /index.html {d} bytes\n", .{index_html.len});

                    var b = std.fmt.bufPrint(http_buffer[length..], "HTTP/1.1 200 OK\r\n", .{}) catch unreachable;
                    length += b.len;
                    b = std.fmt.bufPrint(http_buffer[length..], "Content-Type: text/html\r\n", .{}) catch unreachable;
                    length += b.len;
                    b = std.fmt.bufPrint(http_buffer[length..], "Content-Length: {d}\r\n", .{job.size}) catch unreachable;
                    length += b.len;
                    b = std.fmt.bufPrint(http_buffer[length..], "\r\n", .{}) catch unreachable;
                    length += b.len;

                    const remaining = http_buffer.len - length;
                    const num_packing = @min(remaining, job.size - job.offset);

                    @memcpy(http_buffer[length..][0..num_packing], job.file[job.offset..][0..num_packing]);
                    length += num_packing;

                    logger.debug("HTTP: {d} -> {d}/{d}\n", .{ sock.sport, num_packing, job.size });

                    _ = sock.send(http_buffer[0..length]);
                    job.offset += num_packing;

                    if (job.offset != job.size) {
                        // now send as much shit as we can
                        const num = sock.send(job.file[job.offset..]);
                        job.offset += num;
                        logger.debug("HTTP: {d} -> {d}/{d}\n", .{ sock.sport, job.offset, job.size });
                    }
                }
            }
        },
        .tx_available => {
            if (job.offset != job.size) {
                const num = sock.send(job.file[job.offset..]);
                job.offset += num;
                logger.debug("HTTP: cb {d} -> {d}/{d}\n", .{ sock.sport, job.offset, job.size });
            }
        },
    }
}
