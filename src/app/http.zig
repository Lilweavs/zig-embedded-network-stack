const std = @import("std");
const tcp = @import("../core/tcp.zig");
const handler_mod = @import("http/handler.zig");
const ConnectionHandler = handler_mod.ConnectionHandler;

pub const Request = @import("http/parser.zig").Request;
pub const Response = handler_mod.Response;
pub const RequestHandler = handler_mod.RequestHandler;

pub const HttpError = error{
    BadRequest,
    NotFound,
    MethodNotAllowed,
    UriTooLong,
    InternalServerError,
    HttpVersionNotSupported,
};

pub fn code(e: HttpError) u16 {
    return switch (e) {
        error.BadRequest => 400,
        error.NotFound => 404,
        error.MethodNotAllowed => 405,
        error.UriTooLong => 414,
        error.InternalServerError => 500,
        error.HttpVersionNotSupported => 505,
    };
}

pub fn reason(e: HttpError) []const u8 {
    return switch (e) {
        error.BadRequest => "Bad Request",
        error.NotFound => "Not Found",
        error.MethodNotAllowed => "Method Not Allowed",
        error.UriTooLong => "URI Too Long",
        error.InternalServerError => "Internal Server Error",
        error.HttpVersionNotSupported => "HTTP Version Not Supported",
    };
}

pub fn httpErrorFrom(err: anyerror) HttpError {
    return switch (err) {
        error.BadRequest, error.NotFound, error.MethodNotAllowed, error.UriTooLong, error.HttpVersionNotSupported => |e| e,
        else => error.InternalServerError,
    };
}

const logger = std.log.scoped(.http);

var server: *tcp.TcpServer = undefined;

var request_handler: RequestHandler = undefined;
var request_ctx: ?*anyopaque = null;

const max_connections: usize = 3;

var connection_pool: [max_connections]ConnectionHandler = .{ ConnectionHandler{}, ConnectionHandler{}, ConnectionHandler{} };

pub fn init(handler: RequestHandler, ctx: ?*anyopaque) bool {
    if (tcp.requestServer()) |srv| {
        server = srv;
        server.init(7000, max_connections);
        server.accept_callback = accept;
        request_handler = handler;
        request_ctx = ctx;
        return true;
    }
    return false;
}

fn accept(sock: *tcp.TcpSocket) void {
    for (&connection_pool) |*handler| {
        if (!handler.active) {
            handler.init(sock, request_handler, request_ctx);
            return;
        }
    }
    logger.warn("max connections reached, dropping", .{});
    sock.close();
}
