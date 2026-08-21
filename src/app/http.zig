const std = @import("std");
const tcp = @import("../core/tcp.zig");
const ConnectionHandler = @import("http/handler.zig").ConnectionHandler;

const logger = std.log.scoped(.http);

var server: *tcp.TcpServer = undefined;

const max_connections: usize = 3;

var connection_pool: [max_connections]ConnectionHandler = .{ ConnectionHandler{}, ConnectionHandler{}, ConnectionHandler{} };

pub fn init() bool {
    if (tcp.requestServer()) |srv| {
        server = srv;
        server.init(7000, max_connections);
        server.accept_callback = accept;
        return true;
    }
    return false;
}

fn accept(sock: *tcp.TcpSocket) void {
    for (&connection_pool) |*handler| {
        if (!handler.active) {
            handler.init(sock);
            return;
        }
    }
    logger.warn("max connections reached, dropping", .{});
    sock.close();
}
