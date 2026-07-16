const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax/udp.zig");
const ipv4 = @import("../core/ipv4.zig");

pub const UDPHeader = syntax.UDPHeader;
pub const createUDPHeader = syntax.createHeader;

const udp_pool_size: usize = 4;
var udp_pool: [udp_pool_size]UDPSocket = .{UDPSocket{}} ** udp_pool_size;

const UDPCallbackFn = *const fn (iface: *types.Interface, socket: *UDPSocket, addr: u32, port: u16, payload: []const u8) void;

const logger = std.log.scoped(.udp);

pub fn requestSocketFromPool() ?*UDPSocket {
    for (0..udp_pool.len) |i| {
        if (udp_pool[i].active == false) {
            udp_pool[i].active = true;
            return &udp_pool[i];
        }
    }
    return null;
}

pub fn returnSocketToPool(socket: *UDPSocket) void {
    for (0..udp_pool.len) |i| {
        if (&udp_pool[i] == socket) {}
    }
    socket.active = false;
}

pub fn processUDPFrame(iface: *types.Interface, saddr: u32, buffer: []u8) void {
    const header: UDPHeader = std.mem.bytesToValue(UDPHeader, buffer[0..@sizeOf(UDPHeader)]);
    const length: usize = @intCast(std.mem.bigToNative(u16, header.length));
    const dport = std.mem.bigToNative(u16, header.dport);
    const sport = std.mem.bigToNative(u16, header.sport);
    const payload = buffer[@sizeOf(UDPHeader)..length];

    logger.debug("UDP: Frame Received -> {d}:{d}\n", .{ dport, sport });

    for (&udp_pool) |*sock| {
        if (sock.active and sock.port == dport) {
            return if (sock.recv_callback) |callback| callback(iface, sock, saddr, sport, payload);
        }
    }
}

pub const UDPSocket = struct {
    const Self = @This();

    ip_addr: u32 = 0,
    port: u16 = 0,
    active: bool = false,
    recv_callback: ?UDPCallbackFn = null,
    context: ?*anyopaque = null,

    pub fn bind(self: *Self, port: u16, callback: ?UDPCallbackFn, context: ?*anyopaque) void {
        self.port = port;
        self.recv_callback = callback;
        self.context = context;
        self.active = true;
    }

    pub fn send(self: *Self, iface: *types.Interface, dip_addr: u32, port: u16, frame: *types.Frame) void {
        const base_idx = types.TRANSPORT_HEADER_OFFSET;

        const header = createUDPHeader(self.port, port, @intCast(frame.len), 0x0000);
        @memcpy(frame.buffer[base_idx..][0..@sizeOf(UDPHeader)], std.mem.asBytes(&header));

        const checksum = ipv4.calcPseudoChecksum(frame.buffer[base_idx..][0..frame.len], .UDP, 0, dip_addr);
        @memcpy(frame.buffer[base_idx + @offsetOf(UDPHeader, "checksum") ..][0..2], std.mem.asBytes(&checksum));

        ipv4.send(iface, dip_addr, frame, .UDP);
    }

    pub fn send_broadcast(self: *Self, iface: *types.Interface, port: u16, frame: *types.Frame) void {
        self.send(iface, ipv4.IP_BROADCAST_ADDR, port, frame);
    }
};


