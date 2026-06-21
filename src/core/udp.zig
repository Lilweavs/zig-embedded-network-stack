const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax/udp.zig");
const ipv4 = @import("../core/ipv4.zig");

pub const UDPHeader = syntax.UDPHeader;
pub const createUDPHeader = syntax.createHeader;

const udp_pool_size: usize = 4;
var udp_pool: [udp_pool_size]UDPSocket = .{UDPSocket{}} ** udp_pool_size;

const UDPCallbackFn = *const fn (socket: *UDPSocket, addr: u32, port: u16, payload: []const u8) void;

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
    _ = iface;
    const header: UDPHeader = std.mem.bytesToValue(UDPHeader, buffer[0..@sizeOf(UDPHeader)]);
    const length = std.mem.bigToNative(u16, header.length) - @sizeOf(UDPHeader);
    const dport = std.mem.bigToNative(u16, header.dport);
    const sport = std.mem.bigToNative(u16, header.sport);

    for (&udp_pool) |*sock| {
        if (sock.active and sock.port == dport) {
            return if (sock.recv_callback) |callback| callback(sock, saddr, sport, buffer[0..length]);
        }
    }
}

pub const UDPSocket = struct {
    const Self = @This();

    ip_addr: u32 = 0,
    port: u16 = 0,
    active: bool = false,
    recv_callback: ?UDPCallbackFn = null,

    pub fn bind(self: *Self, port: u16, callback: ?UDPCallbackFn) void {
        self.port = port;
        self.recv_callback = callback;
        self.active = true;
    }

    pub fn send(self: *Self, iface: *types.Interface, dip_addr: u32, port: u16, payload: []const u8) void {
        if (iface.requestSlot()) |slot| {
            const upper_start: usize = types.TRANSPORT_HEADER_OFFSET;
            const udp_len = @as(u16, @intCast(payload.len + @sizeOf(UDPHeader)));

            const header = createUDPHeader(self.port, port, udp_len, 0x0000);

            var pos: usize = upper_start;
            var end: usize = pos + @sizeOf(UDPHeader);
            @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

            pos = end;
            end = pos + payload.len;
            @memcpy(slot.header[pos..end], payload);

            slot.data = slot.header[upper_start..end];
            slot.len = upper_start + slot.data.len;

            const checksum = ipv4.calcPseudoChecksum(slot.data, .UDP, 0, dip_addr);
            @memcpy(slot.header[upper_start + @offsetOf(UDPHeader, "checksum")..][0..2], std.mem.asBytes(&checksum));

            ipv4.send(iface, dip_addr, slot, .UDP);
        }
    }

    pub fn send_broadcast(self: *Self, iface: *types.Interface, port: u16, payload: []const u8) void {
        self.send(iface, ipv4.IP_BROADCAST_ADDR, port, payload);
    }
};

pub fn testCallback(socket: *UDPSocket, addr: u32, port: u16, payload: []const u8) bool {
    _ = socket;
    _ = addr;
    _ = port;
    _ = payload;
    return true;
}
