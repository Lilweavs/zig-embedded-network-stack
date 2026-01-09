const std = @import("std");
const builtin = @import("builtin");
const ipv4 = @import("ipv4.zig");
const eth = @import("eth.zig");
const hal = @import("hal.zig");

// UdpHeader Header
//   0      7 8     15 16    23 24    31
//  +--------+--------+--------+--------+
//  |     Source      |   Destination   |
//  |      Port       |      Port       |
//  +--------+--------+--------+--------+
//  |                 |                 |
//  |     Length      |    Checksum     |
//  +--------+--------+--------+--------+
//  |
//  |          data octets ...
//  +---------------- ...
// IPv4 Header Checksum
// Pseudo header plus
//   0      7 8     15 16    23 24    31
//  +--------+--------+--------+--------+
//  |          source address           |
//  +--------+--------+--------+--------+
//  |        destination address        |
//  +--------+--------+--------+--------+
//  |  zero  |protocol|   UDP length    |
//  +--------+--------+--------+--------+

// If the computed  checksum  is zero,  it is transmitted  as all ones (the
// equivalent  in one's complement  arithmetic).   An all zero  transmitted
// checksum  value means that the transmitter  generated  no checksum  (for
// debugging or for higher level protocols that don't care).

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
        if (&udp_pool[i] == socket) {
            // std.mem.swap(UDPSocket, &udp_pool[i], );
        }
    }
    socket.active = false;
}

pub const UDPHeader = packed struct(u64) {
    sport: u16 = 0x0000,
    dport: u16 = 0x0000,
    length: u16 = 0x0000,
    checksum: u16 = 0x0000,
};

pub fn createUDPHeader(sport: u16, dport: u16, length: u16, checksum: u16) UDPHeader {
    return .{
        .sport = std.mem.nativeToBig(u16, sport),
        .dport = std.mem.nativeToBig(u16, dport),
        .length = std.mem.nativeToBig(u16, length),
        .checksum = std.mem.nativeToBig(u16, checksum),
    };
}

pub fn processUDPFrame(saddr: u32, sport: u16, dport: u16, buffer: []u8) !void {
    const header: UDPHeader = std.mem.bytesToValue(UDPHeader, buffer);
    const length = std.mem.bigToNative(u16, header.length) - @sizeOf(UDPHeader);

    // try hal.printf("---UDP Recv---\n sport: {d}\n dport: {d}\n length: {d}\n checksum: {X:0>4}\n", .{ std.mem.bigToNative(u16, header.sport), std.mem.bigToNative(u16, header.dport), std.mem.bigToNative(u16, header.length), header.checksum });
    // const dport = std.mem.bigToNative(u16, header.dport);

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

    // start with udp checksum
    // eth header = 14B
    // ipv4 header = 20B
    // udp header = 8B
    // offset by 34B

    pub fn send(self: *Self, dip_addr: u32, port: u16, payload: []const u8) !void {
        if (eth.requestSlot()) |slot| {
            const checksum = ipv4.calcPseudoChecksum(payload, .UDP, ipv4.ip_addr, ipv4.dip_addr);

            const header = createUDPHeader(self.port, port, @intCast(payload.len + 8), checksum);

            const pos: usize = 34;
            const end: usize = pos + @sizeOf(UDPHeader);
            @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

            // now send IPv4 Packet
            // ipv4.send(dip_addr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.UDP }) catch {};
            ipv4.send(dip_addr, slot);
        }

        // if (hal.requestBuffer()) |buffer| {
        //     const header = createUDPHeader(self.port, port, @intCast(payload.len + 8), 0x0000);

        //     var pos: usize = 34;
        //     var end: usize = pos + @sizeOf(UDPHeader);
        //     @memcpy(buffer[pos..end], std.mem.asBytes(&header));

        //     pos = end;
        //     end = pos + payload.len;
        //     @memcpy(buffer[pos..end], payload);

        //     const checksum = calcUdpChecksum(buffer[34..end], ipv4.ip_addr, dip_addr);

        //     pos = @offsetOf(UDPHeader, "checksum");
        //     @memcpy(buffer[pos .. pos + @sizeOf(@FieldType(UDPHeader, "checksum"))], std.mem.asBytes(&checksum));

        //     // now send IPv4 Packet
        //     ipv4.send(dip_addr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.UDP }) catch {};
        // }
    }

    pub fn send_broadcast(self: *Self, port: u16, payload: []const u8) !void {
        try self.send(ipv4.IP_BROADCAST_ADDR, port, payload);
    }
};

// can bypass by sending 0
pub fn calcUdpChecksum(buffer: []const u8, saddr: u32, daddr: u32) u16 {
    var checksum: u32 = std.mem.nativeToBig(u16, 17 + @as(u16, @intCast(buffer.len)));

    const offset = (buffer.len & 1);

    const words = std.mem.bytesAsSlice(u16, buffer[0 .. buffer.len - offset]);

    for (words) |word| {
        checksum += word;
    }

    if (offset > 0) {
        checksum += buffer[buffer.len - 1];
    }

    checksum += (saddr & 0xFFFF) + ((saddr >> 16) & 0xFFFF);
    checksum += (daddr & 0xFFFF) + ((daddr >> 16) & 0xFFFF);

    checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF); // handle carry bits i.e. 0x10000 -> 0x0001

    return ~@as(u16, @intCast(checksum & 0xFFFF));
}

test "UdpChecksum" {
    const buffer = [_]u8{ 0xc0, 0x54, 0x30, 0x39, 0x00, 0x13, 0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x55, 0x44, 0x50, 0x21 };

    const checksum = ipv4.calcPseudoChecksum(&buffer, ipv4.Protocol.UDP, 0x7F000001, 0x7F000001);

    std.debug.print("{X} - {X}\n", .{ 0x6794, checksum });
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 0x6794), checksum);
}

// pub fn printUDPHeader(header: UDPHeader) !void {
// try utils.dbg_writer.writer().print("UDPHeader:\n  sport: {d}\n  dport: {d}\n  length: {d}\n  checksum: 0x{X:0>4}\n", .{ std.mem.nativeToBig(u16, header.sport), std.mem.nativeToBig(u16, header.dport), std.mem.nativeToBig(u16, header.length), header.checksum });

// std.debug.print("UDPHeader:\n  sport: {d}\n  dport: {d}\n  length: {d}\n  checksum: 0x{X:0>4}\n", .{ std.mem.nativeToBig(u16, header.sport), std.mem.nativeToBig(u16, header.dport), std.mem.nativeToBig(u16, header.length), header.checksum });
// }

pub fn testCallback(socket: *UDPSocket, addr: u32, port: u16, payload: []const u8) bool {
    _ = socket;
    _ = addr;
    _ = port;
    _ = payload;
    return true;
}
