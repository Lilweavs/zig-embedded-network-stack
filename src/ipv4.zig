//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |Version|  IHL  |Type of Service|          Total Length         |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |         Identification        |Flags|      Fragment Offset    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |  Time to Live |    Protocol   |         Header Checksum       |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                       Source Address                          |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Destination Address                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                    Options                    |    Padding    |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

const std = @import("std");
const builtin = @import("builtin");
const udp = @import("udp.zig");
const eth = @import("eth.zig");
const icmp = @import("icmp.zig");
const hal = @import("hal.zig");
const arp = @import("arp.zig");
const tcp = @import("tcp.zig");

pub const IP_BROADCAST_ADDR: u32 = std.math.maxInt(u32);

const Context = struct {
    buffer: []u8,
    proto: Protocol,
};

pub const Protocol = enum(u8) {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    _,
};

const IpAddr = struct {
    addr: u32,
    pub fn format(
        self: IpAddr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        // Ignore `fmt` and `options` in this simple example
        _ = fmt;
        _ = options;
        const bytes = std.mem.asBytes(&self.addr);
        try std.fmt.format(writer, "{d}.{d}.{d}.{d}", .{
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
        });
    }
};

pub fn fmtIpAddr(addr: u32) std.fmt.Formatter(IpAddr.format) {
    return .{ .data = IpAddr{ .addr = addr } };
}

pub var ip_addr: u32 = 0;
var subnet_mask: u32 = 0;
var default_gateway: u32 = 0;

pub const IPv4Frame = struct {
    header: IPv4Header,
    payload: []u8,
};

pub const VersionIHl = packed struct {
    version: u4,
    ihl: u4,
};

pub const IPv4Header = extern struct {
    version_ihl: VersionIHl align(1) = .{
        .version = 4,
        .ihl = 5,
    },
    type_of_service: u8 align(1) = 0x0,
    length: u16 align(1),
    id: u16 align(1) = 0,
    flags_offset: u16 align(1) = std.mem.nativeToBig(u16, 0x4000),
    ttl: u8 align(1) = 255,
    protocol: u8 align(1),
    checksum: u16 align(1) = 0x0000,
    saddr: u32 align(1),
    daddr: u32 align(1),

    const Self = @This();

    pub fn ihl(self: Self) u4 {
        return (self.version_ihl & 0x0F);
    }

    pub fn flags(self: Self) u3 {
        return ((self.mem.littleToNative(u16, self.flags_offset) > 13) & 0x07);
    }

    pub fn offset(self: Self) u13 {
        return (self.mem.littleToNative(u16, self.flags_offset) & 0x1FFF);
    }
};

// 576 - 20 - 8 - 14 : 534
pub fn send(dip_addr: u32, slot: *eth.Node, proto: Protocol) !void {
    const len: u32 = slot.data.len + 8;
    const header: IPv4Header = .{
        .length = std.mem.nativeToBig(u16, @intCast(@sizeOf(IPv4Header) + len)),
        .ttl = 255,
        .protocol = @as(u8, @intFromEnum(proto)),
        .saddr = ip_addr,
        .daddr = dip_addr,
    };

    // try hal.printf("IPV4 Len: {d}\n", .{payload.len});

    const pos: usize = 14;
    const end: usize = 14 + @sizeOf(IPv4Header);

    @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

    // var dmac_addr = try resolveMacAddress(dip_addr);

    // add ipv4 crc
    if (arp.fetchArpEntry(dip_addr)) |dmac| {
        // const packet_end = 14 + @sizeOf(IPv4Header) + payload.len;
        eth.send(dmac, slot, .IPv4) catch {
            try hal.printf("Error eth send\n", .{});
        };
        // eth.send(dmac, ctx.buffer[14..packet_end], .{ .buffer = ctx.buffer, .len_or_type = eth.EtherType.IPv4 }) catch {
    } else {
        try hal.printf("Arp not resolved\n", .{});
    }
}

// pub fn send(dip_addr: u32, payload: []u8, ctx: Context) !void {
//     const header: IPv4Header = .{
//         .length = std.mem.nativeToBig(u16, @intCast(@sizeOf(IPv4Header) + payload.len)),
//         .ttl = 255,
//         .protocol = @as(u8, @intFromEnum(ctx.proto)),
//         .saddr = ip_addr,
//         .daddr = dip_addr,
//     };

//     // try hal.printf("IPV4 Len: {d}\n", .{payload.len});

//     const pos: usize = 14;
//     const end: usize = 14 + @sizeOf(IPv4Header);
//     @memcpy(ctx.buffer[pos..end], std.mem.asBytes(&header));

//     // var dmac_addr = try resolveMacAddress(dip_addr);

//     // add ipv4 crc

//     if (arp.fetchArpEntry(dip_addr)) |dmac| {
//         const packet_end = 14 + @sizeOf(IPv4Header) + payload.len;
//         eth.send(dmac, ctx.buffer[14..packet_end], .{ .buffer = ctx.buffer, .len_or_type = eth.EtherType.IPv4 }) catch {
//             try hal.printf("Error eth send\n", .{});
//         };
//     } else {
//         try hal.printf("Arp not resolved\n", .{});
//     }
// }

pub fn processIPv4Frame(frame: eth.EthernetFrame) !void {
    const header: IPv4Header = std.mem.bytesToValue(IPv4Header, frame.payload[0..@sizeOf(IPv4Header)]);

    // try hal.printf("---IP Recv---\n proto: {d}\n", .{header.protocol});
    // try hal.printf("---IPv4---\nSRCIP: {d}.{d}.{d}.{d}\nDESIP: {d}.{d}.{d}.{d}\nPROTO: {d} -> {s}\n", .{ sipaddr[0], sipaddr[1], sipaddr[2], sipaddr[3], dipaddr[0], dipaddr[1], dipaddr[2], dipaddr[3], header.protocol, stringFromProto(header.protocol) });
    // try m.printf("---IPv4---\nSRCIP: {d}.{d}.{d}.{d}\nDESIP: {d}.{d}.{d}.{d}\nPROTO: {d} -> {s}\n", .{ header.s_addr[0], header.s_addr[1], header.s_addr[2], header.s_addr[3], header.d_addr[0], header.d_addr[1], header.d_addr[2], header.d_addr[3], header.protocol, stringFromProto(header.protocol) });

    const pos: usize = @sizeOf(IPv4Header);
    const end: usize = std.mem.bigToNative(u16, header.length);

    switch (@as(Protocol, @enumFromInt(header.protocol))) {
        .ICMP => {
            const opt = arp.fetchArpEntry(header.saddr);
            if (opt) |mac| {
                try hal.printf("Mac resolution table {}\n", .{eth.fmtMacAddr(mac)});
            } else {
                try hal.printf("Mac not resolved\n", .{});
            }
            try icmp.processICMPPacket(.{ .header = header, .payload = frame.payload[pos..end] });
        },
        .IGMP => {},
        .TCP => {
            try tcp.processTCPFrame(.{ .header = header, .payload = frame.payload[pos..end] });
        },
        .UDP => {
            try udp.processUDPFrame(.{ .header = header, .payload = frame.payload[pos..end] });
        },
        _ => {
            // error
        },
    }
}

pub fn printIpAddr(addr: u32) !void {
    const bytes = std.mem.asBytes(&addr);
    try hal.printf("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
}

pub fn setIpAddr(addr: u32) void {
    ip_addr = addr;
}

pub fn preparePacket() void {}

const IpRoute = struct {
    ip_addr: u32 = 0,
    mac_addr: u48 = 0,
    time: u32 = 0,
};

var routing_table: [8]IpRoute = .{IpRoute{}} ** 8;

pub fn resolveMacAddress(addr: u32) ![6]u8 {
    if (addr == IP_BROADCAST_ADDR) {
        return .{ 255, 255, 255, 255, 255, 255 };
    }

    // check if multicast

    // check if unicast
    var mac_addr = [_]u8{0} ** 6;
    for (routing_table) |route| {
        if (route.ip_addr == addr) {
            // @memcpy(&mac_addr, &route.mac_addr);

            for (std.mem.asBytes(&route.mac_addr), 0..) |byte, i| {
                mac_addr[i] = byte;
                if (i == 6) break;
            }

            return mac_addr;
        }
    }

    return error.NoRouteToDest;
}

pub fn calculateIPv4Checksum(buffer: []const u8, init_value: u32) u16 {
    var checksum: u32 = accumulateIPv4Checksum(buffer) + init_value;

    // handle carry bits i.e. 0x10000 -> 0x0001
    checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF);

    // ones complement
    return ~@as(u16, @intCast(checksum & 0xFFFF));
}

pub fn accumulateIPv4Checksum(buffer: []const u8) u32 {
    var checksum: u32 = 0;
    const offset = (buffer.len & 1);

    const words = std.mem.bytesAsSlice(u16, buffer[0 .. buffer.len - offset]);

    for (words) |word| {
        checksum += word;
    }

    if (offset > 0) {
        checksum += buffer[buffer.len - 1];
    }
    return checksum;
}

test "IPv4Checksum" {
    // goes over the entire header and payload
    const buffer = [_]u16{ 0xDEAD, 0xBEEF, 0xDEAD, 0xBEEF };

    const u8_buf = std.mem.sliceAsBytes(&buffer);

    const val = calculateIPv4Checksum(u8_buf, 0);
    // 0xDEAD + 0xBEEF + 0xDEAD + 0xBEEF = 0x3B3B (with carry)
    // ~Ox3B3B = 0xC4C4

    try std.testing.expectEqual(0xC4C4, val);
}

//     IPv4 PsuedoHeader for UDP/TCP
// +--------+--------+--------+--------+
// |           Source Address          |
// +--------+--------+--------+--------+
// |         Destination Address       |
// +--------+--------+--------+--------+
// |  zero  |  PTCL  |      Length     |
// +--------+--------+--------+--------+
// return u32 so it can be directly used in calcIPv4Checksum
pub fn getPsuedoHeaderChecksum(proto: Protocol, saddr: u32, daddr: u32, length: u16) u32 {
    var checksum: u32 = @intFromEnum(proto) + length;
    checksum += (saddr & 0xFFFF) + ((saddr >> 16) & 0xFFFF);
    checksum += (daddr & 0xFFFF) + ((daddr >> 16) & 0xFFFF);
    return checksum;
}

test "PseudoHeaderChecksum" {
    // saddr and daddr should be in native byte order
    const val = getPsuedoHeaderChecksum(Protocol.UDP, 0x7F000001, 0x7F000001, 0x0020);
    // +------+------+------+------+
    // | 0x7F   0x00 |  0x00  0x01 |
    // +------+------+------+------+
    // | 0x7F   0x00 |  0x00  0x01 |
    // +------+------+------+------+
    // | 0x00   0x11 | 0x00   0x20 |
    // +------+------+------+------+
    // 0x7F00 + 0x0001 + 0x7F00 + 0x0001 + 0x0011 + 0x0020 = 0xFE33
    try std.testing.expectEqual(0xFE33, val);
}

pub fn calcPseudoChecksum(buffer: []const u8, proto: Protocol, saddr: u32, daddr: u32) u16 {
    return calculateIPv4Checksum(buffer, getPsuedoHeaderChecksum(proto, saddr, daddr, @as(u16, @intCast(buffer.len))));
}
