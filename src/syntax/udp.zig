const std = @import("std");
const ipv4 = @import("ipv4.zig");

pub const UDPHeader = packed struct(u64) {
    sport: u16 = 0x0000,
    dport: u16 = 0x0000,
    length: u16 = 0x0000,
    checksum: u16 = 0x0000,
};

pub fn createHeader(sport: u16, dport: u16, length: u16, checksum: u16) UDPHeader {
    return .{
        .sport = std.mem.nativeToBig(u16, sport),
        .dport = std.mem.nativeToBig(u16, dport),
        .length = std.mem.nativeToBig(u16, length),
        .checksum = std.mem.nativeToBig(u16, checksum),
    };
}

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

    checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF);

    return ~@as(u16, @intCast(checksum & 0xFFFF));
}

test "UdpChecksum" {
    const buffer = [_]u8{ 0xc0, 0x54, 0x30, 0x39, 0x00, 0x13, 0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x55, 0x44, 0x50, 0x21 };

    const checksum = ipv4.calcPseudoChecksum(&buffer, ipv4.Protocol.UDP, 0x7F000001, 0x7F000001);

    try std.testing.expectEqual(@as(u16, 0x6794), checksum);
}
