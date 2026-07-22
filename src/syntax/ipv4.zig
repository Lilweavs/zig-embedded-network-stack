const std = @import("std");

pub const VersionIHl = packed struct(u8) {
    ihl: u4,
    version: u4,
};

pub const IPv4Header = extern struct {
    version_ihl: VersionIHl align(1) = .{ .version = 4, .ihl = 5 },
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
        return ((std.mem.littleToNative(u16, self.flags_offset) > 13) & 0x07);
    }

    pub fn offset(self: Self) u13 {
        return (std.mem.littleToNative(u16, self.flags_offset) & 0x1FFF);
    }
};

pub const FragmentField = packed struct(u16) {
    offset: u13,
    flags: Flags,
};

pub const Flags = packed struct(u3) {
    mf: u1,
    df: u1,
    r: u1,
};

pub const Protocol = enum(u8) {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    _,
};

pub const IP_BROADCAST_ADDR: u32 = std.math.maxInt(u32);

pub const IpAddr = struct {
    addr: u32,
    pub fn format(self: IpAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const bytes = std.mem.asBytes(&self.addr);
        try writer.print("{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] });
    }
};

pub fn fmtIpAddr(addr: u32) IpAddr {
    return .{ .addr = addr };
}

pub fn calculateChecksum(buffer: []const u8, init_value: u32) u16 {
    var checksum: u32 = accumulateChecksum(buffer) + init_value;

    checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF);

    return ~@as(u16, @intCast(checksum & 0xFFFF));
}

pub fn accumulateChecksum(buffer: []const u8) u32 {
    var checksum: u32 = 0;
    const even_len = buffer.len & ~@as(usize, 1);
    var i: usize = 0;
    while (i < even_len) : (i += 2) {
        checksum += (@as(u16, buffer[i]) << 8) | buffer[i + 1];
    }
    if (buffer.len & 1 != 0) {
        checksum += @as(u16, buffer[buffer.len - 1]) << 8;
    }
    return checksum;
}

pub fn getPsuedoHeaderChecksum(proto: Protocol, saddr: u32, daddr: u32, length: u16) u32 {
    var checksum: u32 = @intFromEnum(proto) + length;
    checksum += (saddr & 0xFFFF) + ((saddr >> 16) & 0xFFFF);
    checksum += (daddr & 0xFFFF) + ((daddr >> 16) & 0xFFFF);
    return checksum;
}

pub fn calcPseudoChecksum(buffer: []const u8, proto: Protocol, saddr: u32, daddr: u32) u16 {
    return calculateChecksum(buffer, getPsuedoHeaderChecksum(proto, saddr, daddr, @as(u16, @intCast(buffer.len))));
}

test "IPv4Checksum" {
    const u8_buf = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };
    const val = calculateChecksum(&u8_buf, 0);
    try std.testing.expectEqual(0xC4C4, val);
}

test "PseudoHeaderChecksum" {
    const val = getPsuedoHeaderChecksum(Protocol.UDP, 0x7F000001, 0x7F000001, 0x0020);
    try std.testing.expectEqual(0xFE33, val);
}
