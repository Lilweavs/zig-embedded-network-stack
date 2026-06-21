const std = @import("std");

pub const EthernetHeader = extern struct {
    dest: [6]u8 align(1),
    src: [6]u8 align(1),
    len_or_type: u16 align(1),
};

pub const EtherType = enum(u16) {
    IPv4 = 0x0800,
    ARP = 0x0806,
    _,
};

const MacAddr = struct {
    mac: [6]u8,
    pub fn format(self: MacAddr, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5],
        });
    }
};

pub fn fmtMacAddr(mac: [6]u8) std.fmt.Formatter(MacAddr.format) {
    return .{ .data = MacAddr{ .mac = mac } };
}

pub fn readHeader(buffer: []const u8) EthernetHeader {
    return std.mem.bytesToValue(EthernetHeader, buffer[0..@sizeOf(EthernetHeader)]);
}

pub fn writeHeader(buffer: []u8, header: EthernetHeader) void {
    @memcpy(buffer[0..@sizeOf(EthernetHeader)], std.mem.asBytes(&header));
}
