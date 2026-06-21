const std = @import("std");

pub const ArpFrame = extern struct {
    htype: u16 align(1) = std.mem.nativeToBig(u16, 0x01),
    ptype: u16 align(1) = std.mem.nativeToBig(u16, 0x0800),
    hsize: u8 align(1) = 0x06,
    psize: u8 align(1) = 0x04,
    opcode: u16 align(1),
    shwaddr: [6]u8 align(1) = .{0x00} ** 6,
    sipaddr: u32 align(1),
    thwaddr: [6]u8 align(1) = .{0x00} ** 6,
    tipaddr: u32 align(1),
};

pub const Opcode = enum(u16) {
    Request = 1,
    Reply = 2,
    _,
};

pub fn readFrame(buffer: []const u8) ArpFrame {
    return std.mem.bytesToValue(ArpFrame, buffer[0..@sizeOf(ArpFrame)]);
}
