const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const ipv4 = @import("../core/ipv4.zig");

pub const PingHeader = syntax.icmp.PingHeader;
pub const PingType = syntax.icmp.PingType;
pub const ICMPType = syntax.icmp.ICMPType;

const icmp_magic_string: []const u8 = "abcdefghabcdefghabcdefghabcdefgh";

var sequnce_number: u16 = 0;

pub fn processICMPPacket(iface: *types.Interface, saddr: u32, buffer: []u8) void {
    const icmp_type: u8 = buffer[0];

    switch (@as(ICMPType, @enumFromInt(icmp_type))) {
        .REPLY => {},
        .ECHO => {
            pingReply(iface, saddr, buffer);
        },
        else => {},
    }
}

pub fn pingEcho(iface: *types.Interface, ping_addr: u32) void {
    if (iface.requestSlot()) |slot| {
        const upper_start: usize = types.TRANSPORT_HEADER_OFFSET;

        const header: PingHeader = .{
            .type = .Echo,
            .identifier = 0xBEEF,
            .sequence_numer = sequnce_number,
        };

        var pos: usize = upper_start;
        var end: usize = pos + @sizeOf(PingHeader);
        @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

        pos = end;
        end = pos + icmp_magic_string.len;
        @memcpy(slot.header[pos..end], icmp_magic_string);

        slot.data = slot.header[upper_start..end];
        slot.len = upper_start + slot.data.len;

        const checksum = ipv4.calculateIPv4Checksum(slot.data, 0);
        @memcpy(slot.header[upper_start + @offsetOf(PingHeader, "checksum")..][0..2], std.mem.asBytes(&checksum));

        ipv4.send(iface, ping_addr, slot, .ICMP);
    }
}

pub fn pingReply(iface: *types.Interface, addr: u32, payload: []u8) void {
    const resp_header = std.mem.bytesToValue(PingHeader, payload[0..@sizeOf(PingHeader)]);
    if (iface.requestSlot()) |slot| {
        const upper_start: usize = types.TRANSPORT_HEADER_OFFSET;

        const header: PingHeader = .{
            .type = .Reply,
            .identifier = resp_header.identifier,
            .sequence_number = resp_header.sequence_number,
        };

        var pos: usize = upper_start;
        var end: usize = pos + @sizeOf(PingHeader);
        @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

        pos = end;
        end = pos + (payload.len - @sizeOf(PingHeader));
        @memcpy(slot.header[pos..end], payload[@sizeOf(PingHeader)..]);

        slot.data = slot.header[upper_start..end];
        slot.len = upper_start + slot.data.len;

        ipv4.send(iface, addr, slot, .ICMP);
    }
}
