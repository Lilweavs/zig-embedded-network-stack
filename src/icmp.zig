const std = @import("std");
const ipv4 = @import("ipv4.zig");
const hal = @import("hal.zig");

//Echo or Echo Reply Message
//
//    0                   1                   2                   3
//    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Type      |     Code      |          Checksum             |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |           Identifier          |        Sequence Number        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |     Data ...
//   +-+-+-+-+-

const icmp_magic_string: []const u8 = "abcdefghabcdefghabcdefghabcdefgh";

const PingType = enum(u8) {
    Echo = 0x08,
    Reply = 0x00,
};

const PingHeader = extern struct {
    type: PingType align(1),
    code: u8 align(1) = 0,
    checksum: u16 align(1) = 0x0000,
    identifier: u16 align(1),
    sequence_number: u16 align(1),
};

// identifier and sequence number are manually chosen

var sequnce_number: u16 = 0;

const ICMPType = enum(u8) {
    REPLY = 0,
    DEST_UNREACHABLE = 3,
    SOURCE_QUENCH = 4,
    REDIRECT = 5,
    ECHO = 8,
    TIME_EXCEEDED = 11,
    PARAM_PROBLEM = 12,
    TIMESTAMP = 13,
    TIMESTAMP_REPLY = 14,
    INFO_REQUEST = 15,
    INFO_REPLY = 16,
    _,
};

pub fn processICMPPacket(frame: ipv4.IPv4Frame) !void {
    const icmp_type: u8 = frame.payload[0];

    // try hal.printf("ICMP Received\n", .{});

    switch (@as(ICMPType, @enumFromInt(icmp_type))) {
        .REPLY => {
            // pingReply(payload);
        },
        .ECHO => {
            // try hal.printf("ICMP Response!!!\n", .{});
            try pingReply(frame.header.saddr, frame.payload);
            // try hal.printf("ICMP Complete!!\n", .{});
        },
        else => {},
    }
}

pub fn pingEcho(ping_addr: u32) !void {
    if (hal.requestBuffer()) |buffer| {
        const header: PingHeader = .{
            .type = .Echo,
            .identifier = 0xBEEF,
            .sequence_numer = sequnce_number,
        };

        // sequnce_number += 1;

        var pos: usize = 34; // get rid of magic number
        var end: usize = @sizeOf(PingHeader);
        @memcpy(buffer[pos..end], &header);

        pos = end;
        end = pos + icmp_magic_string.len;
        @memcpy(buffer[pos..end], icmp_magic_string);

        const checksum = ipv4.calculateIPv4Checksum(buffer[0..end]);
        @memcpy(&buffer[@offsetOf(PingHeader, "checksum")], &checksum);

        try ipv4.send(ping_addr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.ICMP });
    }
}

pub fn pingReply(addr: u32, payload: []u8) !void {
    const resp_header = std.mem.bytesToValue(PingHeader, payload[0..@sizeOf(PingHeader)]);
    if (hal.requestBuffer()) |buffer| {
        const header: PingHeader = .{
            .type = .Reply,
            .identifier = resp_header.identifier,
            .sequence_number = resp_header.sequence_number,
        };

        var pos: usize = 34; // get rid of magic number
        var end: usize = 34 + @sizeOf(PingHeader);
        @memcpy(buffer[pos..end], std.mem.asBytes(&header));

        pos = end;
        end = pos + (payload.len - @sizeOf(PingHeader));
        @memcpy(buffer[pos..end], payload[@sizeOf(PingHeader)..]);

        // const checksum = @as(u16, @intCast(ipv4.calculateIPv4Checksum(buffer[34..end])));
        // pos = 34 + @offsetOf(PingHeader, "checksum");

        // @memcpy(buffer[pos .. pos + 2], std.mem.asBytes(&checksum));

        try ipv4.send(addr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.ICMP });
        // _ = addr;
        // try ipv4.send(ipv4.IP_BROADCAST_ADDR, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.ICMP });
    }
}
