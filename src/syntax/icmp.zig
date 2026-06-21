const std = @import("std");

pub const PingType = enum(u8) {
    Echo = 0x08,
    Reply = 0x00,
};

pub const PingHeader = extern struct {
    type: PingType align(1),
    code: u8 align(1) = 0,
    checksum: u16 align(1) = 0x0000,
    identifier: u16 align(1),
    sequence_number: u16 align(1),
};

pub const ICMPType = enum(u8) {
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
