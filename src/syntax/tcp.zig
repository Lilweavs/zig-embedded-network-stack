const std = @import("std");

pub const TcpFlags = packed struct(u8) {
    fin: u1 = 0,
    syn: u1 = 0,
    rst: u1 = 0,
    psh: u1 = 0,
    ack: u1 = 0,
    urg: u1 = 0,
    ece: u1 = 0,
    cwr: u1 = 0,
};

pub const TcpHeader = extern struct {
    sport: u16 align(1) = 0,
    dport: u16 align(1) = 0,
    seq_number: u32 align(1) = 0,
    ack_number: u32 align(1) = 0,
    data_offset: u8 align(1) = 0,
    flags: TcpFlags align(1) = .{},
    window: u16 align(1) = 0,
    checksum: u16 align(1) = 0,
    urgent_pointer: u16 align(1) = 0,
};
