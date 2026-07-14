const std = @import("std");

pub const time = @import("time.zig");
pub const types = @import("types.zig");

pub const syntax = struct {
    pub const eth = @import("syntax/eth.zig");
    pub const arp = @import("syntax/arp.zig");
    pub const ipv4 = @import("syntax/ipv4.zig");
    pub const icmp = @import("syntax/icmp.zig");
    pub const udp = @import("syntax/udp.zig");
    pub const tcp = @import("syntax/tcp.zig");
};

pub const core = struct {
    pub const arp = @import("core/arp.zig");
    pub const ipv4 = @import("core/ipv4.zig");
    pub const icmp = @import("core/icmp.zig");
    pub const udp = @import("core/udp.zig");
    pub const tcp = @import("core/tcp.zig");
    pub const stack = @import("core/stack.zig");
};

pub const app = struct {
    pub const dhcp = @import("app/dhcp.zig");
};

pub const iface = struct {
    pub const eth = @import("iface/eth.zig");
    pub const loop = @import("iface/loop.zig");
};
