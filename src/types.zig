const std = @import("std");

const ETH_HEADER_SIZE: usize = 14;
const IPV4_HEADER_SIZE: usize = 20;
pub const LINK_HEADER_SIZE: usize = ETH_HEADER_SIZE;
pub const NET_HEADER_OFFSET: usize = LINK_HEADER_SIZE;
pub const TRANSPORT_HEADER_OFFSET: usize = LINK_HEADER_SIZE + IPV4_HEADER_SIZE;

pub const ArpEntry = struct {
    ip_addr: u32 = 0,
    mac: [6]u8 = .{0} ** 6,
    time: u32 = 0,
    valid: bool = false,
};

pub const Node = struct {
    next: ?*Node = null,
    header: [64]u8 = undefined,
    len: usize = 0,
    data: []u8 = &.{},
};

pub const FrameQueue = struct {
    const Self = @This();

    slots: [16]Node = undefined,
    fslots: ?*Node = null,
    tslots: ?*Node = null,

    pub fn init(s: *Self) void {
        s.fslots = &s.slots[0];
        var slot: *Node = s.fslots.?;
        for (s.slots[1..]) |*nslot| {
            slot.next = nslot;
            slot = nslot;
        }
    }

    pub fn requestSlot(s: *Self) ?*Node {
        var rslot: ?*Node = null;
        if (s.fslots) |slot| {
            rslot = slot;
            s.fslots = slot.next orelse null;
        }
        return rslot;
    }
};

pub const Device = union(enum) {
    eth: @import("iface/eth.zig").EthDevice,
    loop: @import("iface/loop.zig").LoopDevice,
};

pub const Interface = struct {
    mac_addr: [6]u8 = .{0} ** 6,
    ip_addr: u32 = 0,
    subnet_mask: u32 = 0,
    tx_queue: FrameQueue = .{},
    device: Device = undefined,
    arp_table: []ArpEntry = &.{},

    const Self = @This();

    pub fn init(self: *Self) void {
        self.tx_queue.init();
    }

    pub fn requestSlot(self: *Self) ?*Node {
        return self.tx_queue.requestSlot();
    }

    pub fn send(self: *Self, dst_mac: [6]u8, slot: *Node, ethertype: u16) void {
        const eth_mod = @import("iface/eth.zig");
        const loop_mod = @import("iface/loop.zig");
        switch (self.device) {
            .eth => |*d| eth_mod.ethSend(d, self, dst_mac, slot, ethertype),
            .loop => |*d| loop_mod.loopSend(d, self, dst_mac, slot, ethertype),
        }
    }

    pub fn recv(self: *Self) ?[]u8 {
        const eth_mod = @import("iface/eth.zig");
        const loop_mod = @import("iface/loop.zig");
        return switch (self.device) {
            .eth => |*d| eth_mod.ethRecv(d),
            .loop => |*d| loop_mod.loopRecv(d),
        };
    }

    pub fn processFrame(self: *Self, buffer: []u8) void {
        const eth_mod = @import("iface/eth.zig");
        const loop_mod = @import("iface/loop.zig");
        switch (self.device) {
            .eth => |*d| eth_mod.ethProcess(d, self, buffer),
            .loop => |*d| loop_mod.loopProcess(d, self, buffer),
        }
    }
};
