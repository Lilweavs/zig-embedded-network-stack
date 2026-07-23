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

pub const ArpPendingEntry = struct {
    target_ip: u32 = 0,
    frame: ?*Frame = null,
    first_seen: u32 = 0,
    retries: u32 = 0,
};

pub const Frame = struct {
    buffer: []u8 = &.{},
    len: usize = 0,
    node: std.DoublyLinkedList.Node = .{},
};

pub const FrameQueue = struct {
    const Self = @This();

    backing_buffers: [2][1536]u8 = undefined,
    frames: [2]Frame = undefined,
    fslots: std.DoublyLinkedList = .{},
    tslots: std.DoublyLinkedList = .{},

    pub fn init(s: *Self) void {
        for (&s.frames, 0..) |*frame, i| {
            frame.buffer = &s.backing_buffers[i];
            s.fslots.append(&frame.node);
        }
    }

    pub fn requestFrame(s: *Self) ?*Frame {
        if (s.fslots.pop()) |node| {
            return @as(*Frame, @fieldParentPtr("node", node));
        }
        return null;
    }

    pub fn returnFrame(s: *Self, frame: *Frame) void {
        s.fslots.append(&frame.node);
    }

    pub fn push(s: *Self, frame: *Frame) void {
        s.tslots.append(&frame.node);
    }

    pub fn peek(s: *Self) *Frame {
        if (s.tslots.popFirst()) |node| {
            return @as(*Frame, @fieldParentPtr("node", node));
        }
        return null;
    }
};

// pub const FrameQueue = struct {
//     const Self = @This();

//     slots: [16]Node = undefined,
//     fslots: ?*Node = null,
//     tslots: ?*Node = null,

//     pub fn init(s: *Self) void {
//         s.fslots = &s.slots[0];
//         var slot: *Node = s.fslots.?;
//         for (s.slots[1..]) |*nslot| {
//             slot.next = nslot;
//             slot = nslot;
//         }
//     }

//     pub fn requestSlot(s: *Self) ?*Node {
//         var rslot: ?*Node = null;
//         if (s.fslots) |slot| {
//             rslot = slot;
//             s.fslots = slot.next orelse null;
//         }
//         return rslot;
//     }
// };

pub const Device = union(enum) {
    eth: @import("iface/eth.zig").EthDevice,
    // loop: @import("iface/loop.zig").LoopDevice,
};

pub const Interface = struct {
    mac_addr: [6]u8 = .{0} ** 6,
    ip_addr: u32 = 0,
    subnet_mask: u32 = 0,
    tx_queue: FrameQueue = .{},
    device: Device = undefined,
    arp_table: []ArpEntry = &.{},
    arp_pending: []ArpPendingEntry = &.{},

    const Self = @This();

    pub fn init(self: *Self) void {
        self.tx_queue.init();
    }

    pub fn requestFrame(self: *Self) ?*Frame {
        return self.tx_queue.requestFrame();
    }

    pub fn returnFrame(self: *Self, frame: *Frame) void {
        return self.tx_queue.returnFrame(frame);
    }

    pub fn send(self: *Self, dst_mac: [6]u8, frame: *Frame, ethertype: u16) void {
        const eth_mod = @import("iface/eth.zig");
        // const loop_mod = @import("iface/loop.zig");
        switch (self.device) {
            .eth => |*d| eth_mod.ethSend(d, self, dst_mac, frame, ethertype),
            // .loop => |*d| _ = d, // loop_mod.loopSend(d, self, dst_mac, frame, ethertype),
        }
        self.tx_queue.returnFrame(frame);
    }

    pub fn recv(self: *Self) ?[]u8 {
        const eth_mod = @import("iface/eth.zig");
        // const loop_mod = @import("iface/loop.zig");
        return switch (self.device) {
            .eth => |*d| eth_mod.ethRecv(d),
            // .loop => |*d| _ = d, // loop_mod.loopRecv(d),
        };
    }

    pub fn processFrame(self: *Self, buffer: []u8) void {
        const eth_mod = @import("iface/eth.zig");
        // const loop_mod = @import("iface/loop.zig");
        switch (self.device) {
            .eth => |*d| eth_mod.ethProcess(d, self, buffer),
            // .loop => |*d| _ = d, // loop_mod.loopProcess(d, self, buffer),
        }
    }
};
