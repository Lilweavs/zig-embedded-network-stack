const std = @import("std");
// const m = @import("main.zig");
const ipv4 = @import("ipv4.zig");
const hal = @import("hal.zig");
const arp = @import("arp.zig");

pub const mac_addr = [6]u8{ 0x00, 0x80, 0xE1, 0x00, 0x00, 0x00 };

pub const EthernetHeader = extern struct {
    dest: [6]u8 align(1),
    src: [6]u8 align(1),
    len_or_type: u16 align(1),
};

pub const EthernetFrame = struct {
    header: EthernetHeader,
    payload: []u8,
};

pub const EtherType = enum(u16) {
    IPv4 = 0x0800,
    ARP = 0x0806,
    _,
};

const MacAddr = struct {
    mac: [6]u8,
    pub fn format(
        self: MacAddr,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        // Ignore `fmt` and `options` in this simple example
        _ = fmt;
        _ = options;
        try std.fmt.format(writer, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
        });
    }
};

pub const Node = struct {
    next: ?*Node = null,
    header: [64]u8 = undefined,
    len: usize = 0,
    data: []u8 = &.{},
};

pub const FrameQueue = struct {
    const Self = @This();

    slots: [16]Node = .{},

    fslots: ?*Node = null,
    tslots: ?*Node = null,

    pub fn init(s: *Self) void {
        s.fslots = s.slots[0];
        var slot: *Node = &s.fslots.?;
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

pub fn fmtMacAddr(mac: [6]u8) std.fmt.Formatter(MacAddr.format) {
    return .{ .data = MacAddr{ .mac = mac } };
}

pub fn processEthernetFrame(buffer: []u8) !void {
    const eth_header: EthernetHeader = std.mem.bytesToValue(EthernetHeader, buffer[0..@sizeOf(EthernetHeader)]);

    // try hal.printf("Frame: 0x{X:0<4}\n", .{std.mem.bigToNative(u16, eth_header.len_or_type)});

    // hal.printf("Frame: {d}\n", .{buffer.len}) catch {};
    const protocol = std.mem.bigToNative(u16, eth_header.len_or_type);

    if (protocol >= 1536) {
        // This is an EthernetType2 Frame
        // try hal.printf("---Ethernet Frame---\nSMAC: {X:0<2}:{X:0<2}:{X:0<2}:{X:0<2}:{X:0<2}:{X:0<2}\nDMAC: {X:0<2}:{X:0<2}:{X:0<2}:{X:0<2}:{X:0<2}:{X:0<2}\ntype: {X:0<4}\n", .{ eth_header.dest[0], eth_header.dest[1], eth_header.dest[2], eth_header.dest[3], eth_header.dest[4], eth_header.dest[5], eth_header.src[0], eth_header.src[1], eth_header.src[2], eth_header.src[3], eth_header.src[4], eth_header.src[5], std.mem.nativeToBig(u16, eth_header.len_or_type) });
        switch (@as(EtherType, @enumFromInt(protocol))) {
            .IPv4 => {
                // try m.printf("IPv4 Frame Received!\n", .{});
                try ipv4.processIPv4Frame(.{ .header = eth_header, .payload = buffer[@sizeOf(EthernetHeader)..] });
            },
            .ARP => {
                // try hal.printf("ARP Frame Received!\n", .{});
                try arp.processARPFrame(.{ .header = eth_header, .payload = buffer[@sizeOf(EthernetHeader)..] });
            },
            _ => {},
        }
    } else {
        // This is a length
    }
}

pub const Context = struct {
    buffer: []u8,
    len_or_type: EtherType,
};

pub fn send(dmac_addr: [6]u8, slot: *Node, proto: EtherType) !void {
    const header: EthernetHeader = .{
        .dest = dmac_addr,
        .src = mac_addr,
        .len_or_type = std.mem.nativeToBig(u16, @intFromEnum(proto)),
    };

    @memcpy(slot.header[0..14], std.mem.asBytes(&header));

    // hal.transmitEthFrame(ctx.buffer[0 .. 14 + payload.len]);
    wire.transmitEthFrame();
}

// pub fn send(dmac_addr: [6]u8, payload: []u8, ctx: Context) !void {
//     const header: EthernetHeader = .{
//         .dest = dmac_addr,
//         .src = mac_addr,
//         .len_or_type = std.mem.nativeToBig(u16, @intFromEnum(ctx.len_or_type)),
//     };

//     @memcpy(ctx.buffer[0..14], std.mem.asBytes(&header));

//     // for (0..14 + payload.len) |i| {
//     //     try hal.printf("{X:0>2} ", .{ctx.buffer[i]});
//     // }
//     // var p = [_]u8{ 0x54, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x20, 0x6f, 0x6e, 0x20, 0x53, 0x54, 0x4d, 0x33, 0x32 };
//     // const payload_len = p.len;

//     // if (hal.requestBuffer()) |buffer| {
//     //     // @memcpy(buffer.ptr, p);
//     //     try hal.transmitEthFrame(buffer);
//     // }

//     hal.transmitEthFrame(ctx.buffer[0 .. 14 + payload.len]);

//     // ETH_ConstructEthernetFrame(TxBuffer.buffer, dest_mac, src_mac, type, payload, payload_len);
//     // TxConfig.TxBuffer = &TxBuffer;

//     // HAL_ETH_Transmit(&heth, &TxConfig, 1000);
//     // HAL_ETH_ReleaseTxPacket(&heth);

//     // try hal.transmitEthFrame(ctx.buffer);
// }
