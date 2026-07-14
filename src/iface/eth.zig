const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax/eth.zig");
const arp = @import("../core/arp.zig");
const ipv4 = @import("../core/ipv4.zig");

const logger = std.log.scoped(.eth);

pub const EthDevice = struct {
    transmit: *const fn (buf: []const u8) void = undefined,
    poll_recv: *const fn () ?[]u8 = undefined,
};

pub fn ethSend(dev: *EthDevice, iface: *types.Interface, dst_mac: [6]u8, frame: *types.Frame, ethertype: u16) void {
    const header: syntax.EthernetHeader = .{
        .dest = dst_mac,
        .src = iface.mac_addr,
        .len_or_type = std.mem.nativeToBig(u16, ethertype),
    };
    frame.len += @sizeOf(syntax.EthernetHeader);
    syntax.writeHeader(frame.buffer[0..], header);
    dev.transmit(frame.buffer[0..frame.len]);
}

pub fn ethProcess(dev: *EthDevice, iface: *types.Interface, buffer: []u8) void {
    _ = dev;
    const eth_header = syntax.readHeader(buffer);
    const protocol = std.mem.bigToNative(u16, eth_header.len_or_type);

    if (protocol >= 1536) {
        switch (@as(syntax.EtherType, @enumFromInt(protocol))) {
            .IPv4 => ipv4.processIPv4Frame(iface, buffer[types.NET_HEADER_OFFSET..]),
            .ARP => arp.processARPFrame(iface, buffer),
            _ => {},
        }
    }
}

pub fn ethRecv(dev: *EthDevice) ?[]u8 {
    return dev.poll_recv();
}

pub fn init(dev: *EthDevice) void {
    _ = dev;
}
