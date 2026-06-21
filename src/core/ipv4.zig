const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax/ipv4.zig");
const arp = @import("../core/arp.zig");

pub const Protocol = syntax.Protocol;
pub const IPv4Header = syntax.IPv4Header;
pub const IPv4Frame = syntax.IPv4Frame;
pub const VersionIHl = syntax.VersionIHl;
pub const IP_BROADCAST_ADDR = syntax.IP_BROADCAST_ADDR;
pub const calculateIPv4Checksum = syntax.calculateChecksum;
pub const calcPseudoChecksum = syntax.calcPseudoChecksum;
pub const getPsuedoHeaderChecksum = syntax.getPsuedoHeaderChecksum;
pub const fmtIpAddr = syntax.fmtIpAddr;

const Ipv4ProtocolHandler = *const fn (iface: *types.Interface, saddr: u32, buffer: []u8) void;

var protocol_handlers: [256]?Ipv4ProtocolHandler = .{null} ** 256;

pub fn registerProtocolHandler(proto: Protocol, handler: Ipv4ProtocolHandler) void {
    protocol_handlers[@intFromEnum(proto)] = handler;
}

pub fn send(iface: *types.Interface, daddr: u32, slot: *types.Node, proto: Protocol) void {
    const ip_payload_len: u32 = @intCast(slot.data.len);
    const header: IPv4Header = .{
        .length = std.mem.nativeToBig(u16, @intCast(@sizeOf(IPv4Header) + ip_payload_len)),
        .ttl = 255,
        .protocol = @as(u8, @intFromEnum(proto)),
        .saddr = iface.ip_addr,
        .daddr = daddr,
    };

    @memcpy(slot.header[types.NET_HEADER_OFFSET..][0..@sizeOf(IPv4Header)], std.mem.asBytes(&header));

    if (arp.fetchArpEntry(iface, daddr)) |dmac| {
        iface.send(dmac, slot, @intFromEnum(@import("../syntax/eth.zig").EtherType.IPv4));
    }
}

pub fn processIPv4Frame(iface: *types.Interface, buffer: []u8) void {
    const payload = buffer[@sizeOf(@import("../syntax/eth.zig").EthernetHeader)..];
    const header: IPv4Header = std.mem.bytesToValue(IPv4Header, payload[0..@sizeOf(IPv4Header)]);

    const pos: usize = @sizeOf(IPv4Header);
    const end: usize = std.mem.bigToNative(u16, header.length);

    if (protocol_handlers[header.protocol]) |handler| {
        handler(iface, header.saddr, payload[pos..end]);
    }
}
