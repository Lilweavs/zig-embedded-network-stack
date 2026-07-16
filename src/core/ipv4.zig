const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const ipv4 = syntax.ipv4;
const eth = syntax.eth;
const arp = @import("../core/arp.zig");

pub const Protocol = ipv4.Protocol;
pub const IPv4Header = ipv4.IPv4Header;
pub const IPv4Frame = ipv4.IPv4Frame;
pub const VersionIHl = ipv4.VersionIHl;
pub const IP_BROADCAST_ADDR = ipv4.IP_BROADCAST_ADDR;
pub const calculateIPv4Checksum = ipv4.calculateChecksum;
pub const calcPseudoChecksum = ipv4.calcPseudoChecksum;
pub const getPsuedoHeaderChecksum = ipv4.getPsuedoHeaderChecksum;
pub const fmtIpAddr = ipv4.fmtIpAddr;

const Ipv4ProtocolHandler = *const fn (iface: *types.Interface, saddr: u32, buffer: []u8) void;

var protocol_handlers: [256]?Ipv4ProtocolHandler = .{null} ** 256;

const logger = std.log.scoped(.ipv4);

pub fn registerProtocolHandler(proto: Protocol, handler: Ipv4ProtocolHandler) void {
    protocol_handlers[@intFromEnum(proto)] = handler;
}

pub fn send(iface: *types.Interface, daddr: u32, frame: *types.Frame, proto: Protocol) void {
    const ip_payload_len: u32 = @intCast(frame.len);
    const header: IPv4Header = .{
        .length = std.mem.nativeToBig(u16, @intCast(@sizeOf(IPv4Header) + ip_payload_len)),
        .ttl = 255,
        .protocol = @as(u8, @intFromEnum(proto)),
        .saddr = iface.ip_addr,
        .daddr = daddr,
    };

    @memcpy(frame.buffer[types.NET_HEADER_OFFSET..][0..@sizeOf(IPv4Header)], std.mem.asBytes(&header));

    frame.len += @sizeOf(IPv4Header);

    // if we are a braodcast address we can skip the arp lookup
    if (header.daddr == IP_BROADCAST_ADDR) {
        iface.send(.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, frame, @intFromEnum(eth.EtherType.IPv4));
    }

    if (arp.fetchArpEntry(iface, daddr)) |dmac| {
        iface.send(dmac, frame, @intFromEnum(eth.EtherType.IPv4));
    }
}

pub fn processIPv4Frame(iface: *types.Interface, buffer: []u8) void {
    const header: IPv4Header = std.mem.bytesToValue(IPv4Header, buffer[0..@sizeOf(IPv4Header)]);
    const length: usize = @intCast(std.mem.bigToNative(u16, header.length));
    const header_len = @as(usize, header.version_ihl.ihl) * 4;
    const payload = buffer[header_len..length];

    if (protocol_handlers[header.protocol]) |handler| {
        handler(iface, header.saddr, payload);
    }
}
