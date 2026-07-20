const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const arp = syntax.arp;
const eth = syntax.eth;
const ipv4 = syntax.ipv4;

pub const ArpFrame = arp.ArpFrame;
pub const Opcode = arp.Opcode;

const logger = std.log.scoped(.arp);

pub fn addArpEntry(iface: *types.Interface, addr: u32, mac: [6]u8) void {
    const table = iface.arp_table;
    for (0..table.len) |i| {
        if (table[i].valid == false) {
            table[i] = .{ .valid = true, .mac = mac, .ip_addr = addr };
            return;
        }
    }
}

pub fn fetchArpEntry(iface: *types.Interface, addr: u32) ?[6]u8 {
    const table = iface.arp_table;
    return for (0..table.len) |i| {
        if (table[i].valid == false) break null;
        if (table[i].ip_addr == addr) {
            logger.debug("ARP: Fetch {f} -> {f}\n", .{ ipv4.fmtIpAddr(addr), eth.fmtMacAddr(table[i].mac) });
            break table[i].mac;
        }
    } else null;
}

pub fn arpDiscover(iface: *types.Interface, tipaddr: u32) void {
    logger.debug("ARP: Discover {f}\n", .{ipv4.fmtIpAddr(tipaddr)});
    if (iface.requestFrame()) |frame| {
        const header: ArpFrame = .{
            .opcode = std.mem.nativeToBig(u16, @intFromEnum(Opcode.Request)),
            .shwaddr = iface.mac_addr,
            .sipaddr = iface.ip_addr,
            .tipaddr = tipaddr,
        };

        const pos: usize = types.NET_HEADER_OFFSET;
        const end: usize = pos + @sizeOf(ArpFrame);
        @memcpy(frame.buffer[pos..end], std.mem.asBytes(&header));

        iface.send(.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, frame, @intFromEnum(syntax.eth.EtherType.ARP));
    }
}

pub fn processARPFrame(iface: *types.Interface, buffer: []u8) void {
    const eth_hdr = std.mem.bytesToValue(eth.EthernetHeader, buffer[0..@sizeOf(eth.EthernetHeader)]);
    const payload = buffer[@sizeOf(eth.EthernetHeader)..];
    const recv_header: ArpFrame = arp.readFrame(payload);

    if (recv_header.tipaddr == iface.ip_addr) {
        const resp_header: ArpFrame = .{
            .opcode = std.mem.nativeToBig(u16, @intFromEnum(Opcode.Reply)),
            .shwaddr = iface.mac_addr,
            .sipaddr = recv_header.tipaddr,
            .thwaddr = recv_header.shwaddr,
            .tipaddr = recv_header.sipaddr,
        };

        if (iface.requestFrame()) |frame| {
            logger.debug("ARP: Receive {f} -> {f}\n", .{ ipv4.fmtIpAddr(recv_header.sipaddr), eth.fmtMacAddr(recv_header.shwaddr) });

            const pos = types.NET_HEADER_OFFSET;
            const end = pos + @sizeOf(ArpFrame);
            @memcpy(frame.buffer[pos..end], std.mem.asBytes(&resp_header));

            frame.len = end;
            iface.send(recv_header.shwaddr, frame, @intFromEnum(eth.EtherType.ARP));
        }

        if (fetchArpEntry(iface, recv_header.sipaddr)) |_| {} else {
            addArpEntry(iface, recv_header.sipaddr, eth_hdr.src);
        }
    }
}
