const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const arp = syntax.arp;
const eth = syntax.eth;

pub const ArpFrame = arp.ArpFrame;
pub const Opcode = arp.Opcode;

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
        if (table[i].ip_addr == addr) break table[i].mac;
    } else null;
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
            const eth_type = eth.EtherType.ARP;
            const eth_resp: eth.EthernetHeader = .{
                .dest = recv_header.shwaddr,
                .src = iface.mac_addr,
                .len_or_type = std.mem.nativeToBig(u16, @intFromEnum(eth_type)),
            };

            var pos: usize = 0;
            var end: usize = @sizeOf(eth.EthernetHeader);
            @memcpy(frame.buffer[pos..end], std.mem.asBytes(&eth_resp));

            pos = end;
            end = pos + @sizeOf(ArpFrame);
            @memcpy(frame.buffer[pos..end], std.mem.asBytes(&resp_header));

            frame.len = end;
            iface.send(recv_header.shwaddr, frame, @intFromEnum(eth_type));
        }

        if (fetchArpEntry(iface, recv_header.sipaddr)) |_| {} else {
            addArpEntry(iface, recv_header.sipaddr, eth_hdr.src);
        }
    }
}
