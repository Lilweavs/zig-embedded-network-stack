const std = @import("std");
const builtin = @import("builtin");
const udp = @import("udp.zig");
const eth = @import("eth.zig");
const icmp = @import("icmp.zig");
const ipv4 = @import("ipv4.zig");
const hal = @import("hal.zig");

// 1 = request
// 2 = reply

const ArpFrame = extern struct {
    htype: u16 align(1) = std.mem.nativeToBig(u16, 0x01),
    ptype: u16 align(1) = std.mem.nativeToBig(u16, 0x0800),
    hsize: u8 align(1) = 0x06,
    psize: u8 align(1) = 0x04,
    opcode: u16 align(1),
    shwaddr: [6]u8 align(1) = .{0x00} ** 6,
    sipaddr: u32 align(1),
    thwaddr: [6]u8 align(1) = .{0x00} ** 6,
    tipaddr: u32 align(1),
};

const Entry = struct {
    ip_addr: u32 = 0,
    mac: [6]u8 = .{0} ** 6,
    time: u32 = 0,
    valid: bool = false,
};

var table = [_]Entry{Entry{}} ** 16;

pub fn addArpEntry(addr: u32, mac: [6]u8) void {
    for (0..table.len) |i| {
        if (table[i].valid == false) {
            table[i] = .{
                .valid = true,
                .mac = mac,
                .ip_addr = addr,
            };
            return;
        }
    }
}

pub fn fetchArpEntry(addr: u32) ?[6]u8 {
    return for (0..table.len) |i| {
        if (table[i].valid == false) break null;
        if (table[i].ip_addr == addr) break table[i].mac;
    } else null;
}

// todo broadcast arp

pub fn processARPFrame(frame: eth.EthernetFrame) !void {
    const recv_header: ArpFrame = std.mem.bytesToValue(ArpFrame, frame.payload[0..@sizeOf(ArpFrame)]);

    // try hal.printf("ARP From: {}\n", .{ipv4.fmtIpAddr(recv_header.sipaddr)});
    // try hal.printf("ARP Want: {}\n", .{ipv4.fmtIpAddr(recv_header.tipaddr)});
    // try hal.printf("ARP Have: {}\n", .{ipv4.fmtIpAddr(ipv4.ip_addr)});
    if (recv_header.tipaddr == ipv4.ip_addr) {
        // try ipv4.printIpAddr(header.sipaddr);

        const resp_header: ArpFrame = .{
            .opcode = std.mem.nativeToBig(u16, 0x02),
            .shwaddr = eth.mac_addr,
            .sipaddr = recv_header.tipaddr,
            .thwaddr = recv_header.shwaddr,
            .tipaddr = recv_header.sipaddr,
        };

        if (hal.requestBuffer()) |buffer| {
            const eth_header: eth.EthernetHeader = .{
                .dest = recv_header.shwaddr,
                .src = eth.mac_addr,
                .len_or_type = std.mem.nativeToBig(u16, @intFromEnum(eth.EtherType.ARP)),
            };

            var pos: usize = 0;
            var end: usize = @sizeOf(eth.EthernetHeader);

            @memcpy(buffer[pos..end], std.mem.asBytes(&eth_header));

            pos = end;
            end = pos + @sizeOf(ArpFrame);

            @memcpy(buffer[pos..end], std.mem.asBytes(&resp_header));

            // try hal.printf("End: {d}\n", .{end});

            try hal.transmitEthFrame(buffer[0..end]);
        }

        if (fetchArpEntry(recv_header.sipaddr)) |_| {} else {
            // update arp table
            addArpEntry(recv_header.sipaddr, frame.header.src);
            try printArpTable();
        }
    }
}

pub fn printArpTable() !void {
    // try hal.printf("Interface: {} --- 0x4", .{ipv4.fmtIpAddr(ipv4.ip_addr)});
    // try hal.printf("  Internet Address      Physical Address \n", .{});
    // for (table) |entry| {
    // try hal.printf("  {}    {}\n", .{ ipv4.fmtIpAddr(entry.ip_addr), eth.fmtMacAddr(entry.mac) });
    // }
    // try hal.printf("\n", .{});
}
