const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const arp = syntax.arp;
const eth = syntax.eth;
const ipv4 = syntax.ipv4;
const time = @import("../time.zig");

pub const ArpFrame = arp.ArpFrame;
pub const Opcode = arp.Opcode;

const logger = std.log.scoped(.arp);

const ARP_PENDING_TIMEOUT_MS: u32 = 5000;
const ARP_MAX_RETRIES: u32 = 3;
const ARP_RETRY_INTERVAL_MS: u32 = 500;

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

pub fn addPending(iface: *types.Interface, target_ip: u32, frame: *types.Frame) !void {
    const pending = iface.arp_pending;
    for (0..pending.len) |i| {
        if (pending[i].target_ip == 0) {
            pending[i] = .{
                .target_ip = target_ip,
                .frame = frame,
                .first_seen = time.millis(),
                .retries = 0,
            };
            logger.debug("ARP: Pending {f}\n", .{ipv4.fmtIpAddr(target_ip)});
            return;
        }
    }
    logger.debug("ARP: Pending table full, dropping frame for {f}\n", .{ipv4.fmtIpAddr(target_ip)});
    return error.ArpTableFull;
}

pub fn removePending(iface: *types.Interface, target_ip: u32) void {
    const pending = iface.arp_pending;
    for (0..pending.len) |i| {
        if (pending[i].target_ip == target_ip) {
            pending[i] = .{};
            return;
        }
    }
}

pub fn flushPending(iface: *types.Interface, target_ip: u32, mac: [6]u8) void {
    const pending = iface.arp_pending;
    for (0..pending.len) |i| {
        if (pending[i].target_ip == target_ip) {
            if (pending[i].frame) |frame| {
                logger.debug("ARP: Flushing pending frame for {f}\n", .{ipv4.fmtIpAddr(target_ip)});
                iface.send(mac, frame, @intFromEnum(eth.EtherType.IPv4));
            }
            pending[i] = .{};
        }
    }
}

fn sendArpRequest(iface: *types.Interface, tipaddr: u32) !void {
    const frame = iface.requestFrame() orelse return error.FrameQueueFull;

    const header: ArpFrame = .{
        .opcode = std.mem.nativeToBig(u16, @intFromEnum(Opcode.Request)),
        .shwaddr = iface.mac_addr,
        .sipaddr = iface.ip_addr,
        .tipaddr = tipaddr,
    };

    const pos: usize = types.NET_HEADER_OFFSET;
    const end: usize = pos + @sizeOf(ArpFrame);
    @memcpy(frame.buffer[pos..end], std.mem.asBytes(&header));

    frame.len = @sizeOf(ArpFrame);
    iface.send(.{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, frame, @intFromEnum(eth.EtherType.ARP));
}

pub fn arpDiscover(iface: *types.Interface, tipaddr: u32, frame: ?*types.Frame) void {
    logger.debug("ARP: Discover {f}\n", .{ipv4.fmtIpAddr(tipaddr)});

    sendArpRequest(iface, tipaddr) catch {
        if (frame) |f| iface.returnFrame(f);
    };
    if (frame) |f| {
        addPending(iface, tipaddr, f) catch {
            iface.returnFrame(f);
        };
    }
}

pub fn processARPFrame(iface: *types.Interface, buffer: []u8) void {
    const recv_header: ArpFrame = arp.readFrame(buffer);

    if (recv_header.tipaddr == iface.ip_addr) {
        if (fetchArpEntry(iface, recv_header.sipaddr)) |_| {} else {
            addArpEntry(iface, recv_header.sipaddr, recv_header.shwaddr);
        }

        flushPending(iface, recv_header.sipaddr, recv_header.shwaddr);

        const opcode: Opcode = @enumFromInt(std.mem.bigToNative(u16, recv_header.opcode));
        if (opcode == .Request) {
            const resp_header: ArpFrame = .{
                .opcode = std.mem.nativeToBig(u16, @intFromEnum(Opcode.Reply)),
                .shwaddr = iface.mac_addr,
                .sipaddr = recv_header.tipaddr,
                .thwaddr = recv_header.shwaddr,
                .tipaddr = recv_header.sipaddr,
            };

            if (iface.requestFrame()) |frame| {
                logger.debug("ARP: Reply {f} -> {f}\n", .{ ipv4.fmtIpAddr(recv_header.sipaddr), eth.fmtMacAddr(recv_header.shwaddr) });

                const pos = types.NET_HEADER_OFFSET;
                const end = pos + @sizeOf(ArpFrame);
                @memcpy(frame.buffer[pos..end], std.mem.asBytes(&resp_header));

                frame.len = @sizeOf(ArpFrame);
                iface.send(recv_header.shwaddr, frame, @intFromEnum(eth.EtherType.ARP));
            }
        }
    }
}

pub fn processPending(iface: *types.Interface) void {
    const now = time.millis();
    const pending = iface.arp_pending;

    for (0..pending.len) |i| {
        if (pending[i].target_ip == 0) continue;

        const elapsed = now -% pending[i].first_seen;

        if (elapsed > ARP_PENDING_TIMEOUT_MS) {
            logger.debug("ARP: Pending timeout for {f}\n", .{ipv4.fmtIpAddr(pending[i].target_ip)});
            if (pending[i].frame) |frame| {
                iface.returnFrame(frame);
            }
            pending[i] = .{};
            continue;
        }

        if (pending[i].retries < ARP_MAX_RETRIES) {
            const time_since_first = now -% pending[i].first_seen;
            const next_retry = (pending[i].retries + 1) * ARP_RETRY_INTERVAL_MS;
            if (time_since_first >= next_retry) {
                pending[i].retries += 1;
                logger.debug("ARP: Retry {d} for {f}\n", .{ pending[i].retries, ipv4.fmtIpAddr(pending[i].target_ip) });
                sendArpRequest(iface, pending[i].target_ip) catch @panic("TODO: Not handled yet");
            }
        }
    }
}
