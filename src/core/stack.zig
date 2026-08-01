const std = @import("std");
const types = @import("../types.zig");
const arp = @import("../core/arp.zig");
const ipv4 = @import("../core/ipv4.zig");
const icmp = @import("../core/icmp.zig");
const udp = @import("../core/udp.zig");
const tcp = @import("../core/tcp.zig");
const time = @import("../time.zig");

pub const Config = struct {
    enable_arp: bool = true,
    enable_ipv4: bool = true,
    enable_icmp: bool = true,
    enable_udp: bool = true,
    enable_tcp: bool = true,
    millis: *const fn () u32,
};

pub fn NetworkStack(comptime iface_count: usize, comptime arp_entries: usize, comptime cfg: Config) type {
    return struct {
        const Self = @This();

        interfaces: [iface_count]types.Interface = undefined,
        arp_backing: [iface_count][arp_entries]types.ArpEntry = undefined,
        arp_pending_backing: [iface_count][arp_entries]types.ArpPendingEntry = undefined,

        pub fn init(self: *Self) void {
            time.set(cfg.millis);

            for (&self.interfaces, &self.arp_backing, &self.arp_pending_backing) |*iface, *arpBacking, *pendingBacking| {
                iface.arp_table = arpBacking;
                iface.arp_pending = pendingBacking;
                iface.init();
            }

            if (comptime cfg.enable_ipv4) {
                if (comptime cfg.enable_icmp) {
                    ipv4.registerProtocolHandler(.ICMP, icmp.processICMPPacket);
                }
                if (comptime cfg.enable_udp) {
                    ipv4.registerProtocolHandler(.UDP, udp.processUDPFrame);
                }
                if (comptime cfg.enable_tcp) {
                    ipv4.registerProtocolHandler(.TCP, tcp.processTCPFrame);
                }
            }
        }

        pub fn poll(self: *Self) void {
            for (&self.interfaces) |*iface| {
                arp.processPending(iface);
                while (iface.recv()) |frame| {
                    iface.processFrame(frame);
                }
            }
            tcp.dispatchAccept();
            tcp.dispatchEvents();
        }
    };
}
