const std = @import("std");
const syntax = @import("syntax.zig");
const ipv4 = syntax.ipv4;
const udp = syntax.udp;
const core_udp = @import("core/udp.zig");
const core_arp = @import("core/arp.zig");
const core_tcp = @import("core/tcp.zig");
const core_stack = @import("core/stack.zig");
const dhcp = @import("app/dhcp.zig");

test "include ipv4" { _ = ipv4; }
test "include udp" { _ = udp; }
test "include core_udp" { _ = core_udp; }
test "include core_arp" { _ = core_arp; }
test "include core_tcp" { _ = core_tcp; }
test "include core_stack" { _ = core_stack; }
test "include dhcp" { _ = dhcp; }

fn testMillis() u32 {
    return 0;
}

test "NetworkStack creation" {
    const Stack = core_stack.NetworkStack(2, 8, .{
        .enable_tcp = true,
        .enable_udp = true,
        .enable_arp = true,
        .enable_icmp = true,
        .millis = testMillis,
    });
    var stack: Stack = .{};
    stack.init();

    try std.testing.expectEqual(2, stack.interfaces.len);
    try std.testing.expectEqual(8, stack.arp_backing[0].len);
}

test "loopback device send/recv" {
    const Stack = core_stack.NetworkStack(1, 4, .{
        .enable_tcp = false,
        .enable_udp = false,
        .enable_arp = false,
        .enable_icmp = false,
        .millis = testMillis,
    });
    var stack: Stack = .{};
    stack.init();

    const iface = &stack.interfaces[0];
    iface.ip_addr = 0x7F000001;
    iface.subnet_mask = 0xFF000000;
    iface.mac_addr = .{0} ** 6;
    iface.device = .{ .loop = .{} };
    iface.init();

    const test_data = [_]u8{ 0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01 };
    {
        const slot = iface.requestSlot().?;
        @memcpy(slot.header[0..test_data.len], &test_data);
        slot.len = test_data.len;
        slot.data = slot.header[0..slot.len];
        iface.send(.{0} ** 6, slot, 0x0800);
    }

    const recvd = iface.recv();
    try std.testing.expect(recvd != null);
    try std.testing.expectEqualSlices(u8, &test_data, recvd.?[0..test_data.len]);
}
