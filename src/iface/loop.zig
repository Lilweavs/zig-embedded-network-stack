const std = @import("std");
const types = @import("../types.zig");
const ipv4 = @import("../core/ipv4.zig");

pub const LoopDevice = struct {
    rx_buf: [2048]u8 = undefined,
    rx_len: usize = 0,
    has_data: bool = false,
};

pub fn loopSend(dev: *LoopDevice, iface: *types.Interface, dst_mac: [6]u8, frame: *types.Frame, ethertype: u16) void {
    _ = iface;
    _ = dst_mac;
    _ = ethertype;
    const data = frame.buffer[0..frame.len];
    @memcpy(dev.rx_buf[0..data.len], data);
    dev.rx_len = data.len;
    dev.has_data = true;
}

pub fn loopRecv(dev: *LoopDevice) ?[]u8 {
    if (!dev.has_data) return null;
    dev.has_data = false;
    return dev.rx_buf[0..dev.rx_len];
}

pub fn loopProcess(dev: *LoopDevice, iface: *types.Interface, buffer: []u8) void {
    _ = dev;
    ipv4.processIPv4Frame(iface, buffer);
}

pub fn init(dev: *LoopDevice) void {
    _ = dev;
}
