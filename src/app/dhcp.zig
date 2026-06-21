const std = @import("std");
const types = @import("../types.zig");
const udp = @import("../core/udp.zig");
const ipv4 = @import("../core/ipv4.zig");

const server_port: u16 = 67;
const client_port: u16 = 68;

var state: DHCPState = .Uninit;
var socket: ?*udp.UDPSocket = null;
var start_time: u32 = 0;
var dhcp_iface: *types.Interface = undefined;

const DHCPState = enum {
    Disable,
    Uninit,
    Discover,
    WaitingForOffer,
    WaitingForAck,
    Complete,
};

const DHCPOpCode = enum(u8) {
    BOOTREQEUEST = 1,
    BOOTREPLY = 2,
    _,
};

const DHCPHeader = extern struct {
    op: u8 align(1),
    htype: u8 align(1) = 0x01,
    hlen: u8 align(1) = 0x06,
    hops: u8 align(1) = 0x00,
    xid: u32 align(1),
    secs: u16 align(1) = 0x0000,
    flags: u16 align(1) = std.mem.nativeToBig(u16, 0x8000),
    ciaddr: [4]u8 align(1) = .{ 0, 0, 0, 0 },
    yiaddr: [4]u8 align(1) = .{ 0, 0, 0, 0 },
    siaddr: [4]u8 align(1) = .{ 0, 0, 0, 0 },
    giaddr: [4]u8 align(1) = .{ 0, 0, 0, 0 },
    chaddr: [16]u8 align(1) = .{0} ** 16,
    sname: [64]u8 align(1) = .{0} ** 64,
    file: [128]u8 align(1) = .{0} ** 128,
    magic_cookie: [4]u8 align(1) = .{ 0x63, 0x82, 0x53, 0x63 },
};

var dhcp_buffer: [1528]u8 = .{0} ** 1528;
var magic_number: u32 = 0;
var server_addr: u32 = 0;
var subnet_mask: u32 = 0;
var broadcast_address: u32 = 0;
var requested_addr: u32 = 0;
var gateway_addr: u32 = 0;
var lease_time: u32 = 0;
var renewal_time: u32 = 0;

pub fn init(iface: *types.Interface) void {
    dhcp_iface = iface;
    socket = udp.requestSocketFromPool();
    if (socket) |s| {
        s.bind(client_port, dhcpRecvCallback);
        state = .Discover;

        var prng = std.Random.DefaultPrng.init(1);
        const rand = prng.random();
        magic_number = rand.int(u32);
    }
}

const OptionIterator = struct {
    const Self = @This();
    buffer: []const u8,
    index: usize = 0,

    pub fn next(self: *Self) ?OptionPayload {
        const code = @as(DHCPOptions, @enumFromInt(self.buffer[self.index]));

        if (code == .End) return null;
        if (code == .Pad) {
            self.index += 1;
            return .{ .code = code, .payload = &.{} };
        }

        const length = self.buffer[self.index + 1];
        self.index += 2 + length;

        if (self.index > self.buffer.len) return null;

        return .{ .code = code, .payload = self.buffer[self.index - length .. self.index] };
    }
};

const OptionPayload = struct {
    code: DHCPOptions,
    payload: []const u8,
};

fn dhcpRecvCallback(sock: *udp.UDPSocket, addr: u32, port: u16, payload: []const u8) void {
    _ = sock;
    _ = addr;
    _ = port;

    if (payload.len < @sizeOf(DHCPHeader)) return;

    const dhcp_data: DHCPHeader = std.mem.bytesToValue(DHCPHeader, payload[0..@sizeOf(DHCPHeader)]);

    if (dhcp_data.xid != magic_number) return;

    if (state == .WaitingForOffer and dhcp_data.op == 2) {
        requested_addr = std.mem.bytesToValue(u32, &dhcp_data.yiaddr);

        var iter = OptionIterator{ .buffer = payload[@sizeOf(DHCPHeader)..] };

        while (iter.next()) |option| {
            switch (option.code) {
                .SubnetMask => { subnet_mask = std.mem.bytesToValue(u32, option.payload); },
                .BroadcastAddress => { broadcast_address = std.mem.bytesToValue(u32, option.payload); },
                .IPAddressLeaseTime => { lease_time = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, option.payload)); },
                else => {},
            }
        }

        dhcpRequest() catch {};
    } else if (state == .WaitingForAck and dhcp_data.op == 2) {
        state = .Complete;
        dhcp_iface.ip_addr = requested_addr;
    }
}

pub fn dhcpPoll() DHCPState {
    switch (state) {
        .Disable => {},
        .Uninit => {},
        .Discover => { dhcpDiscover() catch {}; },
        .WaitingForOffer => {},
        .WaitingForAck => {},
        .Complete => {},
    }
    return state;
}

const DHCPOptions = enum(u8) {
    Pad = 0,
    SubnetMask = 1,
    Router = 3,
    TimeServer = 4,
    DomainNameServer = 6,
    HostName = 12,
    DomainName = 15,
    InterfaceMTU = 26,
    BroadcastAddress = 28,
    NTPServers = 42,
    RequestIdAddress = 50,
    IPAddressLeaseTime = 51,
    OptionOverload = 52,
    DHCPMessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    RenewalTime = 58,
    RebindingTime = 59,
    End = 255,
    _,
};

pub fn status() DHCPState {
    return state;
}

pub fn dhcpRequest() !void {
    if (socket) |s| {
        const time_since_discover: u16 = @intCast((start_time) / 1000);

        var dhcp_header: DHCPHeader = .{
            .op = 0x01,
            .xid = magic_number,
            .secs = time_since_discover,
        };

        @memcpy(dhcp_header.chaddr[0..6], &dhcp_iface.mac_addr);

        var pos: usize = 0;
        var end: usize = @sizeOf(DHCPHeader);
        @memcpy(dhcp_buffer[pos..end], std.mem.asBytes(&dhcp_header));

        pos = end;
        end += 3;

        dhcp_buffer[pos] = 0x35;
        dhcp_buffer[pos + 1] = 0x01;
        dhcp_buffer[pos + 2] = 0x03;

        dhcp_buffer[pos + 3] = 50;
        dhcp_buffer[pos + 4] = 0x04;
        pos = pos + 5;
        end = pos + @sizeOf(u32);
        @memcpy(dhcp_buffer[pos..end], std.mem.asBytes(&requested_addr));
        dhcp_buffer[end] = 0xff;

        s.send_broadcast(dhcp_iface, server_port, dhcp_buffer[0 .. end + 1]) catch {};

        state = .WaitingForAck;
    }
}

pub fn dhcpDiscover() !void {
    if (socket) |s| {
        var dhcp_header: DHCPHeader = .{
            .op = 0x01,
            .xid = magic_number,
            .secs = 0x0000,
        };

        start_time = 0;

        @memcpy(dhcp_header.chaddr[0..6], &dhcp_iface.mac_addr);

        var pos: usize = 0;
        var end: usize = @sizeOf(DHCPHeader);
        @memcpy(dhcp_buffer[pos..end], std.mem.asBytes(&dhcp_header));

        pos = end;
        end += 3;

        dhcp_buffer[pos] = 0x35;
        dhcp_buffer[pos + 1] = 0x01;
        dhcp_buffer[pos + 2] = 0x01;
        dhcp_buffer[pos + 3] = 0xff;

        s.send_broadcast(dhcp_iface, server_port, dhcp_buffer[0 .. end + 1]) catch {};

        state = .WaitingForOffer;
    }
}

test "option-parse" {}
