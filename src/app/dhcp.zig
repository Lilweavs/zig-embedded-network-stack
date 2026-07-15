const std = @import("std");
const types = @import("../types.zig");
const udp = @import("../core/udp.zig");
const ipv4 = @import("../core/ipv4.zig");
const time = @import("../time.zig");

const logger = std.log.scoped(.dhcp);

const server_port: u16 = 67;
const client_port: u16 = 68;

var state: DHCPState = .Uninit;
var socket: ?*udp.UDPSocket = null;
var discover_time: u32 = 0;
var dhcp_iface: *types.Interface = undefined;

const DHCPState = enum {
    Disable,
    Uninit,
    Discover,
    WaitingForOffer,
    WaitingForAck,
    Complete,
    Renewal,
    Rebind,
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
var rebind_time: u32 = 0;

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

    logger.debug("DHCP: Payload Received\n", .{});
    if (payload.len < @sizeOf(DHCPHeader)) return;

    const dhcp_data: DHCPHeader = std.mem.bytesToValue(DHCPHeader, payload[0..@sizeOf(DHCPHeader)]);

    logger.debug("DHCP: xid 0x{X} -> 0x{X}\n", .{ dhcp_data.xid, magic_number });
    if (dhcp_data.xid != magic_number) return;

    if (state == .WaitingForOffer and dhcp_data.op == 2) {
        logger.debug("DHCP: Received Offer\n", .{});
        requested_addr = std.mem.bytesToValue(u32, &dhcp_data.yiaddr);

        var iter = OptionIterator{ .buffer = payload[@sizeOf(DHCPHeader)..] };

        while (iter.next()) |option| {
            if (std.enums.tagName(DHCPOptions, option.code)) |name| {
                logger.debug("DHCP Option: {s}\n", .{name});
            } else {
                logger.debug("DHCP Option: {d}\n", .{@intFromEnum(option.code)});
            }
            switch (option.code) {
                .SubnetMask => {
                    subnet_mask = std.mem.bytesToValue(u32, option.payload);
                },
                .BroadcastAddress => {
                    broadcast_address = std.mem.bytesToValue(u32, option.payload);
                },
                .IPAddressLeaseTime => {
                    lease_time = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, option.payload));
                    const now_s = time.millis() / 1000;
                    renewal_time = now_s + lease_time / 2;
                    rebind_time = now_s + lease_time * 7 / 8;
                    logger.debug("IP lease time: {d}\n", .{lease_time});
                },
                .ServerIdentifier => {
                    server_addr = std.mem.bytesToValue(u32, option.payload);
                },
                else => {},
            }
        }

        dhcpSend(.Request);
    } else if (state == .WaitingForAck and dhcp_data.op == 2) {
        logger.debug("DHCP: Received Ack\n", .{});
        dhcp_iface.ip_addr = requested_addr;

        var iter = OptionIterator{ .buffer = payload[@sizeOf(DHCPHeader)..] };
        while (iter.next()) |option| {
            switch (option.code) {
                .IPAddressLeaseTime => {
                    lease_time = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, option.payload));
                    const now_s = time.millis() / 1000;
                    renewal_time = now_s + lease_time / 2;
                    rebind_time = now_s + lease_time * 7 / 8;
                },
                else => {},
            }
        }

        state = .Complete;
        logger.debug("IpAddr: {f}\n", .{ipv4.fmtIpAddr(requested_addr)});
    }
}

var backoff_time: u32 = 0;
var num_retries: u32 = 0;
const max_retries: u32 = 10;
pub fn poll() DHCPState {
    switch (state) {
        .Disable => {},
        .Uninit => {},
        .Discover => {
            logger.debug("DHCP: Discover\n", .{});
            dhcpSend(.Discover);
        },
        .WaitingForOffer => {
            const now = time.millis();
            if (now -| discover_time >= backoff_time) {
                logger.debug("DHCP: Discover retry\n", .{});
                dhcpSend(.Discover);
                // RFC2131 specifies an exponential backoff
                backoff_time = @min(backoff_time * 2, 60 * std.time.ms_per_s);
                num_retries += 1;
                if (num_retries >= max_retries) {
                    logger.debug("DHCP: Discover failed\n", .{});
                    state = .Disable;
                }
            }
        },
        .WaitingForAck => {},
        .Complete => {
            const now_s = time.millis() / 1000;
            if (now_s >= rebind_time) {
                logger.debug("DHCP: Rebinding\n", .{});
                dhcpSend(.Rebind);
            } else if (now_s >= renewal_time) {
                logger.debug("DHCP: Renewing\n", .{});
                dhcpSend(.Renew);
            }
        },
        .Renewal => {},
        .Rebind => {},
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

const MessageType = enum {
    Discover,
    Request,
    Renew,
    Rebind,
};

pub fn dhcpSend(msg: MessageType) void {
    if (socket) |s| {
        const now = time.millis();
        var dhcp_header: DHCPHeader = .{
            .op = 0x01,
            .xid = magic_number,
            .ciaddr = switch (msg) {
                .Renew, .Rebind => @bitCast(dhcp_iface.ip_addr),
                .Discover, .Request => .{ 0, 0, 0, 0 },
            },
            .secs = if (msg == .Request) @intCast((now -| discover_time) / 1000) else 0,
        };

        if (msg == .Discover) discover_time = now;

        @memcpy(dhcp_header.chaddr[0..6], &dhcp_iface.mac_addr);

        var pos: usize = 0;
        var end: usize = @sizeOf(DHCPHeader);
        @memcpy(dhcp_buffer[pos..end], std.mem.asBytes(&dhcp_header));

        pos = end;
        end += 3;
        dhcp_buffer[pos] = 0x35;
        dhcp_buffer[pos + 1] = 0x01;
        dhcp_buffer[pos + 2] = if (msg == .Discover) 0x01 else 0x03;

        if (msg == .Request) {
            dhcp_buffer[pos + 3] = 50;
            dhcp_buffer[pos + 4] = 0x04;
            pos = pos + 5;
            end = pos + @sizeOf(u32);
            @memcpy(dhcp_buffer[pos..end], std.mem.asBytes(&requested_addr));
        }

        dhcp_buffer[end] = 0xff;

        switch (msg) {
            .Renew => s.send(dhcp_iface, server_addr, server_port, dhcp_buffer[0 .. end + 1]),
            .Discover, .Request, .Rebind => s.send_broadcast(dhcp_iface, server_port, dhcp_buffer[0 .. end + 1]),
        }

        state = switch (msg) {
            .Discover => .WaitingForOffer,
            .Request, .Renew, .Rebind => .WaitingForAck,
        };
    }
}
