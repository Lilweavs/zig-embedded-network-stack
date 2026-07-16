const std = @import("std");
const types = @import("../types.zig");
const udp = @import("../core/udp.zig");
const ipv4 = @import("../core/ipv4.zig");
const time = @import("../time.zig");

const logger = std.log.scoped(.dhcp);

const server_port: u16 = 67;
const client_port: u16 = 68;
const max_retries: u32 = 10;

pub const DHCPState = enum {
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

pub const DHCPOptions = enum(u8) {
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

pub const DhcpMessageType = enum(u8) {
    Discover = 0x01,
    Offer = 0x02,
    Request = 0x03,
    Decline = 0x04,
    Ack = 0x05,
    Nack = 0x06,
    Release = 0x07,
    Inform = 0x08,
};

pub const MessageType = enum(u8) {
    Discover,
    Request,
    Renew,
    Rebind,
};

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

pub const DhcpClient = struct {
    const Self = @This();

    state: DHCPState = .Uninit,
    socket: ?*udp.UDPSocket = null,
    iface: *types.Interface = undefined,
    discover_time: u32 = 0,
    magic_number: u32 = 0,
    server_addr: u32 = 0,
    subnet_mask: u32 = 0,
    broadcast_address: u32 = 0,
    requested_addr: u32 = 0,
    lease_time: u32 = 0,
    renewal_time: u32 = 0,
    rebind_time: u32 = 0,
    backoff_time: u32 = 1000, // in milliseconds
    num_retries: u32 = 0,

    pub fn init(self: *Self, iface: *types.Interface) error{PortInUse}!void {
        self.iface = iface;
        self.socket = udp.requestSocketFromPool();
        if (self.socket) |s| {
            try s.bind(client_port, dhcpRecvCallback, self);
            self.state = .Discover;

            var prng = std.Random.DefaultPrng.init(1);
            const rand = prng.random();
            self.magic_number = rand.int(u32);
        }
    }

    pub fn poll(self: *Self) DHCPState {
        switch (self.state) {
            .Disable => {},
            .Uninit => {},
            .Discover => {
                logger.debug("DHCP: Discover\n", .{});
                self.dhcpSend(.Discover);
            },
            .WaitingForOffer => {
                const now = time.millis();
                if (now -| self.discover_time >= self.backoff_time) {
                    self.dhcpSend(.Discover);
                    self.backoff_time = @min(self.backoff_time * 2, 60 * std.time.ms_per_s);
                    logger.debug("DHCP: Discover retry: {d}\n", .{self.backoff_time / 1000});
                    self.num_retries += 1;
                    if (self.num_retries >= max_retries) {
                        logger.debug("DHCP: Discover failed\n", .{});
                        self.state = .Disable;
                        self.backoff_time = 1000;
                    }
                }
            },
            .WaitingForAck => {},
            .Complete => {
                const now_s = time.millis() / 1000;
                if (now_s >= self.rebind_time) {
                    logger.debug("DHCP: Rebinding\n", .{});
                    self.dhcpSend(.Rebind);
                } else if (now_s >= self.renewal_time) {
                    logger.debug("DHCP: Renewing\n", .{});
                    self.dhcpSend(.Renew);
                }
            },
            .Renewal => {},
            .Rebind => {},
        }
        return self.state;
    }

    pub fn status(self: *Self) DHCPState {
        return self.state;
    }

    fn dhcpSend(self: *Self, msg: MessageType) void {
        if (self.socket) |s| {
            if (self.iface.requestFrame()) |frame| {
                const now = time.millis();
                var dhcp_header: DHCPHeader = .{
                    .op = 0x01,
                    .xid = self.magic_number,
                    .ciaddr = switch (msg) {
                        .Renew, .Rebind => @bitCast(self.iface.ip_addr),
                        .Discover, .Request => .{ 0, 0, 0, 0 },
                    },
                    .secs = if (msg == .Request) @intCast((now -| self.discover_time) / 1000) else 0,
                };

                if (msg == .Discover) self.discover_time = now;

                @memcpy(dhcp_header.chaddr[0..6], &self.iface.mac_addr);

                const dhcp_start = types.TRANSPORT_HEADER_OFFSET + @sizeOf(udp.UDPHeader);
                var pos: usize = dhcp_start;
                var end: usize = pos + @sizeOf(DHCPHeader);
                @memcpy(frame.buffer[pos..end], std.mem.asBytes(&dhcp_header));

                pos = end;
                end += 3;
                frame.buffer[pos] = @intFromEnum(DHCPOptions.DHCPMessageType);
                frame.buffer[pos + 1] = 0x01;
                frame.buffer[pos + 2] = @intFromEnum(if (msg == .Discover) DhcpMessageType.Discover else DhcpMessageType.Request);

                if (msg == .Request) {
                    frame.buffer[pos + 3] = @intFromEnum(DHCPOptions.RequestIdAddress);
                    frame.buffer[pos + 4] = 0x04;
                    pos = pos + 5;
                    end = pos + @sizeOf(u32);
                    @memcpy(frame.buffer[pos..end], std.mem.asBytes(&self.requested_addr));
                }

                frame.buffer[end] = @intFromEnum(DHCPOptions.End);

                frame.len = @sizeOf(udp.UDPHeader) + (end + 1 - dhcp_start);

                switch (msg) {
                    .Renew => s.send(self.iface, self.server_addr, server_port, frame),
                    .Discover, .Request, .Rebind => s.send_broadcast(self.iface, server_port, frame),
                }

                self.state = switch (msg) {
                    .Discover => .WaitingForOffer,
                    .Request, .Renew, .Rebind => .WaitingForAck,
                };
            }
        }
    }

    fn recvCallback(self: *Self, iface: *types.Interface, sock: *udp.UDPSocket, addr: u32, port: u16, payload: []const u8) void {
        _ = sock;
        _ = addr;
        _ = port;

        logger.debug("DHCP: Payload Received\n", .{});
        if (payload.len < @sizeOf(DHCPHeader)) return;

        const dhcp_data: DHCPHeader = std.mem.bytesToValue(DHCPHeader, payload[0..@sizeOf(DHCPHeader)]);

        logger.debug("DHCP: xid 0x{X} -> 0x{X}\n", .{ dhcp_data.xid, self.magic_number });
        if (dhcp_data.xid != self.magic_number) return;

        if (self.state == .WaitingForOffer and dhcp_data.op == 2) {
            logger.debug("DHCP: Received Offer\n", .{});
            self.requested_addr = std.mem.bytesToValue(u32, &dhcp_data.yiaddr);

            var iter = OptionIterator{ .buffer = payload[@sizeOf(DHCPHeader)..] };

            while (iter.next()) |option| {
                if (std.enums.tagName(DHCPOptions, option.code)) |name| {
                    logger.debug("DHCP Option: {s}\n", .{name});
                } else {
                    logger.debug("DHCP Option: {d}\n", .{@intFromEnum(option.code)});
                }
                switch (option.code) {
                    .SubnetMask => {
                        self.subnet_mask = std.mem.bytesToValue(u32, option.payload);
                    },
                    .BroadcastAddress => {
                        self.broadcast_address = std.mem.bytesToValue(u32, option.payload);
                    },
                    .IPAddressLeaseTime => {
                        self.lease_time = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, option.payload));
                        const now_s = time.millis() / 1000;
                        self.renewal_time = now_s + self.lease_time / 2;
                        self.rebind_time = now_s + self.lease_time * 7 / 8;
                        logger.debug("IP lease time: {d}\n", .{self.lease_time});
                    },
                    .ServerIdentifier => {
                        self.server_addr = std.mem.bytesToValue(u32, option.payload);
                    },
                    else => {},
                }
            }

            self.dhcpSend(.Request);
        } else if (self.state == .WaitingForAck and dhcp_data.op == 2) {
            logger.debug("DHCP: Received Ack\n", .{});
            iface.ip_addr = self.requested_addr;

            var iter = OptionIterator{ .buffer = payload[@sizeOf(DHCPHeader)..] };
            while (iter.next()) |option| {
                switch (option.code) {
                    .IPAddressLeaseTime => {
                        self.lease_time = std.mem.bigToNative(u32, std.mem.bytesToValue(u32, option.payload));
                        const now_s = time.millis() / 1000;
                        self.renewal_time = now_s + self.lease_time / 2;
                        self.rebind_time = now_s + self.lease_time * 7 / 8;
                    },
                    else => {},
                }
            }

            self.state = .Complete;
            logger.debug("IpAddr: {f}\n", .{ipv4.fmtIpAddr(self.requested_addr)});
        }
    }
};

fn dhcpRecvCallback(iface: *types.Interface, sock: *udp.UDPSocket, addr: u32, port: u16, payload: []const u8) void {
    if (sock.context) |ctx| {
        const client: *DhcpClient = @ptrCast(@alignCast(ctx));
        client.recvCallback(iface, sock, addr, port, payload);
    }
}
