const std = @import("std");
const types = @import("../types.zig");
const udp = @import("../core/udp.zig");
const ipv4 = @import("../core/ipv4.zig");
const time = @import("../time.zig");
const arp = @import("../core/arp.zig");

const logger = std.log.scoped(.ntp);

const server_port: u16 = 123;

const NTP_UNIX_EPOCH_OFFSET = 2_208_988_800;

const NtpHeader = extern struct {
    li_vn_mode: u8 align(1) = 0b00100011, // leep, version, mode
    stratum: u8 align(1) = 0,
    poll: u8 align(1) = 0,
    precision: i8 align(1) = 0,
    root_delay: u32 align(1) = 0,
    root_dispersion: u32 align(1) = 0,
    reference_id: u32 align(1) = 0,
    reference_timestamp: u64 align(1) = 0,
    origin_timestamp: u64 align(1) = 0, // rec
    receive_timestamp: u64 align(1) = 0, // rec
    transmit_timestamp: u64 align(1) = 0, // xmt
};

const NtpStatus = enum {
    WaitingForArp,
    UnSynchronized,
    FirstPass,
    Synchronized,
};

pub const NtpClient = struct {
    const Self = @This();

    iface: *types.Interface = undefined,
    socket: ?*udp.UDPSocket = null,
    ntp_offset: u64 = 0,
    server_addr: u32 = 0,
    state: NtpStatus = .UnSynchronized,

    pub fn init(self: *Self, iface: *types.Interface) error{PortInUse}!void {
        self.iface = iface;
        self.socket = udp.requestSocketFromPool();
        if (self.socket) |s| {
            try s.bind(server_port, ntpRecvCallback, self);
        }
    }

    pub fn status(self: *Self) NtpStatus {
        return self.state;
    }

    pub fn poll(self: *Self) void {
        switch (self.state) {
            .WaitingForArp => {
                if (arp.fetchArpEntry(self.iface, self.server_addr)) |_| {
                    self.state = .UnSynchronized;
                } else {
                    arp.arpDiscover(self.iface, self.server_addr);
                }
            },
            else => self.ntpSyncRequest(),
        }
    }

    pub fn ntpSyncRequest(self: *Self) void {
        const sock = self.socket orelse return;
        const frame = self.iface.requestFrame() orelse return;

        const now: u32 = time.millis();
        const seconds: u32 = time.millis() / 1000;
        const fraction: u32 = @intCast(((@as(u64, now % 1000) << 32) / 1000));

        const transmit_time: u64 = std.mem.nativeToBig(u64, ((@as(u64, seconds) << 32) | @as(u64, fraction)) + self.ntp_offset);

        const header: NtpHeader = .{
            .transmit_timestamp = transmit_time,
        };

        const pos: usize = types.TRANSPORT_HEADER_OFFSET + @sizeOf(udp.UDPHeader);
        const end: usize = pos + @sizeOf(NtpHeader);
        @memcpy(frame.buffer[pos..end], std.mem.asBytes(&header));

        frame.len = @sizeOf(NtpHeader);

        sock.send(self.iface, self.server_addr, server_port, frame);
    }

    fn recvCallback(self: *Self, iface: *types.Interface, sock: *udp.UDPSocket, addr: u32, port: u16, payload: []const u8) void {
        _ = sock;
        _ = addr;
        _ = port;
        _ = iface;

        const now: u32 = time.millis();
        const seconds: u32 = time.millis() / 1000;
        const fraction: u32 = @intCast(((@as(u64, now % 1000) << 32) / 1000));

        const hrx: u64 = (@as(u64, seconds) << 32) | @as(u64, fraction); // i.e. receive_time of client

        const header = std.mem.bytesAsValue(NtpHeader, payload[0..@sizeOf(NtpHeader)]);

        const srx: u64 = std.mem.bigToNative(u64, header.receive_timestamp);
        const stx: u64 = std.mem.bigToNative(u64, header.transmit_timestamp);
        const htx: u64 = std.mem.bigToNative(u64, header.origin_timestamp);

        printUnixTimestamp(htx);
        printNtpTimestamp(srx);
        printNtpTimestamp(stx);
        printUnixTimestamp(hrx);

        if (self.state == .UnSynchronized) {
            self.ntp_offset = stx;
        } else {
            const d1 = @as(i64, @bitCast(srx)) - @as(i64, @bitCast(htx));
            const d2 = @as(i64, @bitCast(hrx)) - @as(i64, @bitCast(stx));

            const offset = @divTrunc(d1 + d2, 2); // average the two offsets

            printOffset(offset);
            // printNtpTimestamp(@intCast(offset));
        }
    }
};

fn ntpRecvCallback(iface: *types.Interface, sock: *udp.UDPSocket, addr: u32, port: u16, payload: []const u8) void {
    if (sock.context) |ctx| {
        const client: *NtpClient = @ptrCast(@alignCast(ctx));
        client.recvCallback(iface, sock, addr, port, payload);
    }
}

pub fn printUnixTimestamp(utc_timestamp: u64) void {
    const utc_seconds: u64 = utc_timestamp >> 32;
    const milliseconds: u32 = @truncate(((utc_timestamp & 0xFFFFFFFF) * 1000) >> 32);

    const epoch_seconds: std.time.epoch.EpochSeconds =
        .{ .secs = @intCast(utc_seconds) };

    const day_seconds = epoch_seconds.getDaySeconds();
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    logger.debug(
        "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:03} UTC\n",
        .{
            year_day.year,
            @intFromEnum(month_day.month),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
            milliseconds,
        },
    );
}

pub fn printOffset(timestamp: i64) void {
    const seconds: i32 = @intCast(timestamp >> 32);
    const milliseconds: u32 = @truncate((@as(u64, @bitCast(timestamp & 0xFFFFFFFF)) * 1000) >> 32);

    logger.debug("{d}.{d}\n", .{
        seconds,
        milliseconds,
    });
}

pub fn printNtpTimestamp(ntp_timestamp: u64) void {
    const ntp_seconds: u32 = @intCast(ntp_timestamp >> 32);
    const fraction: u32 = @truncate(ntp_timestamp);

    const unix_seconds: u32 = ntp_seconds - NTP_UNIX_EPOCH_OFFSET;

    const unix_timestamp: u64 =
        (@as(u64, unix_seconds) << 32) |
        @as(u64, fraction);

    printUnixTimestamp(unix_timestamp);
}
