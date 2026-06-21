const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax/tcp.zig");
const ipv4 = @import("../core/ipv4.zig");

pub const TcpHeader = syntax.TcpHeader;
pub const TcpFlags = syntax.TcpFlags;

fn seqLessThan(a: u32, b: u32) bool {
    return (@as(i32, @intCast(a)) - @as(i32, @intCast(b))) < 0;
}

fn seqLessThanEqual(a: u32, b: u32) bool {
    return (@as(i32, @intCast(a)) - @as(i32, @intCast(b))) <= 0;
}

fn seqGreaterThan(a: u32, b: u32) bool {
    return (@as(i32, @intCast(a)) - @as(i32, @intCast(b))) > 0;
}

fn seqGreaterThanEqual(a: u32, b: u32) bool {
    return (@as(i32, @intCast(a)) - @as(i32, @intCast(b))) >= 0;
}

const TcpBuffer = struct {
    data: [4096]u8 = undefined,
    head: usize = 0,
    tail: usize = 0,
    size: usize = 0,

    const Self = @This();
    const capacity: usize = 4096;

    pub fn store(self: *Self, data: []const u8) usize {
        if (self.availableSpace() < data.len) return 0;
        const bytes_to_copy = data.len;

        const free_chunk: usize = capacity - self.tail;

        if (bytes_to_copy <= free_chunk) {
            @memcpy(@as([*]u8, @ptrCast(&self.data[self.tail])), data);
        } else {
            @memcpy(@as([*]u8, @ptrCast(&self.data[self.tail])), data[0..free_chunk]);
            @memcpy(@as([*]u8, @ptrCast(&self.data[0])), data[free_chunk..]);
        }
        self.tail = (self.tail + bytes_to_copy) % capacity;
        self.size += bytes_to_copy;
        return bytes_to_copy;
    }

    pub fn copy(self: *Self, buffer: []u8) usize {
        const bytes_to_read: usize = @min(self.size, buffer.len);
        const avail_chunk: usize = capacity - self.head;

        if (bytes_to_read <= avail_chunk) {
            @memcpy(buffer[0..bytes_to_read], @as([*]u8, @ptrCast(&self.data[self.head])));
        } else {
            @memcpy(buffer[0..avail_chunk], @as([*]u8, @ptrCast(&self.data[self.head])));
            @memcpy(buffer[avail_chunk..bytes_to_read], @as([*]u8, @ptrCast(&self.data[0])));
        }
        self.head = (self.head + bytes_to_read) % capacity;
        self.size -= bytes_to_read;
        return bytes_to_read;
    }

    pub fn remove(self: *Self, amount: u32) void {
        self.size -|= amount;
        if (self.size == 0) {
            self.head = self.tail;
        } else {
            self.head = (self.head + amount) % capacity;
        }
    }

    fn availableSpace(self: Self) usize {
        return capacity - self.size;
    }

    fn availableBytes(self: Self) usize {
        return self.size;
    }
};

pub var server = TcpServer{};

pub fn processTCPFrame(iface: *types.Interface, saddr: u32, buffer: []u8) void {
    const header: TcpHeader = std.mem.bytesToValue(TcpHeader, buffer[0..@sizeOf(TcpHeader)]);

    const dport = std.mem.bigToNative(u16, header.dport);

    if (server.port == dport) {
        if (header.flags.syn == 1 and header.flags.ack == 0) {
            if (allocControlBlock()) |*tcb| {
                tcb.*.iface = iface;
                tcb.*.port = server.port;
                tcb.*.sport = std.mem.bigToNative(u16, header.sport);
                tcb.*.daddr = saddr;
                tcb.*.state = .LISTEN;
            }
        }

        for (&control_blocks) |*tcb| {
            if (tcb.state == .CLOSED) return else tcb.receive(std.mem.bigToNative(u16, header.sport), saddr, buffer);
        }
    }
}

fn allocControlBlock() ?*TcpControlBlock {
    for (&control_blocks) |*tcb| {
        if (tcb.state == .CLOSED) {
            return tcb;
        }
    }
    return null;
}

pub const State = enum {
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED,
};

pub const TcpServer = struct {
    port: u16 = 0,
    active: bool = false,

    const Self = @This();

    pub fn bind(self: *Self, port: u16) void {
        self.port = port;
    }

    pub fn listen(self: *Self) void {
        _ = self;
    }
};

pub var control_blocks = [_]TcpControlBlock{TcpControlBlock{}} ** 4;

pub const TcpControlBlock = struct {
    iface: ?*types.Interface = null,
    state: State = .CLOSED,
    seq_number: u32 = 0,
    ack_number: u32 = 0,
    port: u16 = 0,
    sport: u16 = 0,
    daddr: u32 = 0,
    active: bool = false,
    recv_callback: ?TcpCallbackFn = null,
    rx_buffer: TcpBuffer = TcpBuffer{},
    tx_buffer: TcpBuffer = TcpBuffer{},

    snd_una: u32 = 0,
    snd_nxt: u32 = 0,
    snd_wnd: u16 = 0,
    snd_up: u32 = 0,
    snd_wl1: u32 = 0,
    snd_wl2: u32 = 0,
    iss: u32 = 0,

    rcv_nxt: u32 = 0,
    rcv_wnd: u16 = 4096,
    rcv_up: u32 = 0,
    irs: u32 = 0,

    mss: u16 = 576 - 40,

    const Self = @This();

    pub fn status(self: *Self) State {
        return self.state;
    }

    pub fn open() void {}

    pub fn connect(self: *Self, iface: *types.Interface) void {
        self.iface = iface;
        self.iss = generateInitialSequenceNumber();
        self.snd_nxt = self.iss;
        self.snd_una = self.iss;
        self.sendInternal(.{ .syn = 1 }, &.{});
        self.state = .SYN_SENT;
        self.snd_nxt +%= 1;
    }

    pub fn close(self: *Self) void {
        switch (self.state) {
            .CLOSE_WAIT => {
                self.sendInternal(.{ .fin = 1, .ack = 1 }, &.{});
                self.state = .LAST_ACK;
            },
            .ESTABLISHED => {},
            else => {},
        }
    }

    pub fn recv(self: *Self, buffer: []u8) usize {
        if (self.rx_buffer.availableSpace() == 0) return 0;
        return self.rx_buffer.copy(buffer);
    }

    pub fn send(self: *Self, payload: []const u8) void {
        const iface = self.iface.?;
        _ = self.tx_buffer.store(payload);

        if (iface.requestSlot()) |slot| {
            var header = TcpHeader{
                .sport = std.mem.nativeToBig(u16, self.port),
                .dport = std.mem.nativeToBig(u16, self.sport),
                .seq_number = std.mem.nativeToBig(u32, self.snd_nxt),
                .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
                .data_offset = 0x50,
                .flags = .{ .ack = 1, .psh = 1 },
                .window = std.mem.nativeToBig(u16, self.rcv_wnd),
            };

            const upper_start: usize = types.TRANSPORT_HEADER_OFFSET;
            var pos: usize = upper_start;
            var end: usize = pos + @sizeOf(TcpHeader);
            @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

            pos = end;
            end = pos + payload.len;
            @memcpy(slot.header[pos..end], payload);

            slot.data = slot.header[upper_start..end];
            slot.len = upper_start + slot.data.len;

            const checksum = ipv4.calcPseudoChecksum(slot.data, .TCP, iface.ip_addr, self.daddr);
            @memcpy(slot.header[upper_start + @offsetOf(TcpHeader, "checksum")..][0..2], std.mem.asBytes(&checksum));

            ipv4.send(iface, self.daddr, slot, .TCP);
            self.snd_nxt +%= payload.len;
        }
    }

    pub fn available(self: Self) usize {
        return self.rx_buffer.size;
    }

    pub fn receive(self: *Self, sport: u16, saddr: u32, payload: []const u8) void {
        _ = sport;
        _ = saddr;

        const header: TcpHeader = std.mem.bytesToValue(TcpHeader, payload[0..@sizeOf(TcpHeader)]);

        const end_of_header: usize = ((header.data_offset >> 4) * 4);
        const segment = payload[end_of_header..];
        const seg_ack = std.mem.nativeToBig(u32, header.ack_number);
        const seg_seq = std.mem.nativeToBig(u32, header.seq_number);
        const seg_wnd = std.mem.nativeToBig(u16, header.window);

        if (header.flags.rst == 1) {
            switch (self.state) {
                .SYN_RECEIVED => {
                    self.state = .LISTEN;
                    return;
                },
                .ESTABLISHED, .FIN_WAIT_1, .FIN_WAIT_2, .CLOSE_WAIT => {},
                else => {
                    self.state = .CLOSED;
                    return;
                },
            }
        }

        switch (self.state) {
            .CLOSED => unreachable,
            .LISTEN => {
                if (header.flags.rst == 1) return;
                if (header.flags.ack == 1) return;
                if (header.flags.syn == 1) {
                    self.rcv_nxt = seg_seq +% 1;
                    self.irs = seg_seq;
                    self.sendSynAck();
                    self.snd_una = std.mem.bigToNative(u32, header.seq_number);
                    self.snd_nxt = self.snd_una +% 1;
                    self.state = .SYN_RECEIVED;
                }
            },
            .SYN_SENT => {
                if (header.flags.ack == 1) {
                    if (seqLessThanEqual(seg_ack, self.iss) or seqGreaterThan(seg_ack, self.snd_nxt)) {
                        if (header.flags.rst == 1) return;
                        self.sendInternal(.{ .rst = 1 }, &.{});
                        return;
                    }
                }
                if (header.flags.syn == 1) {
                    self.rcv_nxt = seg_seq +% 1;
                    self.irs = seg_seq;
                    self.snd_una = seg_seq;
                    if (seqGreaterThan(self.snd_una, self.iss)) {
                        self.state = .ESTABLISHED;
                        self.sendInternal(.{ .ack = 1 }, &.{});
                    }
                }
            },
            .SYN_RECEIVED => {
                if (header.flags.rst == 1) { self.state = .LISTEN; return; }
                if (header.flags.syn == 1) { self.state = .LISTEN; return; }
                if (header.flags.ack == 1) {
                    if (seqLessThan(self.snd_una, seg_ack) and seqLessThanEqual(seg_ack, self.snd_nxt)) {
                        self.snd_wnd = seg_wnd;
                        self.snd_wl1 = seg_seq;
                        self.snd_wl2 = seg_ack;
                        self.state = .ESTABLISHED;
                    }
                }
            },
            .ESTABLISHED => {
                if (header.flags.rst == 1) { self.state = .CLOSED; return; }
                if (header.flags.syn == 1) {}
                if (header.flags.ack == 1) {
                    if (seqLessThan(self.snd_una, seg_ack) and seqLessThanEqual(seg_ack, self.snd_nxt)) {
                        self.snd_una = seg_ack;
                        return;
                    }
                } else return;
                if (header.flags.urg == 1) {}
                if (segment.len > 0) {
                    const num_acked = self.rx_buffer.store(segment);
                    self.rcv_nxt +%= @as(u32, @intCast(num_acked));
                    self.rcv_wnd -= @intCast(num_acked);
                }
                if (header.flags.fin == 1) {
                    self.rcv_nxt +%= 1;
                    self.state = .CLOSE_WAIT;
                }
                self.sendAck();
            },
            .CLOSE_WAIT => { if (header.flags.rst == 1) {} },
            .FIN_WAIT_1 => {
                if (header.flags.rst == 1) self.state = .CLOSED;
                if (header.flags.ack == 1) {
                    self.sendInternal(.{ .fin = 1, .ack = 1 }, &.{});
                    self.state = .FIN_WAIT_2;
                }
            },
            .FIN_WAIT_2 => {},
            .LAST_ACK => {
                if (header.flags.rst == 1) { self.state = .CLOSED; return; }
                if (header.flags.ack == 1) { self.state = .CLOSED; return; }
            },
            else => {},
        }
    }

    fn checkWindowUpdate(self: *Self) void {
        if (self.rx_buffer.availableSpace() -| self.rcv_wnd >= @min(self.rx_buffer.data.len, self.mss)) {
            const num_mss_segments: u16 = @intCast(self.rx_buffer.availableSpace() / self.mss);
            self.rcv_wnd += self.mss * num_mss_segments;
        }
    }

    fn sendInternal(self: *Self, flags: TcpFlags, payload: []u8) void {
        const iface = self.iface.?;
        const slot = iface.requestSlot() orelse return;

        var header = TcpHeader{
            .sport = std.mem.nativeToBig(u16, self.port),
            .dport = std.mem.nativeToBig(u16, self.sport),
            .seq_number = std.mem.nativeToBig(u32, self.snd_nxt),
            .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
            .data_offset = 0x50,
            .flags = flags,
            .window = std.mem.nativeToBig(u16, self.rcv_wnd),
        };

        const upper_start: usize = types.TRANSPORT_HEADER_OFFSET;
        var pos: usize = upper_start;
        var end: usize = pos + @sizeOf(TcpHeader);
        @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

        pos = end;
        end = pos + payload.len;

        slot.data = slot.header[upper_start..end];
        slot.len = upper_start + slot.data.len;

        const checksum = ipv4.calcPseudoChecksum(slot.data, .TCP, iface.ip_addr, self.daddr);
        @memcpy(slot.header[upper_start + @offsetOf(TcpHeader, "checksum")..][0..2], std.mem.asBytes(&checksum));

        ipv4.send(iface, self.daddr, slot, .TCP);
    }

    pub fn sendAck(self: *Self) void {
        self.checkWindowUpdate();
        self.sendInternal(.{ .ack = 1 }, &.{});
    }

    pub fn addMtuOption(buffer: []u8, mss: u16) void {
        buffer[0] = 0x02;
        buffer[1] = 0x04;
        @memcpy(buffer[2..4], std.mem.asBytes(&std.mem.nativeToBig(u16, mss)));
    }

    pub fn sendSynAck(self: *Self) void {
        const iface = self.iface.?;
        self.checkWindowUpdate();
        if (iface.requestSlot()) |slot| {
            var header = TcpHeader{
                .sport = std.mem.nativeToBig(u16, self.port),
                .dport = std.mem.nativeToBig(u16, self.sport),
                .seq_number = std.mem.nativeToBig(u32, self.irs),
                .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
                .data_offset = 0x60,
                .flags = .{ .syn = 1, .ack = 1 },
                .window = std.mem.nativeToBig(u16, self.rcv_wnd),
            };

            const upper_start: usize = types.TRANSPORT_HEADER_OFFSET;
            const pos: usize = upper_start;
            var end: usize = pos + @sizeOf(TcpHeader);
            @memcpy(slot.header[pos..end], std.mem.asBytes(&header));

            addMtuOption(slot.header[end..], self.mss);
            end += 4;

            slot.data = slot.header[upper_start..end];
            slot.len = upper_start + slot.data.len;

            ipv4.send(iface, self.daddr, slot, .TCP);
        }
    }
};

const tcp_pool_size: usize = 4;
var tcp_pool: [tcp_pool_size]TcpControlBlock = .{TcpControlBlock{}} ** tcp_pool_size;

const TcpCallbackFn = *const fn (socket: *TcpControlBlock, addr: u32, port: u16, payload: []const u8) void;

pub fn requestSocketFromPool() ?*TcpControlBlock {
    for (0..tcp_pool.len) |i| {
        if (tcp_pool[i].active == false) {
            tcp_pool[i].active = true;
            return &tcp_pool[i];
        }
    }
    return null;
}

pub fn returnSocketToPool(socket: *TcpControlBlock) void {
    for (0..tcp_pool.len) |i| {
        if (&tcp_pool[i] == socket) {}
    }
    socket.active = false;
}

pub fn generateInitialSequenceNumber() u32 {
    return 100;
}

pub fn generateInitialAcknowledgeNumber() u32 {
    return 100;
}
