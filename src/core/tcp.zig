const std = @import("std");
const types = @import("../types.zig");
const syntax = @import("../syntax.zig");
const ipv4 = @import("../core/ipv4.zig");

pub const TcpHeader = syntax.tcp.TcpHeader;
pub const TcpFlags = syntax.tcp.TcpFlags;

const logger = std.log.scoped(.tcp);

fn seqLessThan(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

fn seqLessThanEqual(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) <= 0;
}

fn seqGreaterThan(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

fn seqGreaterThanEqual(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) >= 0;
}

const TcpBuffer = struct {
    data: [4096]u8 = undefined,
    head: usize = 0,
    tail: usize = 0,
    size: usize = 0,

    const Self = @This();
    const capacity: usize = 4096;

    pub fn store(self: *Self, data: []const u8) usize {
        const bytes_to_copy = @min(data.len, self.availableSpace());
        if (bytes_to_copy == 0) return 0;

        const free_chunk = capacity - self.tail;
        if (bytes_to_copy <= free_chunk) {
            @memcpy(self.data[self.tail..][0..bytes_to_copy], data[0..bytes_to_copy]);
        } else {
            @memcpy(self.data[self.tail..], data[0..free_chunk]);
            @memcpy(self.data[0 .. bytes_to_copy - free_chunk], data[free_chunk..bytes_to_copy]);
        }
        self.tail = (self.tail + bytes_to_copy) % capacity;
        self.size += bytes_to_copy;
        return bytes_to_copy;
    }

    pub fn peek(self: *Self, offset: usize, buf: []u8) usize {
        const bytes_to_read = @min(self.size -| offset, buf.len);
        if (bytes_to_read == 0) return 0;

        const start = (self.head + offset) % capacity;
        const avail_chunk = capacity - start;
        if (bytes_to_read <= avail_chunk) {
            @memcpy(buf[0..bytes_to_read], self.data[start..][0..bytes_to_read]);
        } else {
            @memcpy(buf[0..avail_chunk], self.data[start..][0..avail_chunk]);
            @memcpy(buf[avail_chunk..bytes_to_read], self.data[0 .. bytes_to_read - avail_chunk]);
        }
        return bytes_to_read;
    }

    pub fn copy(self: *Self, buffer: []u8) usize {
        const bytes_to_read = self.peek(0, buffer);
        self.consume(bytes_to_read);
        return bytes_to_read;
    }

    pub fn consume(self: *Self, amount: usize) void {
        const bytes_to_consume = @min(amount, self.size);
        self.size -= bytes_to_consume;
        if (self.size == 0) {
            self.head = self.tail;
        } else {
            self.head = (self.head + bytes_to_consume) % capacity;
        }
    }

    fn availableSpace(self: Self) usize {
        return capacity - self.size;
    }

    fn availableBytes(self: Self) usize {
        return self.size;
    }
};

pub const Event = enum {
    connected,
    data,
    closed,
    tx_available,
};

pub const EventFn = *const fn (socket: *TcpSocket, event: Event, data: []const u8) void;

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

const TcpOptions = enum(u8) {
    End = 0,
    Nop = 1,
    MSS = 2,
    _,
};

const OptionPayload = struct {
    code: TcpOptions,
    payload: []const u8,
};

const OptionIterator = struct {
    const Self = @This();
    buffer: []const u8,
    index: usize = 0,

    pub fn next(self: *Self) ?OptionPayload {
        const code = @as(TcpOptions, @enumFromInt(self.buffer[self.index]));

        while (self.index > self.buffer.len) {
            if (code == .End) break;
            if (code == .Nop) {
                self.index += 1;
            }
            const length = self.buffer[self.index + 1];
            self.index += 2 + length;

            return .{ .code = code, .payload = self.buffer[self.index - length .. self.index] };
        }
        return null;
    }
};

const tcp_pool_size: usize = 4;

pub const TcpSocket = struct {
    iface: ?*types.Interface = null,
    server: ?*TcpServer = null,
    state: State = .CLOSED,
    port: u16 = 0,
    sport: u16 = 0,
    daddr: u32 = 0,
    callback: ?EventFn = null,
    cb_context: ?*anyopaque = null,
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

    mss: u16 = 1460,
    peer_mss: u16 = 1460,
    wnd_update_pending: bool = false,
    tx_backlogged: bool = false,

    const Self = @This();

    inline fn bytesNotAcked(self: Self) usize {
        return self.snd_nxt -% self.snd_una;
    }

    pub fn status(self: *Self) State {
        return self.state;
    }

    pub fn close(self: *Self) void {
        switch (self.state) {
            .ESTABLISHED => {
                self.sendInternal(.{ .fin = 1, .ack = 1 }, &.{});
                self.state = .FIN_WAIT_1;
            },
            .CLOSE_WAIT => {
                self.sendInternal(.{ .fin = 1, .ack = 1 }, &.{});
                self.state = .LAST_ACK;
            },
            else => {},
        }
    }

    pub fn recv(self: *Self, buffer: []u8) usize {
        if (self.rx_buffer.availableBytes() == 0) return 0;
        const bytes_read = self.rx_buffer.copy(buffer);
        self.rcv_wnd += @intCast(bytes_read);
        return bytes_read;
    }

    pub fn send(self: *Self, data: []const u8) usize {
        if (!(self.state == .ESTABLISHED or self.state == .CLOSE_WAIT)) return 0;

        const stored = self.tx_buffer.store(data);
        if (stored < data.len) self.tx_backlogged = true;
        if (stored > 0) {
            var offset: usize = 0;
            while (offset < stored) {
                const chunk_len = @min(stored - offset, @as(usize, self.peer_mss));
                self.sendSegment(data[offset..][0..chunk_len]);
                offset += chunk_len;
            }
        }
        return stored;
    }

    pub fn flush(self: *Self) void {
        const iface = self.iface orelse return;
        std.debug.assert(self.tx_buffer.availableBytes() >= self.bytesNotAcked());
        const unsent = self.tx_buffer.availableBytes() - self.bytesNotAcked();
        if (unsent == 0) return;

        const frame = iface.requestFrame() orelse return;
        const to_send = @min(unsent, @as(usize, self.peer_mss));
        const sidx = types.TRANSPORT_HEADER_OFFSET + @sizeOf(TcpHeader);
        _ = self.tx_buffer.peek(self.bytesNotAcked(), frame.buffer[sidx..][0..to_send]);
        self.sendFrame(iface, frame, to_send);
    }

    fn sendSegment(self: *Self, data: []const u8) void {
        const iface = self.iface orelse return;
        const frame = iface.requestFrame() orelse return;

        const sidx = types.TRANSPORT_HEADER_OFFSET + @sizeOf(TcpHeader);
        @memcpy(frame.buffer[sidx..][0..data.len], data);
        self.sendFrame(iface, frame, data.len);
    }

    fn sendFrame(self: *Self, iface: *types.Interface, frame: *types.Frame, data_len: usize) void {
        var header = TcpHeader{
            .sport = std.mem.nativeToBig(u16, self.port),
            .dport = std.mem.nativeToBig(u16, self.sport),
            .seq_number = std.mem.nativeToBig(u32, self.snd_nxt),
            .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
            .data_offset = 0x50,
            .flags = .{ .ack = 1, .psh = 1 },
            .window = std.mem.nativeToBig(u16, self.rcv_wnd),
        };

        const sidx = types.TRANSPORT_HEADER_OFFSET;
        const pos = sidx + @sizeOf(TcpHeader);
        const end = pos + data_len;

        @memcpy(frame.buffer[sidx..pos], std.mem.asBytes(&header));
        frame.len = end - sidx;

        const checksum = ipv4.calcPseudoChecksum(frame.buffer[sidx..end], .TCP, iface.ip_addr, self.daddr);
        @memcpy(frame.buffer[sidx + @offsetOf(TcpHeader, "checksum") ..][0..2], std.mem.asBytes(&checksum));

        ipv4.send(iface, self.daddr, frame, .TCP);
        self.snd_nxt +%= data_len;
        self.wnd_update_pending = false;
    }

    pub fn available(self: Self) usize {
        return self.rx_buffer.size;
    }

    fn emitEvent(self: *Self, event: Event, data: []const u8) void {
        if (self.callback) |cb| {
            cb(self, event, data);
        }
    }

    pub fn receive(self: *Self, payload: []const u8) void {
        const header: TcpHeader = std.mem.bytesToValue(TcpHeader, payload[0..@sizeOf(TcpHeader)]);

        const end_of_header: usize = ((header.data_offset >> 4) * 4);
        const segment = payload[end_of_header..];
        const seg_ack = std.mem.nativeToBig(u32, header.ack_number);
        const seg_seq = std.mem.nativeToBig(u32, header.seq_number);
        const seg_wnd = std.mem.nativeToBig(u16, header.window);

        if (header.flags.rst == 1) {
            switch (self.state) {
                .SYN_RECEIVED, .ESTABLISHED, .FIN_WAIT_1, .FIN_WAIT_2, .CLOSE_WAIT => {
                    self.emitEvent(.closed, &.{});
                    self.state = .CLOSED;
                    return;
                },
                else => {
                    self.state = .CLOSED;
                    return;
                },
            }
        }

        switch (self.state) {
            .CLOSED => unreachable,
            .LISTEN => {},
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
                        self.emitEvent(.connected, &.{});
                    }
                }
            },
            .SYN_RECEIVED => {
                if (header.flags.rst == 1) {
                    self.emitEvent(.closed, &.{});
                    self.state = .CLOSED;
                    return;
                }
                if (header.flags.syn == 1) {
                    self.emitEvent(.closed, &.{});
                    self.state = .CLOSED;
                    return;
                }
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
                if (header.flags.rst == 1) {
                    self.emitEvent(.closed, &.{});
                    self.state = .CLOSED;
                    return;
                }
                if (header.flags.syn == 1) {
                    self.sendInternal(.{ .rst = 1 }, &.{});
                    self.emitEvent(.closed, &.{});
                    self.state = .CLOSED;
                    return;
                }
                if (header.flags.ack == 1) {
                    if (seqLessThan(self.snd_una, seg_ack) and seqLessThanEqual(seg_ack, self.snd_nxt)) {
                        const bytes_acked = seg_ack -% self.snd_una;
                        self.tx_buffer.consume(bytes_acked);
                        self.snd_una = seg_ack;
                        if (self.tx_backlogged and self.tx_buffer.availableSpace() >= self.peer_mss) {
                            self.tx_backlogged = false;
                            self.emitEvent(.tx_available, &.{});
                        }
                    }
                }
                if (header.flags.urg == 1) {}
                if (segment.len > 0) {
                    if (seg_seq == self.rcv_nxt) {
                        logger.debug("TCP: bytes received {d}\n", .{segment.len});
                        const num_acked = self.rx_buffer.store(segment);
                        self.rcv_nxt +%= @as(u32, @intCast(num_acked));
                        self.rcv_wnd -= @intCast(num_acked);
                        self.wnd_update_pending = true;
                        self.emitEvent(.data, segment);
                    } else {
                        logger.debug("TCP: dropping segment seq={d} expected={d}\n", .{ seg_seq, self.rcv_nxt });
                        self.wnd_update_pending = true;
                    }
                }
                if (segment.len == 0 and seqLessThan(seg_seq, self.rcv_nxt)) {
                    self.sendAck();
                }
                if (header.flags.fin == 1) {
                    self.rcv_nxt +%= 1;
                    self.state = .CLOSE_WAIT;
                    self.emitEvent(.closed, &.{});
                }
                if (self.wnd_update_pending) {
                    self.sendAck();
                }
            },
            .CLOSE_WAIT => {
                if (header.flags.ack == 1) {
                    if (seqLessThan(self.snd_una, seg_ack) and seqLessThanEqual(seg_ack, self.snd_nxt)) {
                        const bytes_acked = seg_ack -% self.snd_una;
                        self.tx_buffer.consume(bytes_acked);
                        self.snd_una = seg_ack;
                        if (self.tx_backlogged and self.tx_buffer.availableSpace() >= self.peer_mss) {
                            self.tx_backlogged = false;
                            self.emitEvent(.tx_available, &.{});
                        }
                    }
                }
                if (segment.len > 0) {
                    if (seg_seq == self.rcv_nxt) {
                        const num_acked = self.rx_buffer.store(segment);
                        self.rcv_nxt +%= @as(u32, @intCast(num_acked));
                        self.rcv_wnd -= @intCast(num_acked);
                        self.wnd_update_pending = true;
                    }
                }
                if (segment.len == 0 and seqLessThan(seg_seq, self.rcv_nxt)) {
                    self.sendAck();
                }
                if (self.wnd_update_pending) {
                    self.sendAck();
                }
            },
            .FIN_WAIT_1 => {
                if (header.flags.rst == 1) self.state = .CLOSED;
                if (header.flags.ack == 1) {
                    self.state = .FIN_WAIT_2;
                }
            },
            .FIN_WAIT_2 => {
                if (header.flags.fin == 1) {
                    self.rcv_nxt +%= 1;
                    self.sendAck();
                    self.emitEvent(.closed, &.{});
                    self.state = .CLOSED;
                }
            },
            .LAST_ACK => {
                if (header.flags.rst == 1) {
                    self.state = .CLOSED;
                    return;
                }
                if (header.flags.ack == 1) {
                    self.state = .CLOSED;
                    return;
                }
            },
            else => {},
        }
    }

    fn sendInternal(self: *Self, flags: TcpFlags, payload: []u8) void {
        const iface = self.iface.?;
        const frame = iface.requestFrame() orelse return;

        var header = TcpHeader{
            .sport = std.mem.nativeToBig(u16, self.port),
            .dport = std.mem.nativeToBig(u16, self.sport),
            .seq_number = std.mem.nativeToBig(u32, self.snd_nxt),
            .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
            .data_offset = 0x50,
            .flags = flags,
            .window = std.mem.nativeToBig(u16, self.rcv_wnd),
        };

        const sidx: usize = types.TRANSPORT_HEADER_OFFSET;
        var pos: usize = sidx;
        var end: usize = pos + @sizeOf(TcpHeader);
        @memcpy(frame.buffer[pos..end], std.mem.asBytes(&header));

        pos = end;
        end = pos + payload.len;

        frame.len = end - sidx;

        const checksum = ipv4.calcPseudoChecksum(frame.buffer[sidx..end], .TCP, iface.ip_addr, self.daddr);
        @memcpy(frame.buffer[sidx + @offsetOf(TcpHeader, "checksum") ..][0..2], std.mem.asBytes(&checksum));

        ipv4.send(iface, self.daddr, frame, .TCP);

        if (flags.fin == 1 or flags.syn == 1) {
            self.snd_nxt +%= 1;
        }
    }

    pub fn sendAck(self: *Self) void {
        self.sendInternal(.{ .ack = 1 }, &.{});
    }

    pub fn addMtuOption(buffer: []u8, mss: u16) void {
        buffer[0] = 0x02;
        buffer[1] = 0x04;
        @memcpy(buffer[2..4], std.mem.asBytes(&std.mem.nativeToBig(u16, mss)));
    }

    fn sendSynAck(self: *Self) void {
        const iface = self.iface.?;
        if (iface.requestFrame()) |frame| {
            var header = TcpHeader{
                .sport = std.mem.nativeToBig(u16, self.port),
                .dport = std.mem.nativeToBig(u16, self.sport),
                .seq_number = std.mem.nativeToBig(u32, self.irs),
                .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
                .data_offset = 0x60,
                .flags = .{ .syn = 1, .ack = 1 },
                .window = std.mem.nativeToBig(u16, self.rcv_wnd),
            };

            const pos: usize = types.TRANSPORT_HEADER_OFFSET;
            var end: usize = pos + @sizeOf(TcpHeader);
            @memcpy(frame.buffer[pos..end], std.mem.asBytes(&header));

            addMtuOption(frame.buffer[end..], self.mss);
            end += 4;

            frame.len = end - pos;

            const checksum = ipv4.calcPseudoChecksum(frame.buffer[pos..end], .TCP, iface.ip_addr, self.daddr);
            @memcpy(frame.buffer[pos + @offsetOf(TcpHeader, "checksum") ..][0..2], std.mem.asBytes(&checksum));

            ipv4.send(iface, self.daddr, frame, .TCP);
        }
    }
};

var tcp_pool_backing_buffer: [tcp_pool_size]TcpSocket = .{TcpSocket{}} ** tcp_pool_size;
var tcp_pool: std.ArrayList(TcpSocket) = .initBuffer(&tcp_pool_backing_buffer);

pub fn requestSocket() ?*TcpSocket {
    return if (tcp_pool.addOneBounded()) |sock| sock else |_| null;
}

pub fn returnSocket(socket: *TcpSocket) void {
    for (tcp_pool.items, 0..) |*sock, i| {
        if (sock == socket) {
            _ = tcp_pool.swapRemove(i);
            break;
        }
    }
}

pub const ServerEvent = enum {
    connected,
};

pub const ServerEventFn = *const fn (server: *TcpServer, event: ServerEvent) void;

pub const TcpServer = struct {
    port: u16 = 0,
    active: bool = false,
    event_callback: ?ServerEventFn = null,
    context: ?*anyopaque = null,
    iface: ?*types.Interface = null,
    max_connections: usize = tcp_pool_size,
    connection_count: usize = 0,

    const Self = @This();

    pub fn init(self: *Self, port: u16, callback: ?ServerEventFn, max_conns: usize, ctx: ?*anyopaque) void {
        self.port = port;
        self.event_callback = callback;
        self.context = ctx;
        self.max_connections = @min(max_conns, tcp_pool_size);
        self.active = true;
    }

    pub fn accept(self: *Self, callback: EventFn, ctx: ?*anyopaque) ?*TcpSocket {
        for (accept_queue.items, 0..) |sock, i| {
            if (sock.port == self.port and sock.state == .ESTABLISHED) {
                _ = accept_queue.swapRemove(i);
                sock.callback = callback;
                sock.cb_context = ctx;
                return sock;
            }
        }
        return null;
    }
};

const tcp_server_pool_size: usize = 1;
pub var tcp_server_pool: [tcp_server_pool_size]TcpServer = .{TcpServer{}} ** tcp_server_pool_size;

var accept_queue_buf: [tcp_pool_size]*TcpSocket = undefined;
var accept_queue: std.ArrayList(*TcpSocket) = .initBuffer(&accept_queue_buf);

pub fn requestServer() ?*TcpServer {
    for (&tcp_server_pool) |*srv| {
        if (!srv.active) {
            return srv;
        }
    }
    return null;
}

pub fn flushAll() void {
    for (&tcp_pool.items) |*sock| {
        sock.flush();
    }
}

pub fn processTCPFrame(iface: *types.Interface, saddr: u32, buffer: []u8) void {
    if (buffer.len < @sizeOf(TcpHeader)) return;

    const header: TcpHeader = std.mem.bytesToValue(TcpHeader, buffer[0..@sizeOf(TcpHeader)]);
    const dport = std.mem.bigToNative(u16, header.dport);
    const sport = std.mem.bigToNative(u16, header.sport);

    const checksum = ipv4.calcPseudoChecksum(buffer, .TCP, saddr, iface.ip_addr);

    if (checksum != 0) {
        logger.debug("TCP: invalid checksum\n", .{});
        return;
    }

    if (header.flags.syn == 1 and header.flags.ack == 0) {
        for (&tcp_server_pool) |*server| {
            if (!server.active or server.port != dport) continue;

            if (server.connection_count >= server.max_connections) {
                return;
            }

            if (requestSocket()) |socket| {
                socket.* = TcpSocket{
                    .iface = iface,
                    .server = server,
                    .state = .SYN_RECEIVED,
                    .port = dport,
                    .sport = sport,
                    .daddr = saddr,
                    .rcv_nxt = std.mem.nativeToBig(u32, header.seq_number) +% 1,
                    .irs = std.mem.nativeToBig(u32, header.seq_number),
                };
                socket.snd_una = std.mem.nativeToBig(u32, header.seq_number);
                socket.snd_nxt = socket.snd_una +% 1;
                socket.sendSynAck();
                if (@sizeOf(TcpHeader) != ((header.data_offset >> 4) * 4)) {
                    const end_of_header = (header.data_offset >> 4) * 4;
                    var opt_iter: OptionIterator = .{ .buffer = buffer[@sizeOf(TcpHeader)..end_of_header] };
                    while (opt_iter.next()) |opt| switch (opt.code) {
                        .MSS => {
                            socket.peer_mss = std.mem.bigToNative(u16, std.mem.bytesToValue(u16, opt.payload[2..]));
                        },
                        else => {},
                    };
                }
                server.connection_count += 1;
                logger.debug("TCP: new connection on port {d} sport={d}\n", .{ dport, sport });
            } else {
                logger.debug("TCP: no sockets available for new connection on port {d}\n", .{dport});
            }
            return;
        }
        logger.debug("TCP: no server for port {d}\n", .{dport});
        return;
    }

    for (tcp_pool.items) |*sock| {
        if (sock.port != dport) continue;
        if (sock.sport != sport or sock.daddr != saddr) continue;

        const prev_state = sock.state;
        sock.wnd_update_pending = false;
        sock.receive(buffer);

        if (prev_state == .SYN_RECEIVED and sock.state == .ESTABLISHED) {
            accept_queue.appendAssumeCapacity(sock);
            for (&tcp_server_pool) |*server| {
                if (server.active and server.port == dport) {
                    if (server.event_callback) |cb| {
                        cb(server, .connected);
                    }
                }
            }
        }

        if (sock.state == .CLOSED) {
            if (sock.server) |srv| srv.connection_count -= 1;
            returnSocket(sock);
        }
    }
}

pub fn generateInitialSequenceNumber() u32 {
    return 100;
}

test "checksum" {
    const tcp_packet: [47]u8 = .{ 0x9c, 0x88, 0x1b, 0x58, 0x99, 0x5b, 0x84, 0x6f, 0x9a, 0x99, 0xb0, 0x25, 0x80, 0x18, 0x00, 0x40, 0x05, 0x2e, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xef, 0xa6, 0x5b, 0xbb, 0x94, 0xd1, 0x27, 0x5e, 'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!', '\r', '\n' };

    const checksum = syntax.ipv4.calcPseudoChecksum(&tcp_packet, .TCP, std.mem.bigToNative(u32, 0x7f000001), std.mem.bigToNative(u32, 0x7f000001));

    try std.testing.expectEqual(0x0000, checksum);
}
