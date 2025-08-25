//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |          Source Port          |       Destination Port        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                        Sequence Number                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Acknowledgment Number                      |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |  Data |       |C|E|U|A|P|R|S|F|                               |
//      | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
//      |       |       |R|E|G|K|H|T|N|N|                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |           Checksum            |         Urgent Pointer        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                           [Options]                           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               :
//      :                             Data                              :
//      :                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//

const std = @import("std");
const builtin = @import("builtin");
const ipv4 = @import("ipv4.zig");
const eth = @import("eth.zig");
const hal = @import("hal.zig");

const TcpFlags = packed struct { fin: u1 = 0, syn: u1 = 0, rst: u1 = 0, psh: u1 = 0, ack: u1 = 0, urg: u1 = 0, ece: u1 = 0, cwr: u1 = 0 };

const TcpHeader = extern struct {
    sport: u16 align(1) = 0,
    dport: u16 align(1) = 0,
    seq_number: u32 align(1) = 0,
    ack_number: u32 align(1) = 0,
    data_offset: u8 align(1) = 0,
    flags: TcpFlags align(1) = .{},
    window: u16 align(1) = 0,
    checksum: u16 align(1) = 0,
    urgent_pointer: u16 align(1) = 0,
};

var rx_queue: [4096]u8 = undefined;
var tx_queue: [1024]u8 = undefined;

var head: usize = 0;
var tail: usize = 0;

// when receiving data copy to tail. Once user removes data free up space with head.
// when sending data copy to tail. Once ack move head

// checksum is the same as udp
// +--------+--------+--------+--------+
// |           Source Address          |
// +--------+--------+--------+--------+
// |         Destination Address       |
// +--------+--------+--------+--------+
// |  zero  |  PTCL  |    TCP Length   |
// +--------+--------+--------+--------+

// Mandatory Option Set
// Kind    Length    Meaning
//   0       -       End of Option List Option.
//   1       -       No-Operation.
//   2       4       Maximum Segment Size.

// TVL - length, 2 + data length

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

    // store must have enough space to store the entire message
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

pub fn processTCPFrame(frame: ipv4.IPv4Frame) !void {
    const header: TcpHeader = std.mem.bytesToValue(TcpHeader, frame.payload[0..@sizeOf(TcpHeader)]);

    // try hal.printf("---TCP Recv---\n sport: {d}\n dport: {d}\n checksum: {X:0>4}\n", .{ std.mem.bigToNative(u16, header.sport), std.mem.bigToNative(u16, header.dport), header.checksum });
    // const offset: usize = header.data_offset * 4;

    const dport = std.mem.bigToNative(u16, header.dport);

    if (server.port == dport) {
        if (header.flags == TcpFlags{ .syn = 1 }) {

            // find a tcb to alloc and responed with SYN-ACK
            try hal.printf("Allocating Block\n", .{});
            if (allocControlBlock()) |*tcb| {
                tcb.*.port = server.port;
                tcb.*.sport = std.mem.bigToNative(u16, header.sport);
                tcb.*.daddr = frame.header.saddr;
                tcb.*.state = .LISTEN;
            }
            // server.tcb.state = .SYN_RECEIVED;

            // server.tcb.seq_number = std.mem.bigToNative(u32, header.seq_number);
            // server.tcb.ack_number = generateInitialAcknowledgeNumber();

            // server.tcb.sendSynAck();
        }

        for (&control_blocks) |*tcb| {
            if (tcb.state == .CLOSED) return else tcb.receive(header.sport, frame.header.saddr, frame.payload);
        }
    }

    // first check if any TCP servers are looking for dport
    // for (&tcp_servers) |server| {
    //     if (tcp_server.active and server.port == dport) {
    //         return tcp_server.processPacket(frame);
    //     }
    // }

    // for (&tcp_pool) |*sock| {
    //     if (sock.active and sock.port == dport) {
    //         return if (sock.recv_callback) |callback| callback(sock, frame.header.saddr, std.mem.nativeToBig(u16, header.sport), frame.payload[header.payload[header.data_offset*4..]]);
    //     }
    // }
}

fn allocControlBlock() ?*TcpControlBlock {
    for (&control_blocks) |*tcb| {
        if (tcb.state == .CLOSED) {
            // hal.printf("TCB: Allocated\n", .{}) catch {};
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

// Variable    Description
// SEG.SEQ     segment sequence number
// SEG.ACK     segment acknowledgment number
// SEG.LEN     segment length
// SEG.WND     segment window
// SEG.UP     segment urgent pointer

// SND.UNA < SEG.ACK =< SND.NXT

// Segment tests
// Segment    Length    Receive Window     Test
//     0         0      SEG.SEQ = RCV.NXT
//     0        >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
//    >0         0      not acceptable
//    >0        >0      RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND

// TCP needs a 4 us tick clock
// ISN = M + F(localip, localport, remoteip, remoteport, secretkey)
// M := 4 usecond timer
// F := likey some cyptographical hash of the above parameters

// Initial sync with TCP
// 1) A --> B  SYN my sequence number is X
// 2) A <-- B  ACK your sequence number is X
// 3) A <-- B  SYN my sequence number is Y
// 4) A --> B  ACK your sequence number is Y
// 2 and 3 can be combined

// for listen
// 1. if syn received
// 2. allocate new TCB -> send SYN, ACK
// 3. if ACK eCB is now Established and can be accepted()

// receivers algorithm

// TCP Retransmission Timer
// SRTT: smoothed round-trip time
// RTTVAR: round-trip time variation
// G: clock granularity
//
// Until RTT is made set RTO to 1
//
// Once first RTT, R is made
// SRTT = R
// RTTVAR = R / 2
// RTO = SRTT + max(G, K * RTTVAR); where K = 4
//
// When another RTT is made R'
// RTTVAR: (1 - beta) * RTTVAR + beta * |SRTT - R'|; where beta = 1/4
// SRTT: (1 - alpha) * SRTT + alpha * R'; where alpha = 1/8
// RTO: SRTT + max(G, K * RTTVAR)
// IF RTO < 1 set to 1. maximum MAY be placed but should be at least 60s

pub const TcpServer = struct {
    // tcb: TcpTcb = {},
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

const TcpSendSegment = struct {
    index: usize,
    len: usize,
    rto: usize,
};

pub const TcpControlBlock = struct {
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

    // Key Send Connection State Variables
    //
    snd_una: u32 = 0,
    //
    snd_nxt: u32 = 0,
    //
    snd_wnd: u16 = 0,
    //
    snd_up: u32 = 0,
    //
    snd_wl1: u32 = 0,
    //
    snd_wl2: u32 = 0,
    //
    iss: u32 = 0,

    // Key  Connection State variables
    //
    rcv_nxt: u32 = 0,
    //
    rcv_wnd: u16 = 4096,
    //
    rcv_up: u32 = 0,
    //
    irs: u32 = 0,

    // Other Key variables
    mss: u16 = 576 - 40, // maximum segment size. maximum 1460 for TCP
    // variables used for CURRENT segment
    // Variable    Description
    // SEG.SEQ    segment sequence number
    // SEG.ACK    segment acknowledgment number
    // SEG.LEN    segment length
    // SEG.WND    segment window
    // SEG.UP     segment urgent pointer

    const Self = @This();

    pub fn status(self: *Self) State {
        return self.state;
    }

    pub fn open() void {}

    pub fn connect(self: *Self) void {
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
                // queue fin ack
                self.sendInternal(.{ .fin = 1, .ack = 1 }, &.{});
                self.state = .LAST_ACK;
            },
            .ESTABLISHED => {
                // queue fin ack
                // enter fin_wait_1
            },
            else => {
                // CLOSING, LAST_ACK, TIME-WAIT
            },
        }
    }

    pub fn recv(self: *Self, buffer: []u8) usize {
        if (self.rx_buffer.availableSpace() == 0) return 0;
        return self.rx_buffer.copy(buffer);
    }

    pub fn send(self: *Self, payload: []const u8) void {
        _ = self.tx_buffer.store(payload);

        if (hal.requestBuffer()) |buffer| {
            var header = TcpHeader{
                .sport = std.mem.nativeToBig(u16, self.port),
                .dport = std.mem.nativeToBig(u16, self.sport),
                .seq_number = std.mem.nativeToBig(u32, self.snd_nxt),
                .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
                .data_offset = 0x50,
                .flags = .{ .ack = 1, .psh = 1 },
                .window = std.mem.nativeToBig(u16, self.rcv_wnd),
            };

            var pos: usize = 34;
            var end: usize = pos + @sizeOf(TcpHeader);
            @memcpy(buffer[pos..end], std.mem.asBytes(&header));

            pos = end;
            end = pos + payload.len;
            @memcpy(buffer[pos..end], payload);

            const checksum = calcPseudoChecksum(buffer[34..end], @intFromEnum(ipv4.Protocol.TCP), ipv4.ip_addr, self.daddr);

            // const checksum = calcTcpChecksum(
            //     buffer[34..end],
            //     ipv4.ip_addr,
            //     self.daddr,
            // );

            pos = @offsetOf(TcpHeader, "checksum");
            @memcpy(buffer[pos .. pos + @sizeOf(@FieldType(TcpHeader, "checksum"))], std.mem.asBytes(&checksum));

            // for (34..end) |i| {
            //     hal.printf("{X:0>2} ", .{buffer[i]}) catch {};
            // }
            // hal.printf("\n", .{}) catch {};

            // now send IPv4 Packet
            ipv4.send(self.daddr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.TCP }) catch {};
            self.snd_nxt +%= payload.len;
        }
    }

    pub fn available(self: Self) usize {
        return self.rx_buffer.size;
    }

    pub fn receive(self: *Self, sport: u16, saddr: u32, payload: []const u8) void {
        _ = sport;
        _ = saddr;

        // hal.printf("TCP Received\n", .{}) catch {};

        const header: TcpHeader = std.mem.bytesToValue(TcpHeader, payload[0..@sizeOf(TcpHeader)]);

        const end_of_header: usize = ((header.data_offset >> 4) * 4);
        const segment = payload[end_of_header..];
        const seg_ack = std.mem.nativeToBig(u32, header.ack_number);
        const seg_seq = std.mem.nativeToBig(u32, header.seq_number);
        const seg_wnd = std.mem.nativeToBig(u16, header.window);

        // first check segment proofs

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

        // segment acceptability test
        switch (self.state) {
            .CLOSED => {
                // discard everything we should never be hear
                hal.printf("IMPOSSIBLE!\n", .{}) catch {};
                unreachable;
            },
            .LISTEN => {
                hal.printf("Listen\n", .{}) catch {};
                if (header.flags.rst == 1) {
                    return;
                } else if (header.flags.ack == 1) {
                    // send ack
                    // <ack=seg.ack><ctl=rst>
                    return;
                } else if (header.flags.syn == 1) {
                    // check security if bad send <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                    self.rcv_nxt = seg_seq +% 1;
                    self.irs = seg_seq;

                    self.sendSynAck();

                    self.snd_una = std.mem.bigToNative(u32, header.seq_number);
                    self.snd_nxt = self.snd_una +% 1;

                    self.state = .SYN_RECEIVED;
                } else {
                    // this shouldn't happen
                }
            },
            .SYN_SENT => {
                if (header.flags.ack == 1) {
                    if (seqLessThanEqual(seg_ack, self.iss) or seqGreaterThan(seg_ack, self.snd_nxt)) {
                        if (header.flags.rst == 1) {
                            return;
                        }
                        self.sendInternal(.{ .rst = 1 }, &.{});
                        return;
                    }
                }
                // if (header.flags.rst == 1) return; // possibly go to close and signal connection reset
                // check security

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
                hal.printf("Syn Received\n", .{}) catch {};
                // if from listen
                if (header.flags.rst == 1) {
                    self.state = .LISTEN;
                    return;
                }
                if (header.flags.syn == 1) {
                    self.state = .LISTEN;
                    return;
                }
                if (header.flags.ack == 1) {
                    if (seqLessThan(self.snd_una, seg_ack) and seqLessThanEqual(seg_ack, self.snd_nxt)) {
                        self.snd_wnd = seg_wnd;
                        self.snd_wl1 = seg_seq;
                        self.snd_wl2 = seg_ack;
                        self.state = .ESTABLISHED;
                        hal.printf("Established\n", .{}) catch {};
                    } else {
                        // send reset
                    }
                }
                // if from syn-sent signal connection refused. flush retransmission queue. enter closed state, delete TCB
            },
            .ESTABLISHED => {
                if (header.flags.rst == 1) {
                    // any outstanding rx and snd should receive reset responses
                    self.state = .CLOSED;
                    return;
                }
                // check security
                if (header.flags.syn == 1) {
                    // send challenge ack
                    // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                }
                if (header.flags.ack == 1) {
                    if (seqLessThan(self.snd_una, seg_ack) and seqLessThanEqual(seg_ack, self.snd_nxt)) {
                        self.snd_una = seg_ack;
                        return;
                    }
                } else {
                    return; // we should always receive an ack
                }
                if (header.flags.urg == 1) {
                    // don't know what this means
                }

                // process segment text
                if (segment.len > 0) {
                    const num_acked = self.rx_buffer.store(segment);
                    self.rcv_nxt +%= num_acked;
                    self.rcv_wnd -= @intCast(num_acked);
                    // ideally num_acked == segment.len in almost all cases
                    // self.rcv_nxt += segment.len;
                }

                // now we can process data
                if (header.flags.fin == 1) {
                    hal.printf("Peer Closed Connection. {d}", .{segment.len}) catch {};
                    self.rcv_nxt +%= 1;
                    self.state = .CLOSE_WAIT; // in close wait we go to last ack
                }

                self.sendAck();
            },
            .CLOSE_WAIT => {
                if (header.flags.rst == 1) {}
            },
            .FIN_WAIT_1 => {
                if (header.flags.rst == 1) {
                    self.state = .CLOSED;
                }
                if (header.flags.ack == 1) {
                    self.sendInternal(.{ .fin = 1, .ack = 1 }, &.{});
                    self.state = .FIN_WAIT_2;
                }
            },
            .FIN_WAIT_2 => {},
            .LAST_ACK => {
                if (header.flags.rst == 1) {
                    // closed and delete TCB
                    self.state = .CLOSED;
                    hal.printf("Connection Closed", .{}) catch {};
                    return;
                }
                if (header.flags.ack == 1) {
                    self.state = .CLOSED;
                    hal.printf("Connection Closed", .{}) catch {};
                    return;
                }
            },
            else => {},
        }
    }

    fn checkWindowUpdate(self: *Self) void {
        // check receive window update
        if (self.rx_buffer.availableSpace() -| self.rcv_wnd >= @min(self.rx_buffer.data.len, self.mss)) {
            const num_mss_segments = self.rx_buffer.availableSpace() / self.mss;
            self.rcv_wnd += self.mss * num_mss_segments;
        }
    }

    // pub fn connect(port: u16, callback: ?TcpCallbackFn) void {
    //     if (hal.requestBuffer()) |buffer| {
    //         var header = TcpHeader{
    //             .sport = std.mem.nativeToBig(u16, 1234),
    //             .dport = std.mem.nativeToBig(u16, 8089),
    //             .seq_number = std.mem.nativeToBig(u32, generateInitialSequenceNumber()),
    //             .data_offset = 5,
    //             .flags = .{ .syn = 1 },
    //             .window = 65535,
    //         };
    //         header.data_offset = std.mem.nativeToBig(u16, 0x0006);

    //         var pos: usize = 34;
    //         var end: usize = pos + @sizeOf(header);
    //         @memcpy(buffer[pos..end], std.mem.asBytes(&header));

    //         pos = end;
    //         end = pos + payload.len;
    //         @memcpy(buffer[pos..end], payload);

    //         // set options
    //         buffer[end] = 0x02;
    //         buffer[end + 1] = 0x04;
    //         buffer[end + 2] = 0xFF;
    //         buffer[end + 3] = 0xFF;

    //         end = end + 4;
    //         // if not ending on 4 byte boundary pad with 0x01

    //         const checksum = calcTcpChecksum(buffer[34..end], ipv4.ip_addr, dip_addr);

    //         pos = @offsetOf(TcpHeader, "checksum");
    //         @memcpy(buffer[pos .. pos + @sizeOf(@FieldType(TcpHeader, "checksum"))], std.mem.asBytes(&checksum));

    //         // now send IPv4 Packet
    //         ipv4.send(dip_addr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.UDP }) catch {};
    //     }
    // }

    // fn prepareFrame(flags: TcpFlags) void {}

    fn sendInternal(self: *Self, flags: TcpFlags, payload: []u8) void {
        const buffer = if (hal.requestBuffer()) |buf| buf else return;

        var header = TcpHeader{
            .sport = std.mem.nativeToBig(u16, self.port),
            .dport = std.mem.nativeToBig(u16, self.sport),
            .seq_number = std.mem.nativeToBig(u32, self.snd_nxt),
            .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
            .data_offset = 0x50,
            .flags = flags,
            .window = std.mem.nativeToBig(u16, self.rcv_wnd),
        };

        var pos: usize = 34;
        var end: usize = pos + @sizeOf(TcpHeader);
        @memcpy(buffer[pos..end], std.mem.asBytes(&header));

        pos = end;
        end = pos + payload.len;

        const checksum = calcPseudoChecksum(
            buffer[34..end],
            @intFromEnum(ipv4.Protocol.TCP),
            ipv4.ip_addr,
            self.daddr,
        );

        pos = @offsetOf(TcpHeader, "checksum");
        @memcpy(buffer[pos .. pos + @sizeOf(@FieldType(TcpHeader, "checksum"))], std.mem.asBytes(&checksum));

        // now send IPv4 Packet
        ipv4.send(self.daddr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.TCP }) catch {};
    }

    fn createHeader() TcpHeader {}

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
        self.checkWindowUpdate();
        if (hal.requestBuffer()) |buffer| {
            // hal.printf("Sending Syn|Ack\n", .{}) catch {};

            var header = TcpHeader{
                .sport = std.mem.nativeToBig(u16, self.port),
                .dport = std.mem.nativeToBig(u16, self.sport),
                .seq_number = std.mem.nativeToBig(u32, self.irs),
                .ack_number = std.mem.nativeToBig(u32, self.rcv_nxt),
                .data_offset = 0x60,
                .flags = .{ .syn = 1, .ack = 1 },
                .window = std.mem.nativeToBig(u16, self.rcv_wnd),
            };

            const pos: usize = 34;
            var end: usize = pos + @sizeOf(TcpHeader);
            @memcpy(buffer[pos..end], std.mem.asBytes(&header));

            // pos = end;
            // end = pos + payload.len;
            // @memcpy(buffer[pos..end], payload);

            // set options
            addMtuOption(buffer[end..], self.mss);
            end += 4;

            // header.data_offset = (@as(u8, @intCast(end - pos)) / 4) << 4;

            // if not ending on 4 byte boundary pad with 0x01

            // const checksum = calcTcpChecksum(
            //     buffer[34..end],
            //     ipv4.ip_addr,
            //     self.daddr,
            // );

            // pos = @offsetOf(TcpHeader, "checksum");
            // @memcpy(buffer[pos .. pos + @sizeOf(@FieldType(TcpHeader, "checksum"))], std.mem.asBytes(&checksum));

            // for (34..end) |i| {
            //     hal.printf("{X:0>2} ", .{buffer[i]}) catch {};
            // }
            // hal.printf("\n", .{}) catch {};

            // now send IPv4 Packet
            ipv4.send(self.daddr, buffer[34..end], .{ .buffer = buffer, .proto = ipv4.Protocol.TCP }) catch {};
        }
    }
};

pub fn calcPseudoChecksum(buffer: []const u8, proto: u8, saddr: u32, daddr: u32) u16 {
    // should be pseudo header + normal checksum function
    var checksum: u32 = std.mem.nativeToBig(u16, proto + @as(u16, @intCast(buffer.len)));

    const offset = (buffer.len & 1);

    const words = std.mem.bytesAsSlice(u16, buffer[0 .. buffer.len - offset]);

    for (words) |word| {
        checksum += word;
    }

    if (offset > 0) {
        checksum += buffer[buffer.len - 1];
    }

    checksum += (saddr & 0xFFFF) + ((saddr >> 16) & 0xFFFF);
    checksum += (daddr & 0xFFFF) + ((daddr >> 16) & 0xFFFF);

    checksum = (checksum & 0xFFFF) + ((checksum >> 16) & 0xFFFF); // handle carry bits i.e. 0x10000 -> 0x0001

    return ~@as(u16, @intCast(checksum & 0xFFFF));
}

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
        if (&tcp_pool[i] == socket) {
            // std.mem.swap(UDPSocket, &udp_pool[i], );
        }
    }
    socket.active = false;
}

pub fn generateInitialSequenceNumber() u32 {
    return 100;
}

pub fn generateInitialAcknowledgeNumber() u32 {
    return 100;
}
