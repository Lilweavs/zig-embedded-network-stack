const std = @import("std");
const http = @import("../http.zig");

const HttpError = http.HttpError;

// TODO: keep unsupported methods commented for now
pub const Method = enum {
    GET,
    // HEAD,
    POST,
    // PUT,
    // DELETE,
    // CONNECT,
    // OPTIONS,
    // TRACE,
    // PATCH,
    // Invalid,
};

pub const Connection = enum {
    Close,
    KeepAlive,
};

pub const Request = struct {
    method: Method,
    target: [128]u8 = undefined, // could just be a hash
    target_len: u8 = 0,
    connection: Connection = .KeepAlive,
    content_length: usize = 0,

    pub fn path(req: *const Request) []const u8 {
        return req.target[0..req.target_len];
    }
};

const State = enum {
    RequestLine,
    Options,
    Body,
};

const HeaderOptions = enum {
    Host,
    ContentLength,
    ContentType,
    Connection,
    TransferEncoding,
    Unknown,
};

// for simplicity terminate on any errors
pub const Parser = struct {
    const Self = @This();

    pub const Result = enum {
        NeedMore,
        Complete,
        Error,
    };

    state: State = .RequestLine,

    consumed: usize = 0,
    idx: usize = 0,

    parsed_host: bool = false,

    pub fn consumedBytes(p: *Self) usize {
        return p.idx;
    }

    pub fn compact(p: *Self) void {
        p.idx = 0;
        p.consumed = 0;
        // p.idx -= n;
        // p.consumed -= n;
    }

    pub fn parse(p: *Self, scratch: []const u8, req: *Request) HttpError!Result {
        // does not include \r\n
        while (std.mem.findPosLinear(u8, scratch, p.idx, "\r\n")) |idx| {
            const line = scratch[p.idx..idx];
            if (p.consumed > 0 and line.len == 0) {
                p.idx += line.len + 2; // jump past the new-line
                p.consumed += line.len + 2;
                return .Complete;
            }
            switch (p.state) {
                .RequestLine => {
                    var iter = std.mem.tokenizeScalar(u8, line, ' ');

                    // parse method
                    if (iter.next()) |str| {
                        if (std.meta.stringToEnum(Method, str)) |e| {
                            req.method = e;
                        } else return error.MethodNotAllowed; // 405
                    } else return error.BadRequest;

                    // parse target
                    if (iter.next()) |str| {
                        if (str.len > req.target.len) return error.UriTooLong; // 413
                        @memcpy(req.target[0..str.len], str);
                        req.target_len = @intCast(str.len);
                    } else return error.BadRequest;

                    // parse version
                    if (iter.next()) |str| {
                        if (!std.ascii.eqlIgnoreCase(str, "HTTP/1.1")) return error.HttpVersionNotSupported; // 505
                    } else return error.BadRequest;
                    p.state = .Options;
                },
                .Options => {
                    var iter = std.mem.tokenizeScalar(u8, line, ' ');

                    if (iter.next()) |opt_str| {
                        if (std.ascii.eqlIgnoreCase(opt_str, "Host:")) {
                            if (p.parsed_host) return error.BadRequest; // only allow one host
                            if (iter.next()) |value_str| {
                                if (validateHost(value_str)) {
                                    p.parsed_host = true;
                                }
                            } else return error.BadRequest;
                        } else if (std.ascii.eqlIgnoreCase(opt_str, "Connection:")) {
                            if (iter.next()) |value_str| {
                                if (std.ascii.eqlIgnoreCase(value_str, "keep-alive")) {
                                    req.connection = .KeepAlive;
                                } else if (std.ascii.eqlIgnoreCase(value_str, "close")) {
                                    req.connection = .Close;
                                } else return error.BadRequest;
                            } else return error.BadRequest;
                        } else if (std.ascii.eqlIgnoreCase(opt_str, "Content-Length:")) {
                            if (iter.next()) |value_str| {
                                req.content_length = std.fmt.parseInt(usize, value_str, 10) catch return error.BadRequest;
                            }
                            if (iter.next() != null) return error.BadRequest;
                        } else {
                            // ignore it and move on
                        }
                    } else return error.BadRequest;
                },
                .Body => {},
            }
            p.idx += line.len + 2; // jump past the new-line
            p.consumed += line.len + 2;
        }
        return .NeedMore;
    }

    /// Returns the number of bytes consumed so far and resets the parser
    /// for parsing the next request while preserving state across a keep-alive.
    pub fn reset(p: *Self) usize {
        const c = p.idx;
        p.idx = 0;
        p.consumed = 0;
        p.state = .RequestLine;
        p.parsed_host = false;
        return c;
    }
};

fn validateHost(host: []const u8) bool {
    _ = host;
    return true;
}

test "simple GET request line" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.Complete, result);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/", req.target[0..req.target_len]);
}

test "GET request with host and connection headers" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET /dashboard HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.Complete, result);
    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/dashboard", req.target[0..req.target_len]);
    try std.testing.expectEqual(Connection.Close, req.connection);
}

test "POST request" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: 42\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.Complete, result);
    try std.testing.expectEqual(Method.POST, req.method);
    try std.testing.expectEqualStrings("/submit", req.target[0..req.target_len]);
    try std.testing.expectEqual(@as(usize, 42), req.content_length);
}

test "unknown headers are skipped" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\nHost: ok.com\r\nX-Custom: foo\r\nAccept: */*\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.Complete, result);
}

test "default connection is keep-alive" {
    const req: Request = .{ .method = .GET };
    try std.testing.expectEqual(Connection.KeepAlive, req.connection);
}

test "need more on partial request line" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET /";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.NeedMore, result);
}

test "need more on partial header" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\nHost: exa";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.NeedMore, result);
}

test "error on unsupported method" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "DELETE / HTTP/1.1\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.MethodNotAllowed, result);
}

test "error on bad http version" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/2.0\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.HttpVersionNotSupported, result);
}

test "error on uri too long" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const long_target = "/" ++ ("a" ** 128);
    const input = "GET " ++ long_target ++ " HTTP/1.1\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.UriTooLong, result);
}

test "error on duplicate host" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.BadRequest, result);
}

test "error on bad content-length" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\nContent-Length: notanumber\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.BadRequest, result);
}

test "error on unknown connection value" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\nConnection: garbage\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.BadRequest, result);
}

test "uppercase method is required" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .POST };

    const input = "get / HTTP/1.1\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectError(error.MethodNotAllowed, result);
}

test "case insensitive connection header" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    const input = "GET / HTTP/1.1\r\nConnection: Keep-Alive\r\n\r\n";
    const result = parser.parse(input, &req);
    try std.testing.expectEqual(Parser.Result.Complete, result);
    try std.testing.expectEqual(Connection.KeepAlive, req.connection);
}

test "reuse parser for multiple requests" {
    var req: Request = .{ .method = .GET };

    {
        var parser: Parser = .{};
        const input = "GET /a HTTP/1.1\r\nHost: one.com\r\n\r\n";
        const result = parser.parse(input, &req);
        try std.testing.expectEqual(Parser.Result.Complete, result);
        try std.testing.expectEqualStrings("/a", req.target[0..req.target_len]);
    }

    {
        var parser: Parser = .{};
        const input = "POST /b HTTP/1.1\r\nHost: two.com\r\nContent-Length: 10\r\n\r\n";
        const result = parser.parse(input, &req);
        try std.testing.expectEqual(Parser.Result.Complete, result);
        try std.testing.expectEqualStrings("/b", req.target[0..req.target_len]);
        try std.testing.expectEqual(Method.POST, req.method);
        try std.testing.expectEqual(@as(usize, 10), req.content_length);
    }
}

test "incremental parse: partial data then completion" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    var buf: [256]u8 = undefined;
    const full = "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 256\r\nConnection: close\r\n\r\n";

    // stage 1: only request line arrives
    const len1: usize = 25;
    @memcpy(buf[0..len1], full[0..len1]);
    const result1 = parser.parse(buf[0..len1], &req);
    try std.testing.expectEqual(Parser.Result.NeedMore, result1);

    // stage 2: first header arrives
    const len2: usize = 47;
    @memcpy(buf[len1..len2], full[len1..len2]);
    const result2 = parser.parse(buf[0..len2], &req);
    try std.testing.expectEqual(Parser.Result.NeedMore, result2);

    // stage 3: remaining headers and blank line arrive
    const len3 = full.len;
    @memcpy(buf[len2..len3], full[len2..len3]);
    const result3 = parser.parse(buf[0..len3], &req);
    try std.testing.expectEqual(Parser.Result.Complete, result3);

    try std.testing.expectEqual(Method.POST, req.method);
    try std.testing.expectEqualStrings("/api/data", req.target[0..req.target_len]);
    try std.testing.expectEqual(Connection.Close, req.connection);
    try std.testing.expectEqual(@as(usize, 256), req.content_length);
}

test "incremental parse: header value split across chunks" {
    var parser: Parser = .{};
    var req: Request = .{ .method = .GET };

    var buf: [256]u8 = undefined;
    const full = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // stage 1: request line + partial header value ("Host: exa")
    const len1: usize = 25;
    @memcpy(buf[0..len1], full[0..len1]);
    const result1 = parser.parse(buf[0..len1], &req);
    try std.testing.expectEqual(Parser.Result.NeedMore, result1);

    // stage 2: rest of header value + blank line ("mple.com\r\n\r\n")
    const len2 = full.len;
    @memcpy(buf[len1..len2], full[len1..len2]);
    const result2 = parser.parse(buf[0..len2], &req);
    try std.testing.expectEqual(Parser.Result.Complete, result2);

    try std.testing.expectEqual(Method.GET, req.method);
    try std.testing.expectEqualStrings("/", req.target[0..req.target_len]);
    try std.testing.expectEqual(Connection.KeepAlive, req.connection);
}
