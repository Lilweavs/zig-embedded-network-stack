const std = @import("std");

// TODO: keep unsupported methods commented for now
const Method = enum {
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

const Connection = enum {
    Close,
    KeepAlive,
};

const Request = struct {
    method: Method,
    target: [128]u8 = undefined, // could just be a hash
    target_len: u8 = 0,
    connection: Connection = .KeepAlive,
    content_length: usize = 0,
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

const HttpError = error{
    MethodNotAllowed,
    BadRequest,
    UriTooLong,
    HttpVersionNotSupported,
};

// for simplicity terminate on any errors
const Parser = struct {
    const Self = @This();

    const Result = enum {
        NeedMore,
        Complete,
        Error,
    };

    state: State = .RequestLine,

    consumed: usize = 0,
    idx: usize = 0,

    parsed_host: bool = false,

    pub fn parse(p: *Self, scratch: []const u8, req: *Request) !Result {
        // does not include \r\n
        while (std.mem.findPosLinear(u8, scratch, p.idx, "\r\n")) |idx| {
            const line = scratch[p.idx..idx];
            if (p.consumed > 0 and line.len == 0) return .Complete;
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
                        req.target_len = str.len;
                    } else return error.BadRequest;

                    // parse version
                    if (iter.next()) |str| {
                        if (!std.ascii.eqlIgnoreCase(str, "HTTP/1.1")) return error.HttpVersionNotSupported; // 505
                    } else return error.BadRequest;
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
};

fn validateHost(host: []const u8) bool {
    _ = host;
    return true;
}
