const std = @import("std");

var millis: *const fn () u32 = .{};

var requestBuffer: *const fn () u32 = .{};

var transmitEthFrame: *const fn (buffer: []u8) void = .{};
