const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("uzip", .{
        .root_source_file = b.path("src/uzip.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_module = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    // run tests
    const tests = b.addTest(.{
        .root_module = test_module,
        // .target = target,
        // .optimize = optimize,
        // .test_runner = .{ .path = b.path("src/test_runner.zig"), .mode = .simple }, // add this line
    });
    // tests.linkLibC();
    // const force_blocking = b.option(bool, "force_blocking", "Force blocking mode") orelse false;
    const options = b.addOptions();
    // options.addOption(bool, "websocket_blocking", force_blocking);
    tests.root_module.addOptions("build", options);

    const run_test = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_test.step);
}
