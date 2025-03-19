const std = @import("std");

const utils = @import("utils").utils;

pub fn build(b: *std.Build) !void {
    const opts = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe }),
    };

    const exe = b.addExecutable(.{
        .name = "nix-sigstop",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = opts.target,
            .optimize = opts.optimize,
            .imports = &.{
                .{ .name = "utils", .module = b.dependency("utils", opts).module("utils") },
                .{ .name = "known-folders", .module = b.dependency("known-folders", opts).module("known-folders") },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    {
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_cmd.addArgs(args);

        run_step.dependOn(&run_cmd.step);
    }

    const test_step = b.step("test", "Run unit tests");
    {
        const exe_test = b.addTest(.{
            .root_module = exe.root_module,
        });

        const run_exe_test = b.addRunArtifact(exe_test);
        test_step.dependOn(&run_exe_test.step);
    }

    _ = utils.addCheckTls(b);
}
