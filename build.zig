const std = @import("std");

const lib = @import("lib").lib;

pub fn build(b: *std.Build) !void {
    const opts = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe }),
    };

    const exe = b.addExecutable(.{
        .name = "nix-sigstop",
        .root_source_file = b.path("main.zig"),
        .target = opts.target,
        .optimize = opts.optimize,
    });
    addDependencyImports(b, &exe.root_module, opts);
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
            .root_source_file = exe.root_module.root_source_file.?,
            .target = opts.target,
            .optimize = opts.optimize,
        });
        addDependencyImports(b, &exe_test.root_module, opts);

        const run_exe_test = b.addRunArtifact(exe_test);
        test_step.dependOn(&run_exe_test.step);
    }

    _ = lib.addCheckTls(b);
}

fn addDependencyImports(b: *std.Build, module: *std.Build.Module, opts: anytype) void {
    module.addImport("lib", b.dependency("lib", opts).module("lib"));
    module.addImport("known-folders", b.dependency("known-folders", opts).module("known-folders"));
}
