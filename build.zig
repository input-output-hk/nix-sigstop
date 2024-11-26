const std = @import("std");

const utils = @import("utils").utils;

pub fn build(b: *std.Build) !void {
    const opts = .{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe }),
    };

    const exe = b.addExecutable(.{
        .name = "nix-sigstop",
        .root_source_file = b.path("src/main.zig"),
        .target = opts.target,
        .optimize = opts.optimize,
    });
    addDependencyImports(b, &exe.root_module, opts);
    linkSystemLibraries(&exe.root_module);
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
        linkSystemLibraries(&exe_test.root_module);

        const run_exe_test = b.addRunArtifact(exe_test);
        test_step.dependOn(&run_exe_test.step);
    }

    _ = utils.addCheckTls(b);
}

fn addDependencyImports(b: *std.Build, module: *std.Build.Module, opts: struct {
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
}) void {
    module.addImport("utils", b.dependency("utils", opts).module("utils"));
    module.addImport("known-folders", b.dependency("known-folders", opts).module("known-folders"));
}

fn linkSystemLibraries(module: *std.Build.Module) void {
    module.link_libc = true;
}
