const std = @import("std");
const lib = @import("lib");

const nix = lib.nix;

/// Symlink build outputs into the eval store to save disk space.
/// Only works if the eval store is a chroot store!
const symlink_ifds_into_eval_store = true;

pub const Event = union(enum) {
    start: struct {
        derivation: nix.build_hook.Derivation,
        build_io: nix.build_hook.BuildIo,
    },
    /// the corresponding `start.derivation.drv_path`
    done: []const u8,

    fn emit(self: @This(), allocator: std.mem.Allocator, fifo: std.fs.File) !void {
        try fifo.lock(.exclusive);
        defer fifo.unlock();

        const fifo_writer = fifo.writer();

        if (std.log.defaultLogEnabled(.debug)) {
            const json = try std.json.stringifyAlloc(allocator, self, .{});
            defer allocator.free(json);

            std.log.debug("emitting IPC event: {s}", .{json});

            try fifo_writer.writeAll(json);
        } else try std.json.stringify(self, .{}, fifo_writer);

        try fifo_writer.writeByte('\n');
    }
};

pub fn main(allocator: std.mem.Allocator) !void {
    const verbosity = verbosity: {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();

        break :verbosity try nix.build_hook.parseArgs(&args);
    };
    std.log.debug("log verbosity: {s}", .{@tagName(verbosity)});

    var nix_config, var connection = try nix.build_hook.start(allocator);
    defer nix_config.deinit();

    if (std.log.defaultLogEnabled(.debug)) {
        var nix_config_msg = std.ArrayList(u8).init(allocator);
        defer nix_config_msg.deinit();

        var iter = nix_config.iterator();
        while (iter.next()) |entry| {
            try nix_config_msg.appendNTimes(' ', 2);
            try nix_config_msg.appendSlice(entry.key_ptr.*);
            try nix_config_msg.appendSlice(" = ");
            try nix_config_msg.appendSlice(entry.value_ptr.*);
            try nix_config_msg.append('\n');
        }

        std.log.debug("nix config:\n{s}", .{nix_config_msg.items});
    }

    var fifo = fifo: {
        const fifo_path = nix_config.get("builders").?;
        if (fifo_path.len == 0) {
            std.log.err("expected path to FIFO for IPC in nix config entry `builders` but it is empty", .{});
            return error.NoBuilders;
        }
        if (!std.fs.path.isAbsolute(fifo_path)) {
            std.log.err("path to FIFO for IPC is not absolute: {s}", .{fifo_path});
            return error.AccessDenied;
        }

        break :fifo std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
            std.log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
            return err;
        };
    };
    defer fifo.close();

    const store = nix_config.get("store").?;

    // Free all the memory in `nix_config` except the entries we still need.
    {
        var iter = nix_config.iterator();
        iter: while (iter.next()) |entry|
            inline for (.{"store"}) |key| {
                if (std.mem.eql(u8, entry.key_ptr.*, key)) continue :iter;
                nix_config.remove(entry.key_ptr.*);
            };
    }

    const drv = try connection.readDerivation(allocator);
    defer drv.deinit(allocator);

    const build_io = try connection.accept(allocator, "auto");
    defer build_io.deinit(allocator);

    try (Event{ .start = .{
        .derivation = drv,
        .build_io = build_io,
    } }).emit(allocator, fifo);

    const build_result = build(allocator, drv.drv_path, build_io.wanted_outputs, store, verbosity);
    try (Event{ .done = drv.drv_path }).emit(allocator, fifo);
    try build_result;
}

fn build(
    allocator: std.mem.Allocator,
    drv_path: []const u8,
    outputs: []const []const u8,
    store: []const u8,
    verbosity: nix.log.Action.Verbosity,
) !void {
    var installable = std.ArrayList(u8).init(allocator);
    defer installable.deinit();

    try installable.appendSlice(drv_path);
    try installable.append('^');
    for (outputs, 0..) |output, idx| {
        if (idx != 0) try installable.append(',');
        try installable.appendSlice(output);
    }

    std.log.debug("installable: {s}", .{installable.items});

    {
        const args = try std.mem.concat(allocator, []const u8, &.{
            nixCli(verbosity),
            &.{
                "copy",
                "--no-check-sigs",
                "--from",
                store,
                drv_path,
            },
        });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("`nix copy --from {s} {s}` failed: {}", .{ store, drv_path, term });
            return error.NixCopy;
        }
    }

    {
        const args = try std.mem.concat(allocator, []const u8, &.{
            nixCli(verbosity),
            &.{
                "build",
                "--no-link",
                "--print-build-logs",
                installable.items,
            },
        });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("`nix build {s}` failed: {}", .{ installable.items, term });
            return error.NixBuild;
        }
    }

    var output_paths = std.BufSet.init(allocator);
    defer output_paths.deinit();
    {
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &.{ "nix", "derivation", "show", installable.items },
            .max_output_bytes = 1024 * 512,
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }

        if (result.term != .Exited or result.term.Exited != 0) {
            std.log.err("`nix derivation show {s}` failed: {}\nstdout: {s}\nstderr: {s}", .{ installable.items, result.term, result.stdout, result.stderr });
            return error.NixDerivationShow;
        }

        const parsed = std.json.parseFromSlice(std.json.ArrayHashMap(struct {
            outputs: std.json.ArrayHashMap(struct { path: []const u8 }),
        }), allocator, result.stdout, .{ .ignore_unknown_fields = true }) catch |err| {
            std.log.err("{s}: Failed to parse output of `nix derivation show {s}`\nstdout: {s}\nstderr: {s}", .{ @errorName(err), installable.items, result.stdout, result.stderr });
            return err;
        };
        defer parsed.deinit();

        for (parsed.value.map.values()) |drv_info|
            for (drv_info.outputs.map.values()) |output|
                try output_paths.insert(output.path);
    }

    if (symlink_ifds_into_eval_store) {
        const dump_argv_head = &.{ "nix-store", "--dump-db" };
        var dump_argv = dump_argv: {
            var dump_argv = try std.ArrayList([]const u8).initCapacity(allocator, dump_argv_head.len + output_paths.count());
            dump_argv.appendSliceAssumeCapacity(dump_argv_head);
            break :dump_argv dump_argv;
        };
        defer dump_argv.deinit();

        {
            var output_paths_iter = output_paths.iterator();
            while (output_paths_iter.next()) |output_path| {
                try dump_argv.append(output_path.*);

                if (std.debug.runtime_safety) std.debug.assert(std.mem.startsWith(
                    u8,
                    output_path.*,
                    std.fs.path.sep_str ++ "nix" ++
                        std.fs.path.sep_str ++ "store" ++
                        std.fs.path.sep_str,
                ));

                const sym_link_path = try std.fs.path.join(allocator, &.{ store, output_path.* });
                std.log.debug("linking: {s} -> {s}", .{ sym_link_path, output_path.* });
                defer allocator.free(sym_link_path);
                try std.fs.symLinkAbsolute(output_path.*, sym_link_path, .{});
            }
        }

        std.log.debug("importing outputs into eval store: {s} <- {s}", .{ store, dump_argv.items[dump_argv_head.len..] });

        // XXX cannot pipe between the processes directly due to https://github.com/ziglang/zig/issues/7738

        const dump_result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = dump_argv.items,
            .max_output_bytes = 1024 * 512,
        });
        defer {
            allocator.free(dump_result.stdout);
            allocator.free(dump_result.stderr);
        }

        if (dump_result.term != .Exited or dump_result.term.Exited != 0) {
            std.log.err("`nix-store --dump-db` failed: {}\nstdout: {s}\nstderr: {s}", .{ dump_result.term, dump_result.stdout, dump_result.stderr });
            return error.NixStoreDumpDb;
        }

        {
            var load_process = std.process.Child.init(&.{ "nix-store", "--load-db", "--store", store }, allocator);
            load_process.stdin_behavior = .Pipe;
            load_process.stdout_behavior = .Pipe;
            load_process.stderr_behavior = .Pipe;

            try load_process.spawn();

            try load_process.stdin.?.writeAll(dump_result.stdout);
            load_process.stdin.?.close();
            load_process.stdin = null;

            var load_process_stdout = std.ArrayList(u8).init(allocator);
            defer load_process_stdout.deinit();

            var load_process_stderr = std.ArrayList(u8).init(allocator);
            defer load_process_stderr.deinit();

            try load_process.collectOutput(&load_process_stdout, &load_process_stderr, 1024 * 512);

            const load_process_term = try load_process.wait();

            if (load_process_term != .Exited or load_process_term.Exited != 0) {
                std.log.err("`nix-store --load-db` failed: {}\nstdout: {s}\nstderr: {s}", .{ load_process_term, load_process_stdout.items, load_process_stderr.items });
                return error.NixStoreLoadDb;
            }
        }
    } else {
        const args = try std.mem.concat(allocator, []const u8, &.{
            nixCli(verbosity),
            &.{
                "copy",
                "--no-check-sigs",
                "--to",
                store,
                installable.items,
            },
        });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        var env = try std.process.getEnvMap(allocator);
        defer env.deinit();
        process.env_map = &env;
        {
            const key = try allocator.dupe(u8, "NIX_HELD_LOCKS");
            errdefer allocator.free(key);

            var value = std.ArrayList(u8).init(allocator);
            errdefer value.deinit();
            {
                var iter = output_paths.iterator();
                var first = true;
                while (iter.next()) |output_path| {
                    if (first)
                        first = false
                    else
                        try value.append(':');

                    try value.appendSlice(output_path.*);
                }
            }

            std.log.debug("NIX_HELD_LOCKS={s}", .{value.items});

            try env.putMove(key, try value.toOwnedSlice());
        }

        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("`nix copy --to {s} {s}` failed: {}", .{ store, installable.items, term });
            return error.NixCopy;
        }
    }
}

fn nixCli(verbosity: nix.log.Action.Verbosity) []const []const u8 {
    const head = .{
        "nix",
        "--extra-experimental-features",
        "nix-command",
        "--log-format",
        "internal-json",
    };
    return switch (@intFromEnum(verbosity)) {
        0 => &(head ++ .{"--quiet"} ** 2),
        1 => &(head ++ .{"--quiet"}),
        2 => &head,
        inline else => |v| &(head ++ .{"-" ++ "v" ** (v - 2)}),
    };
}
