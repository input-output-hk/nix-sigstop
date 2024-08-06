const std = @import("std");
const lib = @import("lib");

const nix = lib.nix;

pub const Event = union(enum) {
    start: nix.build_hook.Derivation,
    /// the corresponding `start.drv_path`
    done: []const u8,

    fn emit(self: @This(), allocator: std.mem.Allocator, fifo: std.fs.File) (std.mem.Allocator.Error || std.fs.File.LockError || std.fs.File.WriteError)!void {
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

    std.log.debug("reading nix config from environment", .{});
    const nix_config_env = nix_config_env: {
        var diagnostics: ?nix.ChildProcessDiagnostics = null;
        defer if (diagnostics) |d| d.deinit(allocator);
        break :nix_config_env nix.config(allocator, &diagnostics) catch |err| return switch (err) {
            error.CouldNotReadNixConfig => blk: {
                std.log.err("could not read nix config: {}, stderr: {s}", .{ diagnostics.?.term, diagnostics.?.stderr });
                break :blk err;
            },
            else => err,
        };
    };
    defer nix_config_env.deinit();

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

    var fifo, const build_store = fifo: {
        const builders = nix_config.get("builders").?;

        const fifo_path, const build_store = iter: {
            var builders_iter = std.mem.splitScalar(u8, builders, std.fs.path.delimiter);
            defer if (std.debug.runtime_safety) std.debug.assert(builders_iter.next() == null);
            break :iter .{
                builders_iter.next() orelse break :iter error.NoBuilders,
                builders_iter.next() orelse break :iter error.NoBuilders,
            };
        } catch |err| switch (err) {
            error.NoBuilders => {
                std.log.err(
                    "expected nix config entry `builders` to have two entries separated by '{c}' but found {s}",
                    .{ std.fs.path.delimiter, builders },
                );
                return err;
            },
        };

        if (fifo_path.len == 0) {
            std.log.err("expected path to FIFO for IPC in nix config entry `builders` but it is empty", .{});
            return error.NoBuilders;
        }
        if (!std.fs.path.isAbsolute(fifo_path)) {
            std.log.err("path to FIFO for IPC is not absolute: {s}", .{fifo_path});
            return error.AccessDenied;
        }

        if (build_store.len == 0) {
            std.log.err("expected a store for building locally in nix config entry `builders` but it is empty", .{});
            return error.NoBuilders;
        }

        std.log.debug("opening FIFO for IPC", .{});
        break :fifo .{
            std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
                std.log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
                return err;
            },
            try allocator.dupe(u8, build_store),
        };
    };
    defer {
        fifo.close();
        allocator.free(build_store);
    }

    var hook_process = hook_process: {
        var args = std.ArrayListUnmanaged([]const u8){};
        defer args.deinit(allocator);

        try args.appendSlice(allocator, nix_config_env.value.@"build-hook".value);
        {
            // Length is arbitrary but should suffice for any verbosity encountered in practice.
            var verbosity_buf: [3]u8 = undefined;
            const verbosity_str = verbosity_buf[0..std.fmt.formatIntBuf(&verbosity_buf, @intFromEnum(verbosity), 10, .lower, .{})];
            try args.append(allocator, verbosity_str);
        }

        var hook_process = std.process.Child.init(args.items, allocator);
        hook_process.stdin_behavior = .Pipe;
        hook_process.stderr_behavior = .Pipe;

        try hook_process.spawn();

        break :hook_process hook_process;
    };
    errdefer |err| _ = hook_process.kill() catch |kill_err|
        std.log.err("{s}: {s}: failed to kill build hook", .{ @errorName(err), @errorName(kill_err) });

    std.log.debug("spawned build hook. PID: {d}", .{hook_process.id});

    var hook_response_pipe_read, var hook_response_pipe_write = hook_response_pipe: {
        const pipe_read, const pipe_write = try std.posix.pipe();
        break :hook_response_pipe .{
            std.fs.File{ .handle = pipe_read },
            std.fs.File{ .handle = pipe_write },
        };
    };
    defer {
        hook_response_pipe_read.close();
        hook_response_pipe_write.close();
    }

    const hook_stderr_thread = try std.Thread.spawn(.{}, process_hook_stderr, .{
        hook_process.stderr.?.reader(),
        hook_response_pipe_write.writer(),
    });
    defer hook_stderr_thread.join();

    const hook_stdin_writer = hook_process.stdin.?.writer();

    {
        {
            const value = try std.mem.join(allocator, " ", nix_config_env.value.@"build-hook".value);
            defer allocator.free(value);

            try nix_config.put("build-hook", value);
        }
        try nix_config.put("builders", nix_config_env.value.builders.value);

        nix_config.hash_map.lockPointers();
        defer nix_config.hash_map.unlockPointers();

        std.log.debug("initializing build hook", .{});
        try (nix.build_hook.Initialization{ .nix_config = nix_config }).write(hook_stdin_writer);
    }

    const drv, const accepted = accept: while (true) {
        std.log.debug("reading derivation request", .{});
        const drv = try connection.readDerivation(allocator);
        errdefer drv.deinit(allocator);

        std.log.debug("requesting build from build hook: {s}", .{drv.drv_path});
        try (nix.build_hook.Request{ .derivation = drv }).write(hook_stdin_writer);

        std.log.debug("reading response from build hook", .{});
        const hook_response = try nix.build_hook.Response.read(allocator, hook_response_pipe_read.reader());
        defer hook_response.deinit(allocator);

        switch (hook_response) {
            .postpone, .accept => {
                std.log.debug("forwarding response from build hook to Nix: {s}", .{@tagName(std.meta.activeTag(hook_response))});
                try hook_response.write(connection.writer);

                switch (hook_response) {
                    .postpone => drv.deinit(allocator),
                    .accept => break :accept .{ drv, true },
                    .decline, .decline_permanently => unreachable,
                }
            },
            .decline, .decline_permanently => break :accept .{ drv, false },
        }
    };
    defer drv.deinit(allocator);

    try (Event{ .start = drv }).emit(allocator, fifo);

    const handle_error_union = handle_hook_final_response(
        allocator,
        if (accepted) .accepted else .{ .declined = drv },
        &hook_process,
        &connection,
        build_store,
        nix_config.get("store").?,
        verbosity,
    );

    (Event{ .done = drv.drv_path }).emit(allocator, fifo) catch |err| {
        handle_error_union catch |handle_err|
            std.log.err("{s}: failed to handle final hook response", .{@errorName(handle_err)});

        // XXX Should be able to just `return err` but it seems that fails peer type resolution.
        // Could this be a compiler bug? This only happens if we have an `errdefer` with capture
        // in the enclosing block. In our case this is the `errdefer` that kills `hook_process`.
        return @as(@typeInfo(@TypeOf(Event.emit)).Fn.return_type.?, err);
    };

    try handle_error_union;
}

fn process_hook_stderr(stderr_reader: anytype, protocol_writer: anytype) !void {
    var log_stream = nix.log.logStream(stderr_reader, protocol_writer);
    const log_reader = log_stream.reader();

    while (true) {
        // Capacity is arbitrary but should suffice for any lines encountered in practice.
        var log_buf = std.BoundedArray(u8, 1024 * 512){};

        // The build hook and logging protocols are line-based.
        log_reader.streamUntilDelimiter(log_buf.writer(), '\n', log_buf.capacity() + 1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        std.debug.getStderrMutex().lock();
        defer std.debug.getStderrMutex().unlock();

        const stderr_writer = std.io.getStdErr().writer();

        try stderr_writer.writeAll(log_buf.constSlice());
        try stderr_writer.writeByte('\n');
    }

    std.log.debug("build hook closed stderr", .{});
}

fn handle_hook_final_response(
    allocator: std.mem.Allocator,
    final_response: union(enum) {
        accepted,
        declined: nix.build_hook.Derivation,
    },
    hook_process: *std.process.Child,
    connection: *nix.build_hook.Connection(std.fs.File.Reader, std.fs.File.Writer),
    build_store: []const u8,
    store: []const u8,
    verbosity: nix.log.Action.Verbosity,
) !void {
    {
        std.log.debug("waiting for build hook to exit", .{});
        const term = try hook_process.wait();
        if (term != .Exited or term.Exited != 0) {
            std.log.info("build hook terminated with {}", .{term});
            return error.NixBuildHook;
        }
    }

    const drv = switch (final_response) {
        .accepted => return,
        .declined => |drv| drv,
    };

    const build_io = try connection.accept(allocator, build_store);
    defer build_io.deinit(allocator);

    try build(allocator, drv.drv_path, build_io.wanted_outputs, build_store, store, verbosity);
}

fn build(
    allocator: std.mem.Allocator,
    drv_path: []const u8,
    outputs: []const []const u8,
    build_store: []const u8,
    target_store: []const u8,
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
                target_store,
                "--to",
                build_store,
                drv_path,
            },
        });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("`nix copy --from {s} --to {s} {s}` failed: {}", .{ target_store, build_store, drv_path, term });
            return error.NixCopyTo;
        }
    }

    {
        const args = try std.mem.concat(allocator, []const u8, &.{
            nixCli(verbosity),
            &.{
                "build",
                "--no-link",
                "--print-build-logs",
                "--store",
                build_store,
                installable.items,
            },
        });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("`nix build --store {s} {s}` failed: {}", .{ build_store, installable.items, term });
            if (build_store[0] == std.fs.path.sep) std.log.warn(
                \\{s} looks like a chroot store.
                \\Please ensure I have read and execute permission on all parent directories.
                \\See https://github.com/NixOS/nixpkgs/pull/90431 for more information.
            , .{build_store});
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

    {
        const args = try std.mem.concat(allocator, []const u8, &.{
            nixCli(verbosity),
            &.{
                "copy",
                "--no-check-sigs",
                "--from",
                build_store,
                "--to",
                target_store,
                installable.items, // XXX pass `output_paths` instead as that may be less work for Nix to figure out the actual store paths from the installable
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
            std.log.err("`nix copy --from {s} --to {s} {s}` failed: {}", .{ build_store, target_store, installable.items, term });
            return error.NixCopyFrom;
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
