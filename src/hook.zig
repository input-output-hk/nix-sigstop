const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

const nix = utils.nix;
const posix = utils.posix;

const root = if (builtin.is_test) @import("main.zig") else @import("root");

const log = utils.log.scoped(.hook);

pub fn main(allocator: std.mem.Allocator, nix_config_env: nix.Config) !u8 {
    const verbosity = verbosity: {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();

        break :verbosity try nix.build_hook.parseArgs(&args);
    };
    log.debug("log verbosity: {s}", .{@tagName(verbosity)});

    var nix_config, var connection = try nix.build_hook.start(allocator);
    defer nix_config.deinit();

    if (log.scopeLogEnabled(.debug)) {
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

        log.debug("nix config:\n{s}", .{nix_config_msg.items});
    }

    const fifo_path = try allocator.dupe(u8, nix_config.get("builders").?);
    defer allocator.free(fifo_path);

    if (fifo_path.len == 0) {
        log.err("expected path to FIFO for IPC in nix config entry `builders` but it is empty", .{});
        return error.NoBuilders;
    }
    if (!std.fs.path.isAbsolute(fifo_path)) {
        log.err("path to FIFO for IPC is not absolute: {s}", .{fifo_path});
        return error.AccessDenied;
    }

    log.debug("opening FIFO for IPC", .{});
    var fifo = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
        log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
        return err;
    };
    defer fifo.close();

    var hook_process = hook_process: {
        var args = std.ArrayListUnmanaged([]const u8){};
        defer args.deinit(allocator);

        try args.appendSlice(allocator, nix_config_env.@"build-hook".value);
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
    var hook_stderr_thread: ?std.Thread = null;
    errdefer |err| {
        _ = hook_process.kill() catch |kill_err| {
            log.err("{s}: {s}: failed to kill build hook", .{ @errorName(err), @errorName(kill_err) });

            if (hook_stderr_thread) |t| t.detach();
        };

        if (hook_stderr_thread) |t| t.join();
    }

    log.debug("spawned build hook. PID: {d}", .{hook_process.id});

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

    hook_stderr_thread = try std.Thread.spawn(.{}, processHookStderr, .{
        (posix.PollingStream(.fd){ .handle = hook_process.stderr.?.handle }).reader(),
        hook_response_pipe_write.writer(),
    });
    hook_stderr_thread.?.setName(utils.mem.capConst(u8, "hook stderr", std.Thread.max_name_len, .end)) catch |err|
        log.debug("{s}: failed to set thread name", .{@errorName(err)});

    const hook_stdin_writer = hook_process.stdin.?.writer();

    {
        {
            const value = try std.mem.join(allocator, " ", nix_config_env.@"build-hook".value);
            defer allocator.free(value);

            try nix_config.put("build-hook", value);
        }
        try nix_config.put("builders", nix_config_env.builders.value);

        nix_config.hash_map.lockPointers();
        defer nix_config.hash_map.unlockPointers();

        log.debug("initializing build hook", .{});
        try (nix.build_hook.Initialization{ .nix_config = nix_config }).write(hook_stdin_writer);
    }

    const accepted, const drv_path = accept: while (true) {
        log.debug("reading derivation request", .{});
        const drv = try connection.readDerivation(allocator);
        defer drv.deinit(allocator);

        log.debug("requesting build from build hook: {s}", .{drv.drv_path});
        try (nix.build_hook.Request{ .derivation = drv }).write(hook_stdin_writer);

        log.debug("reading response from build hook", .{});
        const hook_response = try nix.build_hook.Response.read(allocator, hook_response_pipe_read.reader());
        defer hook_response.deinit(allocator);

        log.debug("build hook responded with \"{s}\"", .{@tagName(std.meta.activeTag(hook_response))});

        switch (hook_response) {
            .postpone => try connection.postpone(),
            .decline, .decline_permanently => {
                // XXX Cache `decline_permanently` so that we don't have
                // to ask the build hook for the remaining derivations.

                // Since we don't accept the build we don't get the wanted output paths,
                // so query them instead, assuming we need to build them all.
                const result = result: {
                    const args = try std.mem.concat(allocator, []const u8, &.{
                        nixCli(verbosity),
                        &.{
                            "derivation",
                            "show",
                            drv.drv_path,
                        },
                    });
                    defer allocator.free(args);

                    break :result try std.process.Child.run(.{
                        .allocator = allocator,
                        .argv = args,
                    });
                };
                defer {
                    allocator.free(result.stdout);
                    allocator.free(result.stderr);
                }

                if (result.term != .Exited or result.term.Exited != 0) {
                    log.err("`nix derivation show {s}` terminated with {}", .{ drv.drv_path, result.term });
                    return switch (result.term) {
                        .Exited => |code| code,
                        else => 1,
                    };
                }

                const drv_show = try std.json.parseFromSlice(std.json.Value, allocator, result.stdout, .{
                    .ignore_unknown_fields = true,
                });
                defer drv_show.deinit();

                var outputs = std.ArrayListUnmanaged([]const u8){};
                defer outputs.deinit(allocator);

                {
                    const drv_info = drv_show.value.object.get(drv.drv_path).?.object;

                    const outputs_info = drv_info.get("outputs").?.object.values();

                    try outputs.ensureUnusedCapacity(allocator, outputs_info.len);
                    for (outputs_info) |output_info|
                        outputs.appendAssumeCapacity(output_info.object.get("path").?.string);
                }

                try (root.Event{ .start = drv }).emit(allocator, fifo, log.scope);

                {
                    const args = try std.mem.concat(allocator, []const u8, &.{
                        &.{
                            self_exe: {
                                var self_exe_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                                break :self_exe try std.fs.selfExePath(&self_exe_buf);
                            },
                            root.notifier_arg,
                            fifo_path,
                            drv.drv_path,
                        },
                        outputs.items,
                    });
                    defer allocator.free(args);

                    var process = std.process.Child.init(args, allocator);
                    process.stdin_behavior = .Close;
                    process.stdout_behavior = .Close;
                    process.stderr_behavior = .Ignore;

                    log.debug("spawning build notifier process for {s}", .{drv.drv_path});
                    const term = try process.spawnAndWait();
                    if (term != .Exited or term.Exited != 0) {
                        log.err("failed to spawn build notifier process, terminated with {}", .{term});
                        return error.BuildNotifier;
                    }
                }

                try connection.decline();
            },
            .accept => |remote_store| {
                const build_io = try connection.accept(allocator, remote_store);
                defer build_io.deinit(allocator);

                try nix.wire.writeStruct(nix.build_hook.BuildIo, hook_stdin_writer, build_io);

                try (root.Event{ .start = drv }).emit(allocator, fifo, log.scope);

                break :accept .{ true, try allocator.dupe(u8, drv.drv_path) };
            },
        }
    };
    defer allocator.free(drv_path);

    log.debug("waiting for build hook to close its stderr", .{});
    // `hook_stderr_thread` polls and waits until
    // `hook_process` closes the write end of its stderr pipe.
    // We must wait for that before calling `hook_process.wait()`
    // because that closes the read end of the stderr pipe
    // and we must not do that while `hook_stderr_thread` is still using it.
    hook_stderr_thread.?.join();

    log.debug("waiting for build hook to exit", .{});
    const term = try hook_process.wait();
    if (term != .Exited or term.Exited != 0) {
        log.info("build hook terminated with {}", .{term});
        return switch (term) {
            .Exited => |code| code,
            else => 1,
        };
    }

    if (accepted)
        try (root.Event{ .done = drv_path }).emit(allocator, fifo, log.scope);

    return 0;
}

fn processHookStderr(stderr_reader: anytype, protocol_writer: anytype) !void {
    errdefer |err| std.debug.panic("{s}: error processing build hook's stderr", .{@errorName(err)});

    var stderr_buffered = std.io.bufferedReader(stderr_reader);

    var log_stream = nix.log.logStream(stderr_buffered.reader(), protocol_writer);
    const log_reader = log_stream.reader();

    while (true) {
        // Capacity is arbitrary but should suffice for any lines encountered in practice.
        var log_line_buf = std.BoundedArray(u8, utils.mem.b_per_mib / 2){};

        log.debug("waiting for a log line from the build hook", .{});

        // The build hook and logging protocols are line-based.
        log_reader.streamUntilDelimiter(log_line_buf.writer(), '\n', log_line_buf.capacity() + 1) catch |err| switch (err) {
            error.NotOpenForReading, error.EndOfStream => break,
            error.StreamTooLong => std.debug.panic("bug: buffer for hook log line is too small", .{}),
            // XXX Should be able to just `return err` but it seems that fails peer type resolution.
            // Could this be a compiler bug? This only happens if we have an `errdefer` with capture
            // in the enclosing block. In our case this is the `errdefer` that panics.
            else => |e| return @as((@TypeOf(log_reader).Error || @TypeOf(log_line_buf).Writer.Error)!void, e),
        };

        log.debug("forwarding a log line of {d} bytes from the build hook", .{log_line_buf.len});

        var buffered_stderr_writer = std.io.bufferedWriter(std.io.getStdErr().writer());
        const stderr_writer = buffered_stderr_writer.writer();

        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        nosuspend {
            try stderr_writer.writeAll(log_line_buf.constSlice());
            try stderr_writer.writeByte('\n');

            try buffered_stderr_writer.flush();
        }
    }

    log.debug("build hook closed stderr", .{});
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
