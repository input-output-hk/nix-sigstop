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

    const fifo_path, const store = builders: {
        const builders = nix_config.get("builders").?;

        const fifo_path, const store = iter: {
            var builders_iter = std.mem.splitScalar(u8, builders, std.fs.path.delimiter);
            defer if (std.debug.runtime_safety) std.debug.assert(builders_iter.next() == null);
            break :iter .{
                builders_iter.next() orelse break :iter error.NoBuilders,
                builders_iter.next() orelse break :iter error.NoBuilders,
            };
        } catch |err| switch (err) {
            error.NoBuilders => {
                log.err(
                    "expected nix config entry `builders` to have two entries separated by '{c}' but found {s}",
                    .{ std.fs.path.delimiter, builders },
                );
                return err;
            },
        };

        if (fifo_path.len == 0) {
            log.err("expected path to FIFO for IPC in nix config entry `builders` but it is empty", .{});
            return error.NoBuilders;
        }
        if (!std.fs.path.isAbsolute(fifo_path)) {
            log.err("path to FIFO for IPC is not absolute: {s}", .{fifo_path});
            return error.AccessDenied;
        }

        break :builders .{
            try allocator.dupe(u8, fifo_path),
            try allocator.dupe(u8, store),
        };
    };
    defer {
        allocator.free(fifo_path);
        allocator.free(store);
    }

    log.debug("opening FIFO for IPC", .{});
    var fifo = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
        log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
        return err;
    };
    defer fifo.close();

    // `NIX_HELD_LOCKS` only has an effect on local fs stores.
    const local_store = if (isLocalStore(store)) null else try daemonStoreAsLocalStore(allocator, store);
    defer if (local_store) |ls| allocator.free(ls);

    if (local_store) |ls| log.info(
        "assuming store `{s}` to effectively be the same as current store `{s}`",
        .{ ls, store },
    );

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
        // If the build hook accepts, we need it to copy into a local fs store
        // because `NIX_HELD_LOCKS` only works on local fs stores.
        try nix_config.put("store", local_store orelse store);

        nix_config.hash_map.lockPointers();
        defer nix_config.hash_map.unlockPointers();

        log.debug("initializing build hook", .{});
        try (nix.build_hook.Initialization{ .nix_config = nix_config }).write(hook_stdin_writer);
    }

    const drv_path = accept: while (true) {
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

                const drv_show_result = result: {
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
                    allocator.free(drv_show_result.stdout);
                    allocator.free(drv_show_result.stderr);
                }

                if (drv_show_result.term != .Exited or drv_show_result.term.Exited != 0) {
                    log.err("`nix derivation show {s}` terminated with {}", .{ drv.drv_path, drv_show_result.term });
                    return switch (drv_show_result.term) {
                        .Exited => |code| code,
                        else => 1,
                    };
                }

                // TODO parse into `std.json.ArrayHashMap` instead
                const drv_show_parsed = try std.json.parseFromSlice(std.json.Value, allocator, drv_show_result.stdout, .{});
                defer drv_show_parsed.deinit();

                const outputs_info = drv_show_parsed.value.object.get(drv.drv_path).?.object
                    .get("outputs").?.object;

                var outputs = std.ArrayListUnmanaged([]const u8){};
                defer outputs.deinit(allocator);

                try outputs.ensureUnusedCapacity(allocator, outputs_info.count());
                for (outputs_info.values()) |output_info|
                    outputs.appendAssumeCapacity(output_info.object.get("path").?.string);

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
                    process.stderr_behavior = .Close;

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

                break :accept try allocator.dupe(u8, drv.drv_path);
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
    const status = if (hook_process.wait()) |term| switch (term) {
        .Exited => |code| code: {
            if (code != 0)
                log.info("build hook exited with {d}", .{code});
            break :code code;
        },
        else => 1,
    } else |err| err;

    (root.Event{ .done = drv_path }).emit(allocator, fifo, log.scope) catch |err| {
        _ = status catch |status_err|
            log.err("{s}: failed to await build hook", .{@errorName(status_err)});

        // XXX Should be able to just `return err` but it seems that fails peer type resolution.
        // Could this be a compiler bug? This only happens if we have an `errdefer` with capture
        // in the enclosing block. In our case this is the `errdefer` that kills `hook_process`.
        return @as(utils.meta.FnErrorSet(@TypeOf(root.Event.emit))!u8, err);
    };

    return status;
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

/// Returns an equivalent local fs store for the given local daemon store if possible.
fn daemonStoreAsLocalStore(allocator: std.mem.Allocator, daemon_store: []const u8) (std.mem.Allocator.Error || utils.meta.ErrorSetExcluding(
    std.fs.Dir.AccessError,
    &.{ error.PermissionDenied, error.FileNotFound },
))!?[]const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const state_dir, const store = local: {
        const uri = std.Uri.parse(daemon_store) catch |err| switch (err) {
            error.UnexpectedCharacter, error.InvalidFormat => std.Uri.parseAfterScheme("", daemon_store) catch return null,
            error.InvalidPort => return null,
        };

        if (uri.host != null) return null;

        const path = try uri.path.toRawMaybeAlloc(arena_allocator);

        if (!(std.mem.eql(u8, uri.scheme, "unix") and path.len != 0 or
            std.mem.eql(u8, uri.scheme, "") and std.mem.eql(u8, path, "daemon")))
            return null;

        const uri_query: ?[]const u8 = if (uri.query) |query|
            try query.toRawMaybeAlloc(arena_allocator)
        else
            null;

        var state_dir: []const u8 = "/nix/var/nix";
        var root_dir: []const u8 = "/";

        if (uri_query) |query| {
            var uri_query_iter = std.mem.tokenizeScalar(u8, query, '&');
            while (uri_query_iter.next()) |param| {
                var param_iter = std.mem.splitScalar(u8, param, '=');

                const param_name = param_iter.next() orelse return null;
                const param_value = param_iter.next();

                if (std.mem.eql(u8, param_name, "state"))
                    state_dir = param_value orelse return null
                else if (std.mem.eql(u8, param_name, "root"))
                    root_dir = param_value orelse return null
                else
                    continue;

                if (param_iter.next() != null) return null;
            }
        }

        break :local .{
            try std.fs.path.join(arena_allocator, &.{ root_dir, state_dir }),
            if (uri_query) |query| try std.mem.concat(arena_allocator, u8, &.{ "local?", query }) else "local",
        };
    };

    // According to `nix help-stores`, `auto` only checks the state directory for write permission.
    if (!builtin.is_test) std.fs.accessAbsolute(state_dir, .{ .mode = .write_only }) catch |err| return switch (err) {
        error.PermissionDenied, error.FileNotFound => null,
        else => |e| e,
    };

    return try allocator.dupe(u8, store);
}

test daemonStoreAsLocalStore {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try std.testing.expectEqual(null, daemonStoreAsLocalStore(allocator, "dummy"));
    try std.testing.expectEqual(null, daemonStoreAsLocalStore(allocator, "local"));
    try std.testing.expectEqualStrings("local", (try daemonStoreAsLocalStore(allocator, "daemon")).?);
    try std.testing.expectEqualStrings("local", (try daemonStoreAsLocalStore(allocator, "unix:///nix/var/nix/daemon-socket/socket")).?);
    try std.testing.expectEqualStrings("local?root=", (try daemonStoreAsLocalStore(allocator, "daemon?root=")).?);
    try std.testing.expectEqualStrings("local?root=", (try daemonStoreAsLocalStore(allocator, "unix:///nix/var/nix/daemon-socket/socket?root=")).?);
    try std.testing.expectEqualStrings("local?root=/", (try daemonStoreAsLocalStore(allocator, "daemon?root=/")).?);
}

fn isLocalStore(store: []const u8) bool {
    return std.mem.startsWith(u8, store, "/") or
        std.mem.eql(u8, store, "local") or
        std.mem.startsWith(u8, store, "local?");
}
