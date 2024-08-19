const builtin = @import("builtin");
const std = @import("std");
const lib = @import("lib");

const nix = lib.nix;

const log = lib.log.scoped(.hook);

pub const Event = union(enum) {
    start: nix.build_hook.Derivation,
    /// the corresponding `start.drv_path`
    done: []const u8,

    fn emit(self: @This(), allocator: std.mem.Allocator, fifo: std.fs.File) (std.mem.Allocator.Error || std.fs.File.LockError || std.fs.File.WriteError)!void {
        try fifo.lock(.exclusive);
        defer fifo.unlock();

        const fifo_writer = fifo.writer();

        if (log.scopeLogEnabled(.debug)) {
            const json = try std.json.stringifyAlloc(allocator, self, .{});
            defer allocator.free(json);

            log.debug("emitting IPC event: {s}", .{json});

            try fifo_writer.writeAll(json);
        } else try std.json.stringify(self, .{}, fifo_writer);

        try fifo_writer.writeByte('\n');
    }
};

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

    var fifo, const build_store, const target_store = builders: {
        const builders = nix_config.get("builders").?;

        const fifo_path, const build_store, const target_store = iter: {
            var builders_iter = std.mem.splitScalar(u8, builders, std.fs.path.delimiter);
            defer if (std.debug.runtime_safety) std.debug.assert(builders_iter.next() == null);
            break :iter .{
                builders_iter.next() orelse break :iter error.NoBuilders,
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

        if (build_store.len == 0) {
            log.err("expected a store for building locally in nix config entry `builders` but it is empty", .{});
            return error.NoBuilders;
        }

        log.debug("opening FIFO for IPC", .{});
        break :builders .{
            std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
                log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
                return err;
            },
            try allocator.dupe(u8, build_store),
            try allocator.dupe(u8, target_store),
        };
    };
    defer {
        fifo.close();
        allocator.free(build_store);
        allocator.free(target_store);
    }

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
    errdefer |err| _ = hook_process.kill() catch |kill_err|
        log.err("{s}: {s}: failed to kill build hook", .{ @errorName(err), @errorName(kill_err) });

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

    const hook_stderr_thread = try std.Thread.spawn(.{}, process_hook_stderr, .{
        hook_process.stderr.?.reader(),
        hook_response_pipe_write.writer(),
    });
    hook_stderr_thread.setName(lib.mem.capConst(u8, "hook stderr", std.Thread.max_name_len, .end)) catch |err|
        log.debug("{s}: failed to set thread name", .{@errorName(err)});
    defer hook_stderr_thread.join();

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

    const drv, const build_io, const accepted = accept: while (true) {
        log.debug("reading derivation request", .{});
        const drv = try connection.readDerivation(allocator);
        errdefer drv.deinit(allocator);

        log.debug("requesting build from build hook: {s}", .{drv.drv_path});
        try (nix.build_hook.Request{ .derivation = drv }).write(hook_stdin_writer);

        log.debug("reading response from build hook", .{});
        const hook_response = try nix.build_hook.Response.read(allocator, hook_response_pipe_read.reader());
        defer hook_response.deinit(allocator);

        log.debug("build hook responded with \"{s}\"", .{@tagName(std.meta.activeTag(hook_response))});

        switch (hook_response) {
            .postpone => {
                try connection.postpone();

                drv.deinit(allocator);
            },
            .accept => |remote_store| {
                log.debug("building remotely in {s}", .{remote_store});

                const build_io = try connection.accept(allocator, remote_store);
                errdefer build_io.deinit(allocator);

                try nix.wire.writeStruct(nix.build_hook.BuildIo, hook_stdin_writer, build_io);

                break :accept .{ drv, build_io, true };
            },
            .decline, .decline_permanently => {
                // XXX Cache `decline_permanently` so that we don't have
                // to ask the build hook for the remaining derivations.

                log.debug("building locally in {s}", .{build_store});

                break :accept .{
                    drv,
                    try connection.accept(allocator, build_store),
                    false,
                };
            },
        }
    };
    defer {
        drv.deinit(allocator);
        build_io.deinit(allocator);
    }

    try (Event{ .start = drv }).emit(allocator, fifo);

    const status = status: {
        log.debug("waiting for build hook to exit", .{});
        if (hook_process.wait()) |term| {
            if (term != .Exited or term.Exited != 0) {
                log.info("build hook terminated with {}", .{term});
                break :status switch (term) {
                    .Exited => |code| code,
                    else => 1,
                };
            }
        } else |err| break :status err;

        if (!accepted) build(
            allocator,
            drv.drv_path,
            build_io.wanted_outputs,
            build_store,
            nix_config.get("store").?,
            verbosity,
        ) catch |err| break :status err;

        break :status 0;
    };

    (Event{ .done = drv.drv_path }).emit(allocator, fifo) catch |err| {
        _ = status catch |status_err|
            log.err("{s}: failed to handle final hook response", .{@errorName(status_err)});

        // XXX Should be able to just `return err` but it seems that fails peer type resolution.
        // Could this be a compiler bug? This only happens if we have an `errdefer` with capture
        // in the enclosing block. In our case this is the `errdefer` that kills `hook_process`.
        return @as(lib.meta.FnErrorSet(@TypeOf(Event.emit))!u8, err);
    };

    return status;
}

fn process_hook_stderr(stderr_reader: anytype, protocol_writer: anytype) !void {
    var log_stream = nix.log.logStream(stderr_reader, protocol_writer);
    const log_reader = log_stream.reader();

    while (true) {
        // Capacity is arbitrary but should suffice for any lines encountered in practice.
        var log_buf = std.BoundedArray(u8, 1024 * 512){};

        log.debug("waiting for a log line from the build hook", .{});

        // The build hook and logging protocols are line-based.
        log_reader.streamUntilDelimiter(log_buf.writer(), '\n', log_buf.capacity() + 1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        log.debug("forwarding a log line of {d} bytes from the build hook", .{log_buf.len});

        std.debug.getStderrMutex().lock();
        defer std.debug.getStderrMutex().unlock();

        const stderr_writer = std.io.getStdErr().writer();

        try stderr_writer.writeAll(log_buf.constSlice());
        try stderr_writer.writeByte('\n');
    }

    log.debug("build hook closed stderr", .{});
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

    log.info("building {s}", .{installable.items});

    {
        const cli = &.{
            "copy",
            "--no-check-sigs",
            "--from",
            target_store,
            "--to",
            build_store,
            drv_path,
        };

        const args = try std.mem.concat(allocator, []const u8, &.{ nixCli(verbosity), cli });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        log.debug("running `nix {s}`", .{lib.fmt.fmtJoin(" ", cli)});
        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            log.err("`nix {s}` failed: {}", .{ lib.fmt.fmtJoin(" ", cli), term });
            return error.NixCopyTo;
        }
    }

    {
        const cli = &.{
            "build",
            "--no-link",
            "--print-build-logs",
            "--store",
            build_store,
            installable.items,
        };

        const args = try std.mem.concat(allocator, []const u8, &.{ nixCli(verbosity), cli });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        log.debug("running `nix {s}`", .{lib.fmt.fmtJoin(" ", cli)});
        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            log.err("`nix {s}` failed: {}", .{ lib.fmt.fmtJoin(" ", cli), term });
            if (build_store[0] == std.fs.path.sep) log.warn(
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
        const args = &.{ "nix", "derivation", "show", installable.items };

        log.debug("running `{s}`", .{lib.fmt.fmtJoin(" ", args)});
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = args,
            .max_output_bytes = 1024 * 512,
        });
        defer {
            allocator.free(result.stdout);
            allocator.free(result.stderr);
        }

        if (result.term != .Exited or result.term.Exited != 0) {
            log.err("`{s}` failed: {}\nstdout: {s}\nstderr: {s}", .{ lib.fmt.fmtJoin(" ", args), result.term, result.stdout, result.stderr });
            return error.NixDerivationShow;
        }

        const parsed = std.json.parseFromSlice(std.json.ArrayHashMap(struct {
            outputs: std.json.ArrayHashMap(struct { path: []const u8 }),
        }), allocator, result.stdout, .{ .ignore_unknown_fields = true }) catch |err| {
            log.err("{s}: failed to parse output of `{s}`\nstdout: {s}\nstderr: {s}", .{ @errorName(err), lib.fmt.fmtJoin(" ", args), result.stdout, result.stderr });
            return err;
        };
        defer parsed.deinit();

        for (parsed.value.map.values()) |drv_info|
            for (drv_info.outputs.map.values()) |output|
                try output_paths.insert(output.path);
    }

    {
        // `NIX_HELD_LOCKS` only has an effect on the `nix copy` command with local fs stores.
        const local_target_store = if (isLocalStore(target_store)) null else try daemonStoreAsLocalStore(allocator, target_store);
        defer if (local_target_store) |lts| allocator.free(lts);

        if (local_target_store) |lts| log.info(
            "assuming store `{s}` to effectively be the same as current store `{s}` so that we can copy {s} into it",
            .{ lts, target_store, installable.items },
        );

        const cli = &.{
            "copy",
            "--no-check-sigs",
            "--from",
            build_store,
            "--to",
            local_target_store orelse target_store,
            installable.items, // XXX pass `output_paths` instead as that may be less work for Nix to figure out the actual store paths from the installable
        };

        const args = try std.mem.concat(allocator, []const u8, &.{ nixCli(verbosity), cli });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        const key_nix_held_locks = "NIX_HELD_LOCKS";

        var env = try std.process.getEnvMap(allocator);
        defer env.deinit();
        process.env_map = &env;
        {
            const key = try allocator.dupe(u8, key_nix_held_locks);
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

            try env.putMove(key, try value.toOwnedSlice());
        }

        const format = "`{s}={s} nix {s}`";
        const format_args = .{ key_nix_held_locks, env.get(key_nix_held_locks).?, lib.fmt.fmtJoin(" ", cli) };

        log.debug("running " ++ format, format_args);
        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            log.err(format ++ " failed: {}", format_args ++ .{term});
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

/// Returns an equivalent local fs store for the given local daemon store if possible.
fn daemonStoreAsLocalStore(allocator: std.mem.Allocator, daemon_store: []const u8) (std.mem.Allocator.Error || lib.meta.ErrorSetExcluding(
    std.fs.Dir.AccessError,
    &.{ error.PermissionDenied, error.FileNotFound },
))!?[]const u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    const state, const store = local: {
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

        var state: []const u8 = "/nix/var/nix";
        var root: []const u8 = "/";

        if (uri_query) |query| {
            var uri_query_iter = std.mem.tokenizeScalar(u8, query, '&');
            while (uri_query_iter.next()) |param| {
                var param_iter = std.mem.splitScalar(u8, param, '=');

                const param_name = param_iter.next() orelse return null;
                const param_value = param_iter.next();

                if (std.mem.eql(u8, param_name, "state"))
                    state = param_value orelse return null
                else if (std.mem.eql(u8, param_name, "root"))
                    root = param_value orelse return null
                else
                    continue;

                if (param_iter.next() != null) return null;
            }
        }

        break :local .{
            try std.fs.path.join(arena_allocator, &.{ root, state }),
            if (uri_query) |query| try std.mem.concat(arena_allocator, u8, &.{ "local?", query }) else "local",
        };
    };

    // According to `nix help-stores`, `auto` only checks the state directory for write permission.
    if (!builtin.is_test) std.fs.accessAbsolute(state, .{ .mode = .write_only }) catch |err| return switch (err) {
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
