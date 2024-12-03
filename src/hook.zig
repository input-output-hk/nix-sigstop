const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

const nix = utils.nix;
const posix = utils.posix;

const root = if (builtin.is_test) @import("main.zig") else @import("root");

const notifier = @import("notifier.zig");

const log = utils.log.scoped(.hook);

pub fn main(allocator: std.mem.Allocator, nix_config_env: nix.Config) !u8 {
    return switch (try hook(allocator, nix_config_env)) {
        .exit => |status| status,
        .notify => |args| notify: {
            errdefer comptime unreachable;

            defer {
                for (args.output_lockfile_paths) |output_lockfile_path|
                    allocator.free(output_lockfile_path);
                allocator.free(args.output_lockfile_paths);

                allocator.free(args.drv_path);

                args.fifo.close();
            }

            notifier.main(args.fifo, args.drv_path, args.output_lockfile_paths);

            break :notify 0;
        },
    };
}

const NotifierArgs = utils.meta.NamedArgs(
    @TypeOf(notifier.main),
    &.{ "fifo", "drv_path", "output_lockfile_paths" },
);

fn hook(allocator: std.mem.Allocator, nix_config_env: nix.Config) !union(enum) {
    exit: u8,
    notify: NotifierArgs,
} {
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

    while (true) {
        log.debug("reading derivation request", .{});
        const drv = try connection.readDerivation(allocator);
        defer drv.deinit(allocator);

        log.debug("requesting build from build hook: {s}", .{drv.drv_path});
        try (nix.build_hook.Request{ .derivation = drv }).write(hook_stdin_writer);

        log.debug("reading response from build hook", .{});
        const hook_response = try nix.build_hook.Response.read(allocator, hook_response_pipe_read.reader());
        defer hook_response.deinit(allocator);

        log.debug("build hook responded with \"{s}\"", .{@tagName(hook_response)});

        switch (hook_response) {
            .postpone => try connection.postpone(),
            // XXX Cache `decline_permanently` so that we don't have
            // to ask the build hook for the remaining derivations.
            .decline, .decline_permanently => switch (try daemonizeToBecomeBuildNotifier(allocator, verbosity, fifo_path, drv, null)) {
                .exit => |caller| switch (caller) {
                    .parent => try connection.decline(),
                    .intermediate => return .{ .exit = 0 },
                },
                .notify => |notify| return .{ .notify = notify },
            },
            .accept => |remote_store| {
                const build_io = try connection.accept(allocator, remote_store);
                defer build_io.deinit(allocator);

                try nix.wire.writeStruct(nix.build_hook.BuildIo, hook_stdin_writer, build_io);

                switch (try daemonizeToBecomeBuildNotifier(allocator, verbosity, fifo_path, drv, build_io.wanted_outputs)) {
                    .exit => |caller| switch (caller) {
                        .parent => break,
                        .intermediate =>
                        // It is important that the intermediate returns
                        // so that it does not attempt to join `hook_stderr_thread`
                        // which the first parent is already doing, leading to a deadlock!
                        return .{ .exit = 0 },
                    },
                    .notify => |notify| return .{ .notify = notify },
                }
            },
        }
    }

    log.debug("waiting for build hook to close its stderr", .{});
    // `hook_stderr_thread` polls and waits until
    // `hook_process` closes the write end of its stderr pipe.
    // We must wait for that before calling `hook_process.wait()`
    // because that closes the read end of the stderr pipe
    // and we must not do that while `hook_stderr_thread` is still using it.
    hook_stderr_thread.?.join();

    return .{
        .exit = exit: {
            log.debug("waiting for build hook to exit", .{});
            const term = try hook_process.wait();
            break :exit if (term != .Exited or term.Exited != 0) status: {
                log.info(
                    "build hook terminated: {s} {d}",
                    .{
                        @tagName(term),
                        switch (term) {
                            inline else => |code| code,
                        },
                    },
                );
                break :status 1;
            } else term.Exited;
        },
    };
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

const DaemonizeParent = utils.enums.Sub(
    @typeInfo(@typeInfo(@TypeOf(posix.daemonize(false))).ErrorUnion.payload).Union.tag_type.?,
    &.{ .parent, .intermediate },
);

/// Prepares arguments needed for `notifier.main()` and forks off a daemon.
/// Returns null if the caller is the parent or
/// returns the notifier arguments if the caller is the daemon.
/// The parent likely wants to exit cleanly by returning from main
/// so all its deferred blocks are run to release all resources.
fn daemonizeToBecomeBuildNotifier(
    allocator: std.mem.Allocator,
    verbosity: nix.log.Action.Verbosity,
    fifo_path: []const u8,
    drv: nix.build_hook.Derivation,
    wanted_outputs: ?[]const []const u8,
) !union(enum) {
    exit: DaemonizeParent,
    notify: NotifierArgs,
} {
    var free = true;

    const output_lockfile_paths = try derivationOutputLockfilePaths(allocator, verbosity, drv.drv_path, wanted_outputs);
    defer if (free) {
        for (output_lockfile_paths) |output_lockfile_path|
            allocator.free(output_lockfile_path);
        allocator.free(output_lockfile_paths);
    };

    const drv_path = try allocator.dupe(u8, drv.drv_path);
    defer if (free) allocator.free(drv_path);

    return switch (posix.daemonize(true) catch |err| {
        log.err("{s}: failed to daemonize", .{@errorName(err)});
        // XXX Should be able to just `return err` but it seems that fails peer type resolution.
        // Could this be a compiler bug? This only happens if we have an `errdefer` with capture
        // in the enclosing block. In our case this is the `errdefer` that sends the done event.
        return @as(posix.DaemonizeError(true)!utils.meta.FnErrorUnionPayload(@TypeOf(daemonizeToBecomeBuildNotifier)), err);
    }) {
        .parent => |daemon_pid| parent: {
            log.info("spawned build notifier daemon with PID {d} for {s}", .{ daemon_pid, drv.drv_path });
            break :parent .{ .exit = .parent };
        },
        inline .intermediate, .daemon => |_, caller| caller: {
            // We cannot log in the intermediate child and daemon
            // because the stderr mutex that the log function uses
            // is not shared across forked processes,
            // leading to intermingled log messages
            // that the nix daemon cannot parse.
            // Close stdio, especially stderr, to ensure an error upon logging attempts
            // instead of sending intermingled messages to the nix daemon.
            std.io.getStdIn().close();
            std.io.getStdOut().close();
            std.io.getStdErr().close();

            break :caller switch (caller) {
                .parent => comptime unreachable,
                .intermediate => .{ .exit = .intermediate },
                .daemon => daemon: {
                    root.globals = .build_notifier;

                    free = false;
                    errdefer free = true;

                    var fifo = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err|
                        std.debug.panic("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
                    errdefer fifo.close();

                    try (root.Event{ .start = drv }).emit(fifo);
                    errdefer |err| (root.Event{ .done = drv.drv_path }).emit(fifo) catch |emit_err|
                        std.debug.panic("{s}: failed to emit done event on error: {s}", .{ @errorName(emit_err), @errorName(err) });

                    break :daemon .{ .notify = .{
                        .fifo = fifo,
                        .drv_path = drv_path,
                        .output_lockfile_paths = output_lockfile_paths,
                    } };
                },
            };
        },
    };
}

fn derivationOutputLockfilePaths(
    allocator: std.mem.Allocator,
    verbosity: nix.log.Action.Verbosity,
    drv_path: []const u8,
    wanted_outputs: ?[]const []const u8,
) ![]const []const u8 {
    const drv_show_result = result: {
        const args = try std.mem.concat(allocator, []const u8, &.{
            nixCli(verbosity),
            &.{
                "derivation",
                "show",
                drv_path,
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
        log.err("`nix derivation show {s}` terminated with {}", .{ drv_path, drv_show_result.term });
        return error.NixDerivationShow;
    }

    const drv_show_parsed = try std.json.parseFromSlice(std.json.ArrayHashMap(struct {
        outputs: std.json.ArrayHashMap(struct {
            path: []const u8,
        }),
    }), allocator, drv_show_result.stdout, .{
        .ignore_unknown_fields = true,
    });
    defer drv_show_parsed.deinit();

    std.debug.assert(drv_show_parsed.value.map.count() == 1);
    const outputs_info = drv_show_parsed.value.map.get(drv_path).?
        .outputs.map;

    var output_lockfile_paths = try std.ArrayListUnmanaged([]const u8).initCapacity(
        allocator,
        if (wanted_outputs) |w_os|
            w_os.len
        else
            outputs_info.count(),
    );
    errdefer {
        for (output_lockfile_paths.items) |output_lockfile_path|
            allocator.free(output_lockfile_path);
        output_lockfile_paths.deinit(allocator);
    }

    if (wanted_outputs) |w_os| {
        for (w_os) |wanted_output| {
            const output_lockfile_path = try std.mem.concat(allocator, u8, &.{ outputs_info.get(wanted_output).?.path, ".lock" });
            errdefer allocator.free(output_lockfile_path);

            output_lockfile_paths.appendAssumeCapacity(output_lockfile_path);
        }
    } else for (outputs_info.values()) |output_info| {
        const output_lockfile_path = try std.mem.concat(allocator, u8, &.{ output_info.path, ".lock" });
        errdefer allocator.free(output_lockfile_path);

        output_lockfile_paths.appendAssumeCapacity(output_lockfile_path);
    }

    return output_lockfile_paths.toOwnedSlice(allocator);
}

fn nixCli(verbosity: nix.log.Action.Verbosity) []const []const u8 {
    return verbosity.comptimeCli(true, .{
        "nix",
        "--extra-experimental-features",
        "nix-command",
        "--log-format",
        "internal-json",
    }, .{});
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
