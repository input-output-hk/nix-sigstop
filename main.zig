const std = @import("std");
const known_folders = @import("known-folders");
const lib = @import("lib");

const nix = lib.nix;

pub const std_options = .{
    .logFn = struct {
        fn logFn(comptime message_level: std.log.Level, comptime scope: @Type(.EnumLiteral), comptime format: []const u8, args: anytype) void {
            switch (globals) {
                .wrapper => std.log.defaultLog(message_level, scope, format, args),
                .build_hook => nix.log.logFn(message_level, scope, format, args),
            }
        }
    }.logFn,
};

const hook_arg = "__build-hook";

/// Symlink build outputs into the eval store to save disk space.
/// Only works if the eval store is a chroot store!
const symlink_ifds_into_eval_store = true;

var globals: union(enum) {
    /// The PID of the nix client process.
    wrapper: ?std.process.Child.Id,
    build_hook,
} = .{ .wrapper = null };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.log.err("leaked memory", .{});
    const allocator = gpa.allocator();

    if (build_hook: {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();

        std.debug.assert(args.next() != null);

        break :build_hook if (args.next()) |arg1|
            std.mem.eql(u8, arg1, hook_arg)
        else
            false;
    }) {
        globals = .build_hook;
        return buildHook(allocator);
    }

    {
        const sa = std.posix.Sigaction{
            .handler = .{
                .handler = struct {
                    fn handler(sig: c_int) callconv(.C) void {
                        // Instead of just exiting upon receiving the signal,
                        // we want to have the nix client process exit
                        // so that we properly clean up all resources
                        // the normal way via `defer` statements
                        // after waiting on it at the end of `main()`.

                        if (globals.wrapper) |nix_process_id| {
                            // We need to send `SIGCONT` so that the nix client process can actually handle the following signal.
                            std.posix.kill(nix_process_id, std.posix.SIG.CONT) catch |err|
                                std.log.err("{s}: failed to send SIGCONT to nix client process in order to propagate signal {d}", .{ @errorName(err), sig });

                            // In this handler, we don't know whether the signal
                            // was sent to only our own PID or the entire process group.
                            // It should not hurt to send the signal again
                            // so let's just propagate it to be sure.
                            std.posix.kill(nix_process_id, @intCast(sig)) catch |err|
                                std.log.err("{s}: failed to propagate signal {d} to nix client process", .{ @errorName(err), sig });
                        }
                    }
                }.handler,
            },
            .mask = std.posix.empty_sigset,
            .flags = std.posix.SA.RESETHAND,
        };
        try std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
        try std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    }

    const state_dir_path = if (try known_folders.getPath(allocator, .data)) |known_folder_path| state_dir_path: {
        defer allocator.free(known_folder_path);
        break :state_dir_path try std.fs.path.join(allocator, &.{ known_folder_path, "nix-sigstop" });
    } else {
        std.log.err("no data folder available", .{});
        return error.NoDataDir;
    };
    defer allocator.free(state_dir_path);

    try std.fs.cwd().makePath(state_dir_path);

    const store = if (try known_folders.getPath(allocator, .cache)) |known_folder_path| store: {
        defer allocator.free(known_folder_path);
        break :store try std.fs.path.join(allocator, &.{ known_folder_path, "nix-sigstop" });
    } else {
        std.log.err("no cache folder available", .{});
        return error.NoCacheDir;
    };
    defer allocator.free(store);

    const fifo_path = fifo_path: {
        // see `PID_MAX_LIMIT` in `man 5 proc`
        var pid_str_buf: [std.fmt.comptimePrint("{d}", .{std.math.maxInt(u22)}).len]u8 = undefined;
        const pid_str = pid_str_buf[0..std.fmt.formatIntBuf(&pid_str_buf, std.os.linux.getpid(), 10, .lower, .{})];

        break :fifo_path try std.fs.path.joinZ(allocator, &.{ state_dir_path, pid_str });
    };
    defer allocator.free(fifo_path);

    const fifo_lock_path = try std.mem.concat(allocator, u8, &.{ fifo_path, ".lock" });
    defer allocator.free(fifo_lock_path);

    const fifo_lock = try std.fs.createFileAbsolute(fifo_lock_path, .{ .exclusive = true });
    defer {
        fifo_lock.close();
        std.fs.deleteFileAbsolute(fifo_lock_path) catch |err|
            std.log.err("{s}: failed to delete lock file: {s}", .{ @errorName(err), fifo_lock_path });
    }

    if (std.os.linux.mknod(fifo_path, std.os.linux.S.IFIFO | 0o622, 0) != 0) return error.Mknod;
    defer std.posix.unlink(fifo_path) catch |err|
        std.log.err("{s}: failed to delete FIFO: {s}", .{ @errorName(err), fifo_path });

    const done_pipe_read, const done_pipe_write = done_pipe: {
        const pipe_read, const pipe_write = try std.posix.pipe();
        break :done_pipe .{
            std.fs.File{ .handle = pipe_read },
            std.fs.File{ .handle = pipe_write },
        };
    };
    defer {
        done_pipe_read.close();
        done_pipe_write.close();
    }

    var nix_process = nix_process: {
        const args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, args);

        const build_hook_arg = try std.mem.concat(allocator, u8, &.{
            if (std.fs.path.isAbsolute(args[0])) args[0] else self_exe: {
                var self_exe_buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                break :self_exe try std.fs.readLinkAbsolute("/proc/self/exe", &self_exe_buf);
            },
            " ",
            hook_arg,
        });
        defer allocator.free(build_hook_arg);

        const extra_nix_args: []const []const u8 = &.{
            "--build-hook", build_hook_arg,
            "--builders",   fifo_path,
            "--store",      store,
        };

        const nix_args = try allocator.alloc([]const u8, extra_nix_args.len + args.len);
        defer allocator.free(nix_args);

        nix_args[0] = "nix";
        @memcpy(nix_args[1 .. 1 + extra_nix_args.len], extra_nix_args);
        @memcpy(nix_args[1 + extra_nix_args.len .. 1 + extra_nix_args.len + args.len - 1], args[1..]);

        var nix_process = std.process.Child.init(nix_args, allocator);
        nix_process.request_resource_usage_statistics = true;

        try nix_process.spawn();

        break :nix_process nix_process;
    };
    globals.wrapper = nix_process.id;

    const process_messages_thread = try std.Thread.spawn(.{}, processMessages, .{ allocator, fifo_path, done_pipe_read, nix_process.id });

    const term = try nix_process.wait();
    globals.wrapper = null;

    if (term != .Exited or term.Exited != 0)
        std.log.debug("nix command terminated: {s} {d}", .{ @tagName(term), switch (term) {
            inline else => |v| v,
        } });

    if (nix_process.resource_usage_statistics.getMaxRss()) |max_rss|
        std.log.info("max RSS: {d} bytes / {d:.2} MiB / {d:.2} GiB", .{
            max_rss,
            @as(f32, @floatFromInt(max_rss)) / 1024 / 1024,
            @as(f32, @floatFromInt(max_rss)) / 1024 / 1024 / 1024,
        });

    try done_pipe_write.writeAll(&.{0});
    process_messages_thread.join();
}

fn processMessages(
    allocator: std.mem.Allocator,
    /// This is where the build hooks send their messages.
    fifo_path: []const u8,
    /// The nix command is done when this has data available for reading.
    /// The data itself carries no meaning.
    done: std.fs.File,
    pid: std.process.Child.Id,
) !void {
    var num_building: u32 = 0;

    std.log.debug("opening FIFO for IPC: {s}", .{fifo_path});
    const fifo = try std.fs.openFileAbsolute(fifo_path, .{
        // Makes sure the `open()` syscall does not block.
        .mode = .read_write,
    });
    defer fifo.close();

    std.log.debug("waiting for messages from build hooks", .{});

    var poller = std.io.poll(allocator, enum { fifo, done }, .{ .fifo = fifo, .done = done });
    defer poller.deinit();

    // We could remove this and always use zero instead.
    // However this allows us to skip parts of the buffer
    // we already looked for the message end in.
    var fifo_readable_checked_len: usize = 0;

    while (try poller.poll()) {
        while (true) {
            const fifo_readable = poller.fifo(.fifo).readableSlice(0);

            if (std.mem.indexOfScalarPos(u8, fifo_readable, fifo_readable_checked_len, '\n')) |end_pos| {
                fifo_readable_checked_len = 0;

                var fifo_json_reader = std.json.reader(allocator, std.io.limitedReader(poller.fifo(.fifo).reader(), end_pos + 1));
                defer fifo_json_reader.deinit();

                const message = try std.json.parseFromTokenSource(Message, allocator, &fifo_json_reader, .{});
                defer message.deinit();

                switch (message.value) {
                    .start => |msg| {
                        num_building += 1;
                        std.log.info("build started: {s}", .{msg.derivation.drv_path});

                        if (num_building == 1) {
                            std.log.info("stopping the nix client process", .{});
                            try std.posix.kill(pid, std.posix.SIG.STOP);
                        }
                    },
                    .done => |msg| {
                        num_building -= 1;
                        std.log.info("build finished: {s}", .{msg});
                    },
                }

                std.log.info("{d} builds running", .{num_building});

                if (num_building == 0) {
                    std.log.info("continuing the nix client process", .{});
                    try std.posix.kill(pid, std.posix.SIG.CONT);
                }

                if (end_pos + 1 == fifo_readable.len)
                    // We have read the buffer to the end
                    // so we need to poll for new data.
                    break;
            } else {
                fifo_readable_checked_len = fifo_readable.len;
                break;
            }
        }

        if (poller.fifo(.done).readableLength() != 0) break;
    }
}

const Message = union(enum) {
    start: struct {
        derivation: nix.build_hook.Derivation,
        build_io: nix.build_hook.BuildIo,
    },
    /// the corresponding `start.derivation.drv_path`
    done: []const u8,

    fn send(self: @This(), allocator: std.mem.Allocator, fifo: std.fs.File, fifo_lock: std.fs.File) !void {
        try fifo_lock.lock(.exclusive);
        defer fifo_lock.unlock();

        const fifo_writer = fifo.writer();

        if (std.log.defaultLogEnabled(.debug)) {
            const json = try std.json.stringifyAlloc(allocator, self, .{});
            defer allocator.free(json);

            std.log.debug("sending IPC message: {s}", .{json});

            try fifo_writer.writeAll(json);
        } else try std.json.stringify(self, .{}, fifo_writer);

        try fifo_writer.writeByte('\n');
    }
};

fn buildHook(allocator: std.mem.Allocator) !void {
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

    var fifo, var fifo_lock = fifo: {
        const fifo_path = nix_config.get("builders").?;
        if (fifo_path.len == 0) {
            std.log.err("expected path to FIFO for IPC in nix config entry `builders` but it is empty", .{});
            return error.NoBuilders;
        }
        if (!std.fs.path.isAbsolute(fifo_path)) {
            std.log.err("path to FIFO for IPC is not absolute: {s}", .{fifo_path});
            return error.AccessDenied;
        }

        const fifo_lock_path = try std.mem.concat(allocator, u8, &.{ fifo_path, ".lock" });
        defer allocator.free(fifo_lock_path);

        const fifo_lock = try std.fs.openFileAbsolute(fifo_lock_path, .{});
        errdefer fifo_lock.close();

        const fifo = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
            std.log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
            return err;
        };
        errdefer fifo.close();

        break :fifo .{ fifo, fifo_lock };
    };
    defer {
        fifo.close();
        fifo_lock.close();
    }

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

    try (Message{ .start = .{
        .derivation = drv,
        .build_io = build_io,
    } }).send(allocator, fifo, fifo_lock);

    defer (Message{ .done = drv.drv_path }).send(allocator, fifo, fifo_lock) catch |err|
        std.log.err("{s}: failed to send IPC message", .{@errorName(err)});

    var installable = std.ArrayList(u8).init(allocator);
    defer installable.deinit();

    try installable.appendSlice(drv.drv_path);
    try installable.append('^');
    for (build_io.wanted_outputs, 0..) |wanted_output, idx| {
        if (idx != 0) try installable.append(',');
        try installable.appendSlice(wanted_output);
    }

    std.log.debug("installable: {s}", .{installable.items});

    {
        const args = try nixCli(allocator, verbosity, &.{
            "copy",
            "--no-check-sigs",
            "--from",
            store,
            drv.drv_path,
        });
        defer allocator.free(args);

        var process = std.process.Child.init(args, allocator);

        const term = try process.spawnAndWait();
        if (term != .Exited or term.Exited != 0) {
            std.log.err("`nix copy --from {s} {s}` failed: {}", .{ store, drv.drv_path, term });
            return error.NixCopy;
        }
    }

    {
        const args = try nixCli(allocator, verbosity, &.{
            "build",
            "--no-link",
            "--print-build-logs",
            installable.items,
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
        const args = try nixCli(allocator, verbosity, &.{
            "copy",
            "--no-check-sigs",
            "--to",
            store,
            installable.items,
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

fn nixCli(allocator: std.mem.Allocator, verbosity: nix.log.Action.Verbosity, args: []const []const u8) ![]const []const u8 {
    var cli = try std.ArrayListUnmanaged([]const u8).initCapacity(allocator, 4 + args.len);
    errdefer cli.deinit(allocator);

    cli.appendSliceAssumeCapacity(&.{ "nix", "--log-format", "internal-json" });
    switch (@intFromEnum(verbosity)) {
        0 => {},
        inline else => |v| cli.appendAssumeCapacity("-" ++ "v" ** v),
    }
    cli.appendSliceAssumeCapacity(args);

    return cli.toOwnedSlice(allocator);
}
