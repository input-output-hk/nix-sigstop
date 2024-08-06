const std = @import("std");
const known_folders = @import("known-folders");
const lib = @import("lib");

const nix = lib.nix;

const hook = @import("hook.zig");

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

        std.debug.assert(args.skip());

        break :build_hook if (args.next()) |arg1|
            std.mem.eql(u8, arg1, hook_arg)
        else
            false;
    }) {
        globals = .build_hook;
        return hook.main(allocator);
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

    const cache_dir_path = if (try known_folders.getPath(allocator, .cache)) |known_folder_path| cache_dir_path: {
        defer allocator.free(known_folder_path);
        break :cache_dir_path try std.fs.path.join(allocator, &.{ known_folder_path, "nix-sigstop" });
    } else {
        std.log.err("no cache folder available", .{});
        return error.NoCacheDir;
    };
    defer allocator.free(cache_dir_path);

    try std.fs.cwd().makePath(state_dir_path);

    const fifo_path = fifo_path: {
        // see `PID_MAX_LIMIT` in `man 5 proc`
        var pid_str_buf: [std.fmt.comptimePrint("{d}", .{std.math.maxInt(u22)}).len]u8 = undefined;
        const pid_str = pid_str_buf[0..std.fmt.formatIntBuf(&pid_str_buf, std.os.linux.getpid(), 10, .lower, .{})];

        break :fifo_path try std.fs.path.joinZ(allocator, &.{ state_dir_path, pid_str });
    };
    defer allocator.free(fifo_path);

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
                break :self_exe try std.fs.selfExePath(&self_exe_buf);
            },
            " ",
            hook_arg,
        });
        defer allocator.free(build_hook_arg);

        const builders_arg = try std.mem.join(allocator, &.{std.fs.path.delimiter}, &.{ fifo_path, cache_dir_path });
        defer allocator.free(builders_arg);

        const nix_args = try std.mem.concat(allocator, []const u8, &.{
            &.{"nix"},
            &.{
                "--build-hook", build_hook_arg,
                "--builders",   builders_arg,
            },
            args[1..],
        });
        defer allocator.free(nix_args);

        var nix_process = std.process.Child.init(nix_args, allocator);
        nix_process.request_resource_usage_statistics = true;

        try nix_process.spawn();

        break :nix_process nix_process;
    };
    globals.wrapper = nix_process.id;

    const process_events_thread = try std.Thread.spawn(.{}, processEvents, .{ allocator, fifo_path, done_pipe_read, nix_process.id });

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
    process_events_thread.join();
}

fn processEvents(
    allocator: std.mem.Allocator,
    /// This is where the build hooks write their events to.
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

    std.log.debug("waiting for events from build hooks", .{});

    var poller = std.io.poll(allocator, enum { fifo, done }, .{ .fifo = fifo, .done = done });
    defer poller.deinit();

    // We could remove this and always use zero instead.
    // However this allows us to skip parts of the buffer
    // we already looked for the event end in.
    var fifo_readable_checked_len: usize = 0;

    while (try poller.poll()) {
        while (true) {
            const fifo_readable = poller.fifo(.fifo).readableSlice(0);

            if (std.mem.indexOfScalarPos(u8, fifo_readable, fifo_readable_checked_len, '\n')) |end_pos| {
                fifo_readable_checked_len = 0;

                var fifo_json_reader = std.json.reader(allocator, std.io.limitedReader(poller.fifo(.fifo).reader(), end_pos + 1));
                defer fifo_json_reader.deinit();

                const event = try std.json.parseFromTokenSource(hook.Event, allocator, &fifo_json_reader, .{});
                defer event.deinit();

                switch (event.value) {
                    .start => |msg| {
                        num_building += 1;
                        std.log.info("build started: {s}", .{msg.drv_path});

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
