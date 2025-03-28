const builtin = @import("builtin");
const std = @import("std");
const known_folders = @import("known-folders");
const utils = @import("utils");

const nix = utils.nix;

const hook = @import("hook.zig");

pub const std_options = std.Options{
    .log_scope_levels = &.{
        .{ .scope = .hook, .level = .debug },
        .{ .scope = .notifier, .level = .err },
    },

    .logFn = struct {
        fn logFn(comptime message_level: std.log.Level, comptime scope: @Type(.enum_literal), comptime format: []const u8, args: anytype) void {
            switch (globals) {
                .wrapper => std.log.defaultLog(message_level, scope, format, args),
                .build_hook => nix.log.logFn(message_level, scope, format, args),
                .build_notifier => {}, // Daemons have no stdio.
            }
        }
    }.logFn,
};

pub const Event = union(enum) {
    start: nix.build_hook.Derivation,
    /// the corresponding `start.drv_path`
    done: []const u8,

    pub fn emit(self: @This(), fifo: std.fs.File) (std.fs.File.LockError || std.fs.File.WriteError)!void {
        try fifo.lock(.exclusive);
        defer fifo.unlock();

        const fifo_writer = fifo.writer();

        try std.json.stringify(self, .{}, fifo_writer);
        try fifo_writer.writeByte('\n');
    }
};

pub const hook_arg = "__build-hook";

pub var globals: union(enum) {
    /// The PID of the nix client process.
    wrapper: ?std.process.Child.Id,
    build_hook,
    build_notifier,
} = .{ .wrapper = null };

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() == .leak) std.log.err("leaked memory", .{});
    const allocator = gpa.allocator();

    {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();

        std.debug.assert(args.skip());

        if (args.next()) |arg1| {
            if (std.mem.eql(u8, arg1, hook_arg))
                globals = .build_hook;
        }
    }

    std.log.debug("reading nix config from environment", .{});
    const nix_config_env = nix_config_env: {
        var diagnostics: nix.ConfigDiagnostics = undefined;
        errdefer |err| switch (err) {
            error.CouldNotReadNixConfig => {
                defer diagnostics.CouldNotReadNixConfig.deinit(allocator);
                std.log.err("could not read nix config: {}, stderr: {s}", .{
                    diagnostics.CouldNotReadNixConfig.term,
                    diagnostics.CouldNotReadNixConfig.stderr,
                });
            },
            else => {},
        };
        break :nix_config_env try nix.config(allocator, &diagnostics);
    };
    defer nix_config_env.deinit();

    switch (globals) {
        .wrapper => {},
        .build_hook => return hook.main(allocator, nix_config_env.value),
        .build_notifier => unreachable,
    }

    if (!builtin.is_test) {
        // we need the `nix store info` command for `nix.storeInfo()`
        const min_nix_version = std.SemanticVersion{ .major = 2, .minor = 19, .patch = 0 };

        const version = try nix.version(allocator);

        if (version.order(min_nix_version) == .lt) {
            std.log.err("nix version {} is too old, must be {} or newer", .{ version, min_nix_version });
            return 1;
        }
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
        std.posix.sigaction(std.posix.SIG.TERM, &sa, null);
        std.posix.sigaction(std.posix.SIG.INT, &sa, null);
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

    const pid_str = pid_str: {
        // see `PID_MAX_LIMIT` in `man 5 proc`
        var pid_str_buf: [std.fmt.comptimePrint("{d}", .{std.math.maxInt(u22)}).len]u8 = undefined;
        break :pid_str pid_str_buf[0..std.fmt.formatIntBuf(&pid_str_buf, std.posix.system.getpid(), 10, .lower, .{})];
    };

    const fifo_path = try std.mem.concatWithSentinel(allocator, u8, &.{
        state_dir_path,
        std.fs.path.sep_str,
        pid_str,
        ".pipe",
    }, 0);
    defer allocator.free(fifo_path);

    if (std.posix.system.mknod(fifo_path, std.posix.system.S.IFIFO | 0o622, 0) != 0) return error.Mknod;
    defer std.posix.unlink(fifo_path) catch |err|
        std.log.err("{s}: failed to delete FIFO: {s}", .{ @errorName(err), fifo_path });

    const daemon_socket_path = try std.mem.concat(allocator, u8, &.{
        state_dir_path,
        std.fs.path.sep_str,
        pid_str,
        "-daemon.sock",
    });
    defer allocator.free(daemon_socket_path);

    var daemon_server = try (try std.net.Address.initUnix(daemon_socket_path)).listen(.{ .kernel_backlog = 0 });
    defer {
        daemon_server.deinit();
        std.fs.deleteFileAbsolute(daemon_socket_path) catch |err|
            std.log.err("{s}: failed to delete daemon socket: {s}", .{ @errorName(err), daemon_socket_path });
    }

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // `nix store info` resolves `--store auto`.
    const store_info = store_info: {
        const store = store: for (args[0 .. args.len - 1], args[1..]) |arg_flag, arg_value| {
            if (std.mem.eql(u8, arg_flag, "--store")) break :store arg_value;
        } else nix_config_env.value.store.value;

        var diagnostics: nix.StoreInfoDiagnostics = undefined;
        errdefer |err| switch (err) {
            error.CouldNotPingNixStore => {
                defer diagnostics.CouldNotPingNixStore.deinit(allocator);
                std.log.err("{s}: `nix store info --store {s}` terminated with {}\nstderr: {s}", .{
                    @errorName(err),
                    store,
                    diagnostics.CouldNotPingNixStore.term,
                    diagnostics.CouldNotPingNixStore.stderr,
                });
            },
            else => {},
        };
        break :store_info try nix.storeInfo(allocator, store, &diagnostics);
    };
    defer store_info.deinit();

    const upstream_daemon_socket_path = upstream_daemon_socket_path: {
        const store = store_info.value.url;

        break :upstream_daemon_socket_path if (std.mem.eql(u8, store, "daemon") or std.mem.startsWith(u8, store, "daemon?"))
            "/nix/var/nix/daemon-socket/socket"
        else if (std.mem.startsWith(u8, store, "unix://"))
            store[0 .. std.mem.indexOfScalarPos(u8, store, "unix://".len, '?') orelse store.len]
        else {
            std.log.err("nix-sigstop only works with local daemon stores which the current store is not: {s}", .{store});
            return 1;
        };
    };
    std.log.debug("upstream nix daemon socket: {s}", .{upstream_daemon_socket_path});

    var proxy_daemon_socket_ctrl = utils.posix.ProxyDuplexControl.init(allocator);
    defer proxy_daemon_socket_ctrl.deinit();

    var proxy_daemon_socket_thread: ?std.Thread = null;
    var process_events_thread: ?std.Thread = null;

    const done_pipe_read, const done_pipe_write = done_pipe: {
        const pipe_read, const pipe_write = try std.posix.pipe();
        break :done_pipe .{
            std.fs.File{ .handle = pipe_read },
            std.fs.File{ .handle = pipe_write },
        };
    };
    defer {
        done_pipe_write.close();

        // These threads finish on `POLLHUP` from closing the write end.
        // Closing the read end while they are still polling it
        // is undefined behavior as documented in `man 2 select`.
        if (process_events_thread) |t| t.join();
        if (proxy_daemon_socket_thread) |t| t.join();

        done_pipe_read.close();
    }

    proxy_daemon_socket_thread = try std.Thread.spawn(.{}, proxyDaemonSocket, .{ allocator, &daemon_server, upstream_daemon_socket_path, done_pipe_read, &proxy_daemon_socket_ctrl });
    proxy_daemon_socket_thread.?.setName(utils.mem.capConst(u8, "daemon proxy", std.Thread.max_name_len, .end)) catch |err|
        std.log.debug("{s}: failed to set thread name", .{@errorName(err)});

    var nix_process = nix_process: {
        const store_arg = try std.mem.concat(allocator, u8, &.{ "unix://", daemon_socket_path });
        defer allocator.free(store_arg);

        const build_hook_arg = try std.mem.concat(allocator, u8, &.{
            self_exe: {
                var self_exe_buf: [std.fs.max_path_bytes]u8 = undefined;
                break :self_exe try std.fs.selfExePath(&self_exe_buf);
            },
            " ",
            hook_arg,
        });
        defer allocator.free(build_hook_arg);

        const builders_arg = try std.mem.join(allocator, &.{std.fs.path.delimiter}, &.{
            fifo_path,
            store_info.value.url,
        });
        defer allocator.free(builders_arg);

        const nix_args = try std.mem.concat(allocator, []const u8, &.{
            &.{"nix"},
            args[1..],
            &.{
                "--store",      store_arg,
                "--build-hook", build_hook_arg,
                "--builders",   builders_arg,
            },
        });
        defer allocator.free(nix_args);

        var nix_process = std.process.Child.init(nix_args, allocator);
        nix_process.request_resource_usage_statistics = true;

        try nix_process.spawn();

        break :nix_process nix_process;
    };
    globals.wrapper = nix_process.id;

    process_events_thread = try std.Thread.spawn(.{}, processEvents, .{ allocator, fifo_path, done_pipe_read, nix_process.id, &proxy_daemon_socket_ctrl });
    process_events_thread.?.setName(utils.mem.capConst(u8, "hook events", std.Thread.max_name_len, .end)) catch |err|
        std.log.debug("{s}: failed to set thread name", .{@errorName(err)});

    const term = try nix_process.wait();
    globals.wrapper = null;

    if (term != .Exited or term.Exited != 0)
        std.log.debug("nix command terminated: {s} {d}", .{ @tagName(term), switch (term) {
            inline else => |v| v,
        } });

    if (nix_process.resource_usage_statistics.getMaxRss()) |max_rss|
        std.log.info("max RSS: {d} bytes / {d:.2} MiB / {d:.2} GiB", .{
            max_rss,
            @as(f32, @floatFromInt(max_rss)) / utils.mem.b_per_mib,
            @as(f32, @floatFromInt(max_rss)) / utils.mem.b_per_gib,
        });

    return switch (term) {
        .Exited => |status| status,
        else => 1,
    };
}

fn processEvents(
    allocator: std.mem.Allocator,
    /// This is where the build hooks write their events to.
    fifo_path: []const u8,
    /// The nix command is done when the other end of this pipe is closed.
    /// Will never have any data.
    done: std.fs.File,
    pid: std.process.Child.Id,
    proxy_daemon_socket_ctrl: *utils.posix.ProxyDuplexControl,
) !void {
    errdefer |err| std.debug.panic("{s}: error processing hook events", .{@errorName(err)});

    var num_building: usize = 0;

    std.log.debug("opening FIFO for IPC: {s}", .{fifo_path});
    const fifo = try std.fs.openFileAbsolute(fifo_path, .{
        // Makes sure the `open()` syscall does not block.
        .mode = .read_write,
    });
    defer fifo.close();

    std.log.debug("listening to events from build hooks", .{});
    defer std.log.debug("no longer listening to events from build hooks", .{});

    const PollerStream = enum { fifo, done };
    var poller = std.io.poll(allocator, PollerStream, .{ .fifo = fifo, .done = done });
    defer poller.deinit();

    // We could remove this and always use zero instead.
    // However this allows us to skip parts of the buffer
    // we already looked for the event end in.
    var fifo_readable_checked_len: usize = 0;

    poll: while (try poller.poll()) {
        const num_building_before_events = num_building;

        while (true) {
            const poller_fifo = poller.fifo(.fifo);

            const fifo_readable = poller_fifo.readableSliceOfLen(poller_fifo.readableLength());

            if (std.mem.indexOfScalarPos(u8, fifo_readable, fifo_readable_checked_len, '\n')) |end_pos| {
                fifo_readable_checked_len = 0;

                const event = try std.json.parseFromSlice(Event, allocator, fifo_readable[0..end_pos], .{});
                defer {
                    event.deinit();

                    // `event` refers to memory in `poller_fifo`'s buffer
                    // so we need to make sure not to discard it before freeing `event`.
                    poller_fifo.discard(end_pos + 1);
                }

                switch (event.value) {
                    .start => |drv| {
                        std.log.info("build started: {s}", .{drv.drv_path});
                        num_building += 1;
                    },
                    .done => |drv_path| {
                        std.log.info("build done: {s}", .{drv_path});
                        num_building -= 1;
                    },
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

        if (num_building_before_events == 0 and num_building != 0) {
            std.log.info("stopping the nix client process", .{});
            try proxy_daemon_socket_ctrl.ignore(.downstream);
            try std.posix.kill(pid, std.posix.SIG.STOP);
        }
        if (num_building_before_events != 0 and num_building == 0) {
            std.log.info("continuing the nix client process", .{});
            try std.posix.kill(pid, std.posix.SIG.CONT);
            try proxy_daemon_socket_ctrl.unignore(.downstream);
        }

        if (num_building != num_building_before_events)
            std.log.info("{d} builds running", .{num_building});

        for (poller.poll_fds, std.enums.values(PollerStream)) |poll_fd, stream| {
            switch (stream) {
                .fifo => {},
                .done => if (poll_fd.revents & std.posix.POLL.HUP != 0)
                    break :poll,
            }

            if (poll_fd.fd == -1) {
                std.log.err("error polling `{}`. revents: 0x{X}", .{ stream, poll_fd.revents });

                if (stream == .done) {
                    // Continue the nix client process in case it is currently stopped
                    // because we are about to shut down this thread and do not want
                    // to leave it in a stopped state forever.
                    std.posix.kill(pid, std.posix.SIG.CONT) catch |err| switch (err) {
                        error.ProcessNotFound => {
                            // We have no way to tell whether
                            // the nix client process is running
                            // because our `done` pipe is broken.
                        },
                        // XXX Should be able to just `return err` but it seems that fails peer type resolution.
                        // Could this be a compiler bug? This only happens if we have an `errdefer` with capture
                        // in the enclosing block. In our case this is the `errdefer` that panics.
                        else => |e| return @as(utils.meta.FnErrorSet(@TypeOf(std.posix.kill))!void, e),
                    };
                    try proxy_daemon_socket_ctrl.unignore(.downstream);
                }

                break :poll;
            }
        }
    }
}

fn proxyDaemonSocket(
    allocator: std.mem.Allocator,
    server: *std.net.Server,
    upstream_daemon_socket_path: []const u8,
    /// The nix command is done when the other end of this pipe is closed.
    /// Will never have any data.
    done: std.fs.File,
    control: *utils.posix.ProxyDuplexControl,
) !void {
    const posix = std.posix;
    const POLL = posix.POLL;

    var wg = std.Thread.WaitGroup{};

    defer {
        std.log.debug("waiting for nix daemon proxy threads to finish", .{});
        defer std.log.debug("all nix daemon proxy threads finished", .{});

        wg.wait();
    }

    std.log.debug("ready for nix client connections", .{});
    defer std.log.debug("accepting no more nix client connections", .{});

    // We cannot use `std.io.poll()` for this
    // because it does `posix.read()` on `POLL.IN` events.
    var poll_fds = [2]posix.pollfd{
        .{
            .fd = server.stream.handle,
            .events = POLL.IN,
            .revents = undefined,
        },
        .{
            .fd = done.handle,
            .events = POLL.HUP,
            .revents = undefined,
        },
    };

    poll: while (true) {
        std.debug.assert(try posix.poll(&poll_fds, -1) != 0);

        if (poll_fds[0].revents & POLL.IN != 0) {
            const connection = server.accept() catch |err| switch (err) {
                error.SocketNotListening, error.ConnectionAborted => break,
                else => |e| return e,
            };
            errdefer connection.stream.close();

            std.log.debug("nix client connected", .{});

            const upstream = std.net.connectUnixSocket(upstream_daemon_socket_path) catch |err| {
                std.log.err("{s}: cannot connect to upstream nix daemon socket", .{@errorName(err)});
                return err;
            };
            errdefer upstream.close();

            wg.spawnManager(struct {
                fn work(
                    allocator_: std.mem.Allocator,
                    connection_: std.net.Server.Connection,
                    upstream_: std.net.Stream,
                    done_: std.fs.File,
                    control_: *utils.posix.ProxyDuplexControl,
                ) void {
                    defer {
                        connection_.stream.close();
                        upstream_.close();
                    }

                    const reason = @call(.auto, utils.posix.proxyDuplex, .{
                        allocator_,
                        utils.posix.ProxyDuplexOptions.ComptimeOptions{
                            .downstream_kind = .socket,
                            .upstream_kind = .socket,
                        },
                        connection_.stream.handle,
                        upstream_.handle,
                        utils.posix.ProxyDuplexOptions{
                            .cancel = done_.handle,
                            .control = control_,
                            .fifo_max_size = utils.mem.b_per_gib,
                            .fifo_desired_size = 8 * utils.mem.b_per_mib,
                        },
                    }) catch |err| {
                        std.log.err("{s}: error proxying nix client connection", .{@errorName(err)});
                        return;
                    };

                    std.log.debug("finished proxying nix client connection: {s}", .{@tagName(reason)});
                }
            }.work, .{ allocator, connection, upstream, done, control });
        }

        if (poll_fds[1].revents & POLL.HUP != 0)
            break;

        inline for (poll_fds, .{ "nix daemon server", "done pipe" }) |poll_fd, name|
            if (poll_fd.fd & (POLL.ERR | POLL.NVAL | POLL.HUP) != 0) {
                std.log.err("error polling {s}. revents: 0x{X}", .{ name, poll_fd.revents });
                break :poll;
            };
    }
}

test {
    _ = std.testing.refAllDeclsRecursive(@This());
}
