const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

const root = if (builtin.is_test) @import("main.zig") else @import("root");

const c = @cImport({
    @cInclude("unistd.h");
});

const log = utils.log.scoped(.notifier);

pub fn main(allocator: std.mem.Allocator) !u8 {
    switch (std.posix.errno(c.daemon(0, 0))) {
        .SUCCESS => {},
        else => |errno| {
            log.err("{s}: failed to daemonize", .{@tagName(errno)});
            return 1;
        },
    }

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    std.debug.assert(args.skip());
    std.debug.assert(args.skip());

    const fifo_path = args.next().?;
    const drv_path = args.next().?;

    while (args.next()) |wanted_output| {
        const lockfile_path = try std.mem.concat(allocator, u8, &.{ wanted_output, ".lock" });
        defer allocator.free(lockfile_path);

        if (std.fs.openFileAbsolute(lockfile_path, .{ .lock = .exclusive })) |lockfile|
            lockfile.close()
        else |err| switch (err) {
            // The output might not actually have to get built
            // or the lockfile might have been deleted already.
            error.FileNotFound => std.log.debug("considering output without lockfile as finished: {s} of {s}", .{ wanted_output, drv_path }),
            else => |e| return e,
        }
    }

    log.debug("opening FIFO for IPC: {s}", .{fifo_path});
    var fifo = std.fs.openFileAbsolute(fifo_path, .{ .mode = .write_only }) catch |err| {
        log.err("{s}: failed to open path to FIFO for IPC: {s}", .{ @errorName(err), fifo_path });
        return err;
    };
    defer fifo.close();

    try (root.Event{ .done = drv_path }).emit(allocator, fifo, log.scope);

    return 0;
}
