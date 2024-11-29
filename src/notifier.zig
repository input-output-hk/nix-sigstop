const builtin = @import("builtin");
const std = @import("std");
const utils = @import("utils");

const root = if (builtin.is_test) @import("main.zig") else @import("root");

const log = utils.log.scoped(.notifier);

pub fn main(
    fifo: std.fs.File,
    drv_path: []const u8,
    output_lockfile_paths: []const []const u8,
) void {
    for (output_lockfile_paths) |output_lockfile|
        if (std.fs.openFileAbsolute(output_lockfile, .{ .lock = .exclusive })) |lockfile|
            lockfile.close()
        else |err| switch (err) {
            // The output might not actually have to get built
            // or the lockfile might have been deleted already.
            error.FileNotFound => log.debug(
                "considering output without lockfile as finished: {s} of {s}",
                .{ output_lockfile[0 .. output_lockfile.len - ".lock".len], drv_path },
            ),
            else => |e| fatal("{s}: failed to acquire lock", .{@errorName(e)}),
        };

    (root.Event{ .done = drv_path }).emit(fifo) catch |err|
        fatal("{s}: failed to emit done event", .{@errorName(err)});
}

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    log.err(fmt, args);
    std.debug.panic(fmt, args);
}
