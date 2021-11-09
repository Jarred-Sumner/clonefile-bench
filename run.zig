const std = @import("std");
usingnamespace std.c;
const builtin = @import("builtin");
const os = std.os;
const mem = std.mem;
const Stat = std.fs.File.Stat;
const Kind = std.fs.File.Kind;
const StatError = std.fs.File.StatError;
const errno = os.errno;
const zeroes = mem.zeroes;

// int clonefileat(int src_dirfd, const char * src, int dst_dirfd, const char * dst, int flags);
pub extern "c" fn clonefileat(c_int, [*c]const u8, c_int, [*c]const u8, uint32_t: c_int) c_int;
// int fclonefileat(int srcfd, int dst_dirfd, const char * dst, int flags);
pub extern "c" fn fclonefileat(c_int, c_int, [*c]const u8, uint32_t: c_int) c_int;
// int clonefile(const char * src, const char * dst, int flags);

pub fn main() anyerror!void {
    const tmpdir = std.fs.openDirAbsolute(std.os.getenvZ("TMPDIR") orelse @panic("Expected $TMPDIR to be defined"), .{ .iterate = true }) catch @panic("Failed to open tmpdir");

    var src: std.builtin.SourceLocation = @src();
    const root_dir = std.fs.path.dirname(std.mem.span(src.file)).?;

    const src_dirfd = std.fs.openDirAbsolute(root_dir, .{ .iterate = true }) catch @panic("Failed to open root dir");

    var outbuf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const dest_dir = try std.os.getFdPath(tmpdir.fd, &outbuf);
    var remainder = outbuf[dest_dir.len..];
    std.mem.copy(u8, remainder, "/huge_node_modules");

    var _dir: std.fs.Dir = src_dirfd.openDirZ("huge/node_modules", .{}) catch @panic("Failed to open huge/node_modules");
    defer _dir.close();
    var dest_abs = outbuf[0 .. dest_dir.len + "/huge_node_modules".len];

    var timer = try std.time.Timer.start();
    delete_existing: {
        tmpdir.deleteTree("huge_node_modules") catch break :delete_existing;
        std.log.info("Deleted existing dir: {d}ns", .{timer.lap()});
    }
    var args = try std.process.argsAlloc(std.heap.c_allocator);

    var flag = std.mem.span(args[args.len - 1]);

    if (std.mem.eql(u8, flag, "clonefile")) {
        std.log.info("starting clonefilatat(): {s}\n", .{dest_abs});
        const ret = clonefileat(src_dirfd.fd, "huge/node_modules", tmpdir.fd, "huge_node_modules", 0);
        std.log.info("finished clonefileat() {d}ns (returned: {d})\n", .{ timer.lap(), ret });
    } else if (std.mem.eql(u8, flag, "copyfile")) {
        timer.reset();
        var destin = tmpdir.makeOpenPath("huge_node_modules", .{ .iterate = true }) catch @panic("Failed to make huge_node_modules");
        defer destin.close();
        const FileCopier = struct {
            pub fn copy(
                destination_dir_: std.fs.Dir,
                walker: *std.fs.Dir.Walker,
            ) !void {
                while (try walker.next()) |entry| {
                    if (entry.kind != .File) continue;

                    var outfile = destination_dir_.createFile(entry.path, .{}) catch brk: {
                        if (std.fs.path.dirname(entry.path)) |entry_dirname| {
                            destination_dir_.makePath(entry_dirname) catch {};
                        }
                        break :brk destination_dir_.createFile(entry.path, .{}) catch |err| {
                            std.debug.panic("FAiled create file {s} {s}", .{ entry.basename, @errorName(err) });
                        };
                    };
                    defer outfile.close();

                    var infile = try entry.dir.openFile(entry.basename, .{ .read = true });
                    defer infile.close();

                    doCopy(infile.handle, outfile.handle) catch |err| {
                        std.debug.panic("FAiled copy file {s} {s}", .{ entry.basename, @errorName(err) });
                    };
                }
            }
        };

        var walker = try _dir.walk(std.heap.c_allocator);
        defer walker.deinit();
        std.log.info("starting fcopyfile(): {s}\n", .{dest_abs});
        timer.reset();
        try FileCopier.copy(destin, &walker);
        std.log.info("finished fcopyfile(): {d}ns\n", .{timer.lap()});
    } else if (std.mem.eql(u8, flag, "link")) {
        timer.reset();
        var destin = tmpdir.makeOpenPath("huge_node_modules", .{ .iterate = true }) catch @panic("Failed to make huge_node_modules");

        const FileCopier = struct {
            pub fn link(
                destination_dir_: std.fs.Dir,
                walker: *std.fs.Dir.Walker,
            ) !void {
                while (try walker.next()) |entry| {
                    if (entry.kind != .File) continue;
                    std.os.linkat(entry.dir.fd, entry.basename, destination_dir_.fd, entry.path, 0) catch {
                        if (std.fs.path.dirname(entry.path)) |dirname| {
                            destination_dir_.makePath(dirname) catch {};
                        }
                        std.os.linkat(entry.dir.fd, entry.basename, destination_dir_.fd, entry.path, 0) catch |err| {
                            std.debug.panic("FAiled linking file {s} {s}", .{ entry.path, @errorName(err) });
                        };
                    };
                }
            }
        };

        var walker = try _dir.walk(std.heap.c_allocator);

        std.log.info("starting os.linkat(): {s}\n", .{dest_abs});
        timer.reset();
        try FileCopier.link(destin, &walker);
        std.log.info("finished os.linkat(): {d}ns\n", .{timer.lap()});
    } else {
        std.log.err("Invalid flag: {s}", .{flag});
    }
}


// Mostly copy-pasted 
const math = std.math;

const CopyFileError = error{SystemResources} || os.CopyFileRangeError || os.SendFileError;

// Transfer all the data between two file descriptors in the most efficient way.
// The copy starts at offset 0, the initial offsets are preserved.
// No metadata is transferred over.
pub fn doCopy(fd_in: os.fd_t, fd_out: os.fd_t) CopyFileError!void {
    if (comptime std.Target.current.isDarwin()) {
        const rc = os.system.fcopyfile(fd_in, fd_out, null, os.system.COPYFILE_DATA);
        switch (os.errno(rc)) {
            .SUCCESS => return,
            .INVAL => unreachable,
            .NOMEM => return error.SystemResources,
            // The source file is not a directory, symbolic link, or regular file.
            // Try with the fallback path before giving up.
            .OPNOTSUPP => {},
            else => |err| return os.unexpectedErrno(err),
        }
    }

    if (comptime std.Target.current.os.tag == .linux) {
        // Try copy_file_range first as that works at the FS level and is the
        // most efficient method (if available).
        var offset: u64 = 0;
        cfr_loop: while (true) {
            // The kernel checks the u64 value `offset+count` for overflow, use
            // a 32 bit value so that the syscall won't return EINVAL except for
            // impossibly large files (> 2^64-1 - 2^32-1).
            const amt = try os.copy_file_range(fd_in, offset, fd_out, offset, math.maxInt(u32), 0);
            // Terminate when no data was copied
            if (amt == 0) break :cfr_loop;
            offset += amt;
        }
        return;
    }

    // Sendfile is a zero-copy mechanism iff the OS supports it, otherwise the
    // fallback code will copy the contents chunk by chunk.
    const empty_iovec = [0]os.iovec_const{};
    var offset: u64 = 0;
    sendfile_loop: while (true) {
        const amt = try os.sendfile(fd_out, fd_in, offset, 0, &empty_iovec, &empty_iovec, 0);
        // Terminate when no data was copied
        if (amt == 0) break :sendfile_loop;
        offset += amt;
    }
}
