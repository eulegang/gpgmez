const std = @import("std");

const gpg = @cImport({
    @cInclude("gpgme.h");
});

pub const Error = error{failed};

threadlocal var gerr: gpg.gpgme_error_t = gpg.GPG_ERR_NO_ERROR;

pub fn error_msg() ?[]const u8 {
    if (gerr == gpg.GPG_ERR_NO_ERROR) {
        return null;
    } else {
        var buf: []const u8 = std.mem.span(gpg.gpg_strerror(gerr));
        return buf;
    }
}

pub fn init() void {
    _ = gpg.gpgme_check_version(null);
}

pub const Context = struct {
    const Self = @This();

    ctx: gpg.gpgme_ctx_t,

    pub fn init() !Self {
        var ctx: gpg.gpgme_ctx_t = undefined;
        var err = gpg.gpgme_new(&ctx);

        if (err != gpg.GPG_ERR_NO_ERROR) {
            gerr = err;
            return Error.failed;
        }

        return Context{
            .ctx = ctx,
        };
    }

    pub fn deinit(self: *Self) void {
        gpg.gpgme_release(self.ctx);
    }

    pub fn decrypt(self: *Self, cipher: *Data, plain: *Data) !void {
        const err = gpg.gpgme_op_decrypt(self.ctx, cipher.handle, plain.handle);

        if (err != gpg.GPG_ERR_NO_ERROR) {
            gerr = err;
            return Error.failed;
        }
    }
};

pub const Data = struct {
    const Self = @This();

    handle: gpg.gpgme_data_t,

    pub fn init() !Data {
        var handle: gpg.gpgme_data_t = undefined;

        const err = gpg.gpgme_data_new(&handle);
        if (err != gpg.GPG_ERR_NO_ERROR) {
            gerr = err;
            return Error.failed;
        }

        return Self{ .handle = handle };
    }

    pub fn file(path: [*:0]const u8) !Data {
        var handle: gpg.gpgme_data_t = undefined;

        const err = gpg.gpgme_data_new_from_file(&handle, path, 1);

        if (err != gpg.GPG_ERR_NO_ERROR) {
            gerr = err;
            return Error.failed;
        }

        return Self{ .handle = handle };
    }

    pub fn deinit(self: *Self) void {
        gpg.gpgme_data_release(self.handle);
    }

    pub fn write(self: *Self, buf: []const u8) isize {
        return gpg.gpgme_data_write(self.handle, buf.ptr, buf.len);
    }

    pub fn read(self: *Self, buf: []u8) isize {
        return gpg.gpgme_data_read(self.handle, buf.ptr, buf.len);
    }

    pub fn reset(self: *Self) void {
        _ = gpg.gpgme_data_seek(self.handle, 0, gpg.SEEK_SET);
    }
};

test "simple decrypt op" {
    init();
    var out = try Data.init();
    var cipher = try Data.file("msg.gpg\x00");

    var context = try Context.init();
    try context.decrypt(&cipher, &out);
    out.reset();

    var buf: [4096]u8 = undefined;
    const len = out.read(&buf);
    var result = buf[0..@intCast(len)];

    try std.testing.expectEqualSlices(u8, "hello world\n", result);
}
