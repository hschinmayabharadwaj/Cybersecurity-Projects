// ©AngelaMos | 2026
// token.zig

const std = @import("std");
const config = @import("../config.zig");
const pin = @import("../crypto/pin.zig");
const keystore = @import("../crypto/keystore.zig");
const env = @import("env.zig");

pub const PinSlot = struct {
    salt: pin.Salt,
    hash: pin.Hash,
};

pub const Token = struct {
    initialized: bool = false,
    label: [config.label_len]u8 = @splat(' '),
    so: PinSlot = std.mem.zeroes(PinSlot),
    user: ?PinSlot = null,
    so_fail: u32 = 0,
    user_fail: u32 = 0,
    user_mk: ?keystore.Wrapped = null,
};

const flag_initialized: u32 = 1 << 0;
const flag_user_present: u32 = 1 << 1;
const flag_user_mk: u32 = 1 << 2;

const Record = extern struct {
    magic: u32,
    version: u32,
    flags: u32,
    label: [config.label_len]u8,
    so_salt: [pin.salt_len]u8,
    so_hash: [pin.hash_len]u8,
    user_salt: [pin.salt_len]u8,
    user_hash: [pin.hash_len]u8,
    so_fail: u32,
    user_fail: u32,
    mk_salt: [pin.salt_len]u8,
    mk_nonce: [keystore.nonce_len]u8,
    mk_ct: [keystore.mk_len]u8,
    mk_tag: [keystore.tag_len]u8,
};

fn serialize(t: Token) Record {
    var r = std.mem.zeroes(Record);
    r.magic = config.token_record_magic;
    r.version = config.token_record_version;
    r.flags = (if (t.initialized) flag_initialized else 0) | (if (t.user != null) flag_user_present else 0) | (if (t.user_mk != null) flag_user_mk else 0);
    r.label = t.label;
    r.so_salt = t.so.salt;
    r.so_hash = t.so.hash;
    if (t.user) |u| {
        r.user_salt = u.salt;
        r.user_hash = u.hash;
    }
    if (t.user_mk) |w| {
        r.mk_salt = w.salt;
        r.mk_nonce = w.nonce;
        r.mk_ct = w.ct;
        r.mk_tag = w.tag;
    }
    r.so_fail = t.so_fail;
    r.user_fail = t.user_fail;
    return r;
}

fn deserialize(r: *const Record) Token {
    return .{
        .initialized = (r.flags & flag_initialized) != 0,
        .label = r.label,
        .so = .{ .salt = r.so_salt, .hash = r.so_hash },
        .user = if ((r.flags & flag_user_present) != 0) PinSlot{ .salt = r.user_salt, .hash = r.user_hash } else null,
        .so_fail = r.so_fail,
        .user_fail = r.user_fail,
        .user_mk = if ((r.flags & flag_user_mk) != 0) keystore.Wrapped{ .salt = r.mk_salt, .nonce = r.mk_nonce, .ct = r.mk_ct, .tag = r.mk_tag } else null,
    };
}

pub fn resolvePath(buf: []u8) ![]const u8 {
    return env.resolvePath(buf, config.token_path_env, config.token_path_default);
}

pub fn saveTo(io: std.Io, path: []const u8, t: Token) !void {
    const rec = serialize(t);
    var tmp_buf: [config.path_buf_len + 8]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
    const dir = std.Io.Dir.cwd();
    try dir.writeFile(io, .{ .sub_path = tmp, .data = std.mem.asBytes(&rec) });
    try dir.rename(tmp, dir, path, io);
}

pub fn loadFrom(io: std.Io, allocator: std.mem.Allocator, path: []const u8) Token {
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(config.token_read_limit)) catch return .{};
    defer allocator.free(bytes);
    if (bytes.len != @sizeOf(Record)) return .{};
    var rec: Record = undefined;
    @memcpy(std.mem.asBytes(&rec), bytes[0..@sizeOf(Record)]);
    if (rec.magic != config.token_record_magic or rec.version != config.token_record_version) return .{};
    return deserialize(&rec);
}

pub fn save(io: std.Io, t: Token) !void {
    var buf: [config.path_buf_len]u8 = undefined;
    const path = try resolvePath(&buf);
    try saveTo(io, path, t);
}

pub fn load(io: std.Io, allocator: std.mem.Allocator) Token {
    var buf: [config.path_buf_len]u8 = undefined;
    const path = resolvePath(&buf) catch return .{};
    return loadFrom(io, allocator, path);
}

test "serialize then deserialize round-trips an initialized token with a user PIN" {
    var t: Token = .{ .initialized = true, .so_fail = 2, .user_fail = 1 };
    t.label = @splat('X');
    t.so = .{ .salt = @splat(3), .hash = @splat(4) };
    t.user = .{ .salt = @splat(5), .hash = @splat(6) };

    const rec = serialize(t);
    const back = deserialize(&rec);

    try std.testing.expect(back.initialized);
    try std.testing.expectEqualSlices(u8, &t.label, &back.label);
    try std.testing.expectEqual(t.so.salt, back.so.salt);
    try std.testing.expectEqual(t.so.hash, back.so.hash);
    try std.testing.expect(back.user != null);
    try std.testing.expectEqual(t.user.?.hash, back.user.?.hash);
    try std.testing.expectEqual(@as(u32, 2), back.so_fail);
    try std.testing.expectEqual(@as(u32, 1), back.user_fail);
}

test "an uninitialized token has no user PIN after a round-trip" {
    const rec = serialize(.{});
    const back = deserialize(&rec);
    try std.testing.expect(!back.initialized);
    try std.testing.expect(back.user == null);
}

test "saveTo then loadFrom persists across a file" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "/tmp/angelamos-hsm-unit-token.bin";
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    var t: Token = .{ .initialized = true };
    t.label = @splat('Z');
    t.so = .{ .salt = @splat(9), .hash = @splat(8) };

    try saveTo(io, path, t);
    const back = loadFrom(io, std.testing.allocator, path);
    try std.testing.expect(back.initialized);
    try std.testing.expectEqual(t.so.hash, back.so.hash);
    try std.testing.expect(back.user == null);
}

test "loadFrom a missing file yields a default uninitialized token" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const back = loadFrom(io, std.testing.allocator, "/tmp/angelamos-hsm-does-not-exist.bin");
    try std.testing.expect(!back.initialized);
}
