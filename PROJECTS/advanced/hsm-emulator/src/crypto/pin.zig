// ©AngelaMos | 2026
// pin.zig

const std = @import("std");
const config = @import("../config.zig");

const argon2 = std.crypto.pwhash.argon2;

pub const salt_len = config.pin_salt_len;
pub const hash_len = config.pin_hash_len;

pub const Salt = [salt_len]u8;
pub const Hash = [hash_len]u8;

const params: argon2.Params = .{
    .t = config.pin_kdf_t,
    .m = config.pin_kdf_m_kib,
    .p = config.pin_kdf_p,
};

pub fn genSalt(io: std.Io, out: *Salt) !void {
    try io.randomSecure(out);
}

pub fn derive(io: std.Io, allocator: std.mem.Allocator, pin: []const u8, salt: *const Salt, out: *Hash) !void {
    try argon2.kdf(allocator, out, pin, salt, params, .argon2id, io);
}

pub fn verify(io: std.Io, allocator: std.mem.Allocator, pin: []const u8, salt: *const Salt, expected: *const Hash) !bool {
    var got: Hash = undefined;
    defer std.crypto.secureZero(u8, &got);
    try derive(io, allocator, pin, salt, &got);
    return std.crypto.timing_safe.eql(Hash, got, expected.*);
}

test "argon2id derive is deterministic for a fixed salt" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const salt: Salt = @splat(7);
    var a: Hash = undefined;
    var b: Hash = undefined;
    try derive(io, std.testing.allocator, "1234", &salt, &a);
    try derive(io, std.testing.allocator, "1234", &salt, &b);
    try std.testing.expectEqual(a, b);
}

test "verify accepts the right PIN and rejects the wrong one" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var salt: Salt = undefined;
    try genSalt(io, &salt);
    var h: Hash = undefined;
    try derive(io, std.testing.allocator, "secret-pin", &salt, &h);

    try std.testing.expect(try verify(io, std.testing.allocator, "secret-pin", &salt, &h));
    try std.testing.expect(!try verify(io, std.testing.allocator, "wrong-pin", &salt, &h));
}

test "a fresh salt changes the derived hash" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var s1: Salt = undefined;
    var s2: Salt = undefined;
    try genSalt(io, &s1);
    try genSalt(io, &s2);
    var h1: Hash = undefined;
    var h2: Hash = undefined;
    try derive(io, std.testing.allocator, "1234", &s1, &h1);
    try derive(io, std.testing.allocator, "1234", &s2, &h2);
    try std.testing.expect(!std.mem.eql(u8, &h1, &h2));
}
