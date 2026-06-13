// ©AngelaMos | 2026
// keystore.zig

const std = @import("std");
const config = @import("../config.zig");
const pin = @import("pin.zig");

const gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const mk_len = config.master_key_len;
pub const nonce_len = config.gcm_iv_len;
pub const tag_len = config.gcm_tag_len;
pub const seal_overhead = nonce_len + tag_len;

pub const MasterKey = [mk_len]u8;
pub const Salt = pin.Salt;

pub const Error = error{ Malformed, AuthFailed };

pub const Wrapped = struct {
    salt: Salt = @splat(0),
    nonce: [nonce_len]u8 = @splat(0),
    ct: [mk_len]u8 = @splat(0),
    tag: [tag_len]u8 = @splat(0),
};

pub fn deriveKek(io: std.Io, allocator: std.mem.Allocator, pin_bytes: []const u8, salt: *const Salt, out: *MasterKey) !void {
    try pin.derive(io, allocator, pin_bytes, salt, out);
}

pub fn generateMasterKey(io: std.Io, out: *MasterKey) !void {
    try io.randomSecure(out);
}

pub fn wrap(io: std.Io, allocator: std.mem.Allocator, pin_bytes: []const u8, mk: *const MasterKey) !Wrapped {
    var w: Wrapped = .{};
    try pin.genSalt(io, &w.salt);
    var kek: MasterKey = undefined;
    defer std.crypto.secureZero(u8, &kek);
    try deriveKek(io, allocator, pin_bytes, &w.salt, &kek);
    try io.randomSecure(&w.nonce);
    gcm.encrypt(&w.ct, &w.tag, mk, "", w.nonce, kek);
    return w;
}

pub fn rewrap(io: std.Io, allocator: std.mem.Allocator, pin_bytes: []const u8, mk: *const MasterKey) !Wrapped {
    return wrap(io, allocator, pin_bytes, mk);
}

pub fn unwrap(io: std.Io, allocator: std.mem.Allocator, pin_bytes: []const u8, w: *const Wrapped, out: *MasterKey) !bool {
    var kek: MasterKey = undefined;
    defer std.crypto.secureZero(u8, &kek);
    try deriveKek(io, allocator, pin_bytes, &w.salt, &kek);
    gcm.decrypt(out, &w.ct, w.tag, "", w.nonce, kek) catch {
        std.crypto.secureZero(u8, out);
        return false;
    };
    return true;
}

pub fn sealedLen(plain_len: usize) usize {
    return nonce_len + plain_len + tag_len;
}

pub fn seal(io: std.Io, mk: *const MasterKey, ad: []const u8, plain: []const u8, out: []u8) !usize {
    var nonce: [nonce_len]u8 = undefined;
    try io.randomSecure(&nonce);
    @memcpy(out[0..nonce_len], &nonce);
    const ct = out[nonce_len..][0..plain.len];
    const tag = out[nonce_len + plain.len ..][0..tag_len];
    gcm.encrypt(ct, tag, plain, ad, nonce, mk.*);
    return sealedLen(plain.len);
}

pub fn unseal(mk: *const MasterKey, ad: []const u8, sealed: []const u8, out: []u8) Error!usize {
    if (sealed.len < seal_overhead) return Error.Malformed;
    const ct_len = sealed.len - seal_overhead;
    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&nonce, sealed[0..nonce_len]);
    var tag: [tag_len]u8 = undefined;
    @memcpy(&tag, sealed[nonce_len + ct_len ..][0..tag_len]);
    const ct = sealed[nonce_len..][0..ct_len];
    gcm.decrypt(out[0..ct_len], ct, tag, ad, nonce, mk.*) catch return Error.AuthFailed;
    return ct_len;
}

test "master key wrap then unwrap round-trips under the right PIN" {
    const io = std.testing.io;
    const a = std.testing.allocator;
    var mk: MasterKey = undefined;
    try generateMasterKey(io, &mk);

    const w = try wrap(io, a, "1234", &mk);
    var got: MasterKey = undefined;
    try std.testing.expect(try unwrap(io, a, "1234", &w, &got));
    try std.testing.expectEqualSlices(u8, &mk, &got);
}

test "unwrap with the wrong PIN fails the GCM tag and yields false" {
    const io = std.testing.io;
    const a = std.testing.allocator;
    var mk: MasterKey = undefined;
    try generateMasterKey(io, &mk);

    const w = try wrap(io, a, "1234", &mk);
    var got: MasterKey = undefined;
    try std.testing.expect(!try unwrap(io, a, "9999", &w, &got));
}

test "rewrap under a new PIN keeps the same master key recoverable" {
    const io = std.testing.io;
    const a = std.testing.allocator;
    var mk: MasterKey = undefined;
    try generateMasterKey(io, &mk);

    const w1 = try wrap(io, a, "old-pin", &mk);
    var unwrapped: MasterKey = undefined;
    try std.testing.expect(try unwrap(io, a, "old-pin", &w1, &unwrapped));

    const w2 = try rewrap(io, a, "new-pin", &unwrapped);
    var got: MasterKey = undefined;
    try std.testing.expect(!try unwrap(io, a, "old-pin", &w2, &got));
    try std.testing.expect(try unwrap(io, a, "new-pin", &w2, &got));
    try std.testing.expectEqualSlices(u8, &mk, &got);
}

test "seal then unseal round-trips and binds the AAD" {
    const io = std.testing.io;
    var mk: MasterKey = undefined;
    try generateMasterKey(io, &mk);

    const secret = "private-scalar-bytes";
    const ad = "\x11\x00\x00\x00\x00\x00\x00\x00";
    var sealed: [64]u8 = undefined;
    const sn = try seal(io, &mk, ad, secret, &sealed);
    try std.testing.expectEqual(sealedLen(secret.len), sn);

    var out: [64]u8 = undefined;
    const un = try unseal(&mk, ad, sealed[0..sn], &out);
    try std.testing.expectEqualSlices(u8, secret, out[0..un]);

    try std.testing.expectError(Error.AuthFailed, unseal(&mk, "\x12\x00\x00\x00\x00\x00\x00\x00", sealed[0..sn], &out));
    sealed[0] ^= 0x01;
    try std.testing.expectError(Error.AuthFailed, unseal(&mk, ad, sealed[0..sn], &out));
}
