// ©AngelaMos | 2026
// digest.zig

const std = @import("std");
const ck = @import("../ck.zig");

const sha2 = std.crypto.hash.sha2;

pub const max_digest_len = sha2.Sha512.digest_length;

pub const state_tag_sha256: u8 = 1;
pub const state_tag_sha384: u8 = 2;
pub const state_tag_sha512: u8 = 3;

pub const Hasher = union(enum) {
    sha256: sha2.Sha256,
    sha384: sha2.Sha384,
    sha512: sha2.Sha512,

    pub fn init(mech: ck.CK_MECHANISM_TYPE) ?Hasher {
        return switch (mech) {
            ck.CKM_SHA256 => .{ .sha256 = sha2.Sha256.init(.{}) },
            ck.CKM_SHA384 => .{ .sha384 = sha2.Sha384.init(.{}) },
            ck.CKM_SHA512 => .{ .sha512 = sha2.Sha512.init(.{}) },
            else => null,
        };
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.*) {
            inline else => |*h| h.update(data),
        }
    }

    pub fn digestLen(self: *const Hasher) usize {
        return switch (self.*) {
            inline else => |h| @TypeOf(h).digest_length,
        };
    }

    pub fn finalInto(self: *Hasher, out: []u8) void {
        switch (self.*) {
            inline else => |*h| {
                const Hash = @TypeOf(h.*);
                h.final(out[0..Hash.digest_length]);
            },
        }
    }

    pub fn stateTag(self: *const Hasher) u8 {
        return switch (self.*) {
            .sha256 => state_tag_sha256,
            .sha384 => state_tag_sha384,
            .sha512 => state_tag_sha512,
        };
    }

    pub fn stateLen(self: *const Hasher) usize {
        return switch (self.*) {
            inline else => |*h| @sizeOf(@TypeOf(h.*)),
        };
    }

    pub fn writeState(self: *const Hasher, out: []u8) void {
        switch (self.*) {
            inline else => |*h| @memcpy(out[0..@sizeOf(@TypeOf(h.*))], std.mem.asBytes(h)),
        }
    }

    pub fn fromState(tag: u8, bytes: []const u8) ?Hasher {
        switch (tag) {
            state_tag_sha256 => {
                if (bytes.len != @sizeOf(sha2.Sha256)) return null;
                var h: Hasher = .{ .sha256 = undefined };
                @memcpy(std.mem.asBytes(&h.sha256), bytes);
                return h;
            },
            state_tag_sha384 => {
                if (bytes.len != @sizeOf(sha2.Sha384)) return null;
                var h: Hasher = .{ .sha384 = undefined };
                @memcpy(std.mem.asBytes(&h.sha384), bytes);
                return h;
            },
            state_tag_sha512 => {
                if (bytes.len != @sizeOf(sha2.Sha512)) return null;
                var h: Hasher = .{ .sha512 = undefined };
                @memcpy(std.mem.asBytes(&h.sha512), bytes);
                return h;
            },
            else => return null,
        }
    }
};

pub fn digestLenOf(mech: ck.CK_MECHANISM_TYPE) ?usize {
    return switch (mech) {
        ck.CKM_SHA256 => sha2.Sha256.digest_length,
        ck.CKM_SHA384 => sha2.Sha384.digest_length,
        ck.CKM_SHA512 => sha2.Sha512.digest_length,
        else => null,
    };
}

test "one-shot digest matches a known SHA-256 vector" {
    var h = Hasher.init(ck.CKM_SHA256).?;
    h.update("abc");
    var out: [max_digest_len]u8 = undefined;
    h.finalInto(&out);
    const expect = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqual(@as(usize, 32), h.digestLen());
    try std.testing.expectEqualSlices(u8, &expect, out[0..32]);
}

test "multi-part digest equals single-part" {
    var a = Hasher.init(ck.CKM_SHA512).?;
    a.update("hello world");
    var oa: [max_digest_len]u8 = undefined;
    a.finalInto(&oa);

    var b = Hasher.init(ck.CKM_SHA512).?;
    b.update("hello ");
    b.update("world");
    var ob: [max_digest_len]u8 = undefined;
    b.finalInto(&ob);

    try std.testing.expectEqualSlices(u8, oa[0..64], ob[0..64]);
}

test "unknown mechanism yields null" {
    try std.testing.expect(Hasher.init(ck.CKM_AES_CBC) == null);
    try std.testing.expect(digestLenOf(ck.CKM_SHA384).? == 48);
}

test "op-state serialize then restore continues the same digest" {
    var a = Hasher.init(ck.CKM_SHA256).?;
    a.update("first part ");

    var blob: [1 + @sizeOf(sha2.Sha512)]u8 = undefined;
    const tag = a.stateTag();
    const len = a.stateLen();
    a.writeState(blob[0..len]);

    var b = Hasher.fromState(tag, blob[0..len]).?;
    a.update("second part");
    b.update("second part");

    var oa: [max_digest_len]u8 = undefined;
    var ob: [max_digest_len]u8 = undefined;
    a.finalInto(&oa);
    b.finalInto(&ob);
    try std.testing.expectEqualSlices(u8, oa[0..32], ob[0..32]);

    try std.testing.expect(Hasher.fromState(99, blob[0..len]) == null);
    try std.testing.expect(Hasher.fromState(tag, blob[0 .. len - 1]) == null);
}
