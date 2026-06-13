// ©AngelaMos | 2026
// mac.zig

const std = @import("std");
const ck = @import("../ck.zig");

const hmac = std.crypto.auth.hmac.sha2;

pub const max_mac_len = hmac.HmacSha512.mac_length;

pub const Mac = union(enum) {
    sha256: hmac.HmacSha256,
    sha384: hmac.HmacSha384,
    sha512: hmac.HmacSha512,

    pub fn init(mech: ck.CK_MECHANISM_TYPE, key: []const u8) ?Mac {
        return switch (mech) {
            ck.CKM_SHA256_HMAC => .{ .sha256 = hmac.HmacSha256.init(key) },
            ck.CKM_SHA384_HMAC => .{ .sha384 = hmac.HmacSha384.init(key) },
            ck.CKM_SHA512_HMAC => .{ .sha512 = hmac.HmacSha512.init(key) },
            else => null,
        };
    }

    pub fn update(self: *Mac, data: []const u8) void {
        switch (self.*) {
            inline else => |*m| m.update(data),
        }
    }

    pub fn macLen(self: *const Mac) usize {
        return switch (self.*) {
            inline else => |m| @TypeOf(m).mac_length,
        };
    }

    pub fn finalInto(self: *Mac, out: []u8) void {
        switch (self.*) {
            inline else => |*m| {
                const M = @TypeOf(m.*);
                m.final(out[0..M.mac_length]);
            },
        }
    }
};

pub fn macLenOf(mech: ck.CK_MECHANISM_TYPE) ?usize {
    return switch (mech) {
        ck.CKM_SHA256_HMAC => hmac.HmacSha256.mac_length,
        ck.CKM_SHA384_HMAC => hmac.HmacSha384.mac_length,
        ck.CKM_SHA512_HMAC => hmac.HmacSha512.mac_length,
        else => null,
    };
}

test "HMAC-SHA256 matches RFC 4231 test case 2" {
    var m = Mac.init(ck.CKM_SHA256_HMAC, "Jefe").?;
    m.update("what do ya want ");
    m.update("for nothing?");
    var out: [max_mac_len]u8 = undefined;
    m.finalInto(&out);
    const expect = [_]u8{
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    try std.testing.expectEqual(@as(usize, 32), m.macLen());
    try std.testing.expectEqualSlices(u8, &expect, out[0..32]);
}

test "macLenOf maps mechanisms and rejects non-HMAC" {
    try std.testing.expectEqual(@as(?usize, 48), macLenOf(ck.CKM_SHA384_HMAC));
    try std.testing.expectEqual(@as(?usize, 64), macLenOf(ck.CKM_SHA512_HMAC));
    try std.testing.expect(macLenOf(ck.CKM_SHA256) == null);
}
