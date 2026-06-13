// ©AngelaMos | 2026
// session.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const digest = @import("../crypto/digest.zig");
const mac = @import("../crypto/mac.zig");
const cipher = @import("../crypto/cipher.zig");
const ecdsa = @import("../crypto/ecdsa.zig");
const rsa = @import("../crypto/rsa.zig");

pub const Find = struct {
    matches: [config.max_objects]ck.CK_OBJECT_HANDLE = undefined,
    count: usize = 0,
    cursor: usize = 0,
    active: bool = false,
};

pub const RsaSig = struct {
    key: ck.CK_OBJECT_HANDLE,
    params: rsa.SignParams,
    sig_len: usize,
};

pub const RsaCrypt = struct {
    key: ck.CK_OBJECT_HANDLE,
    params: rsa.CryptParams,
    out_len: usize,
};

pub const RsaRecover = struct {
    key: ck.CK_OBJECT_HANDLE,
    out_len: usize,
};

pub const GcmStream = struct {
    cipher: cipher.Cipher,
    buf: ?[]u8 = null,
    len: usize = 0,

    pub fn append(self: *GcmStream, allocator: std.mem.Allocator, bytes: []const u8) error{ OutOfMemory, TooLarge }!void {
        if (bytes.len == 0) return;
        const needed = self.len + bytes.len;
        if (needed > config.max_gcm_stream_len) return error.TooLarge;
        if (self.buf == null or self.buf.?.len < needed) {
            var new_cap: usize = if (self.buf) |b| b.len else 256;
            while (new_cap < needed) new_cap *|= 2;
            if (new_cap > config.max_gcm_stream_len) new_cap = config.max_gcm_stream_len;
            const fresh = try allocator.alloc(u8, new_cap);
            if (self.buf) |old| {
                @memcpy(fresh[0..self.len], old[0..self.len]);
                std.crypto.secureZero(u8, old);
                allocator.free(old);
            }
            self.buf = fresh;
        }
        @memcpy(self.buf.?[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn data(self: *const GcmStream) []const u8 {
        return if (self.buf) |b| b[0..self.len] else &.{};
    }

    pub fn deinit(self: *GcmStream, allocator: std.mem.Allocator) void {
        if (self.buf) |b| {
            std.crypto.secureZero(u8, b);
            allocator.free(b);
        }
        self.buf = null;
        self.len = 0;
    }
};

pub const SignOp = union(enum) {
    mac: mac.Mac,
    ec: ecdsa.SignState,
    rsa: RsaSig,

    pub fn update(self: *SignOp, data: []const u8) void {
        switch (self.*) {
            .mac => |*m| m.update(data),
            .ec => |*e| e.update(data),
            .rsa => {},
        }
    }

    pub fn zeroize(self: *SignOp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const VerifyOp = union(enum) {
    mac: mac.Mac,
    ec: ecdsa.VerifyState,
    rsa: RsaSig,

    pub fn update(self: *VerifyOp, data: []const u8) void {
        switch (self.*) {
            .mac => |*m| m.update(data),
            .ec => |*e| e.update(data),
            .rsa => {},
        }
    }

    pub fn zeroize(self: *VerifyOp) void {
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const EncryptOp = union(enum) {
    aes: cipher.Cipher,
    gcm: GcmStream,
    rsa: RsaCrypt,

    pub fn deinit(self: *EncryptOp, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .gcm => |*g| g.deinit(allocator),
            else => {},
        }
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const DecryptOp = union(enum) {
    aes: cipher.Cipher,
    gcm: GcmStream,
    rsa: RsaCrypt,

    pub fn deinit(self: *DecryptOp, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .gcm => |*g| g.deinit(allocator),
            else => {},
        }
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

pub const Session = struct {
    slot: ck.CK_SLOT_ID,
    flags: ck.CK_FLAGS,
    find: Find = .{},
    digest_op: ?digest.Hasher = null,
    sign_op: ?SignOp = null,
    verify_op: ?VerifyOp = null,
    encrypt_op: ?EncryptOp = null,
    decrypt_op: ?DecryptOp = null,
    sign_recover_op: ?RsaRecover = null,
    verify_recover_op: ?RsaRecover = null,

    pub fn endDigest(self: *Session) void {
        if (self.digest_op) |*o| std.crypto.secureZero(u8, std.mem.asBytes(o));
        self.digest_op = null;
    }

    pub fn endSign(self: *Session) void {
        if (self.sign_op) |*o| o.zeroize();
        self.sign_op = null;
    }

    pub fn endVerify(self: *Session) void {
        if (self.verify_op) |*o| o.zeroize();
        self.verify_op = null;
    }

    pub fn endEncrypt(self: *Session, allocator: std.mem.Allocator) void {
        if (self.encrypt_op) |*o| o.deinit(allocator);
        self.encrypt_op = null;
    }

    pub fn endDecrypt(self: *Session, allocator: std.mem.Allocator) void {
        if (self.decrypt_op) |*o| o.deinit(allocator);
        self.decrypt_op = null;
    }

    pub fn endSignRecover(self: *Session) void {
        if (self.sign_recover_op) |*o| std.crypto.secureZero(u8, std.mem.asBytes(o));
        self.sign_recover_op = null;
    }

    pub fn endVerifyRecover(self: *Session) void {
        if (self.verify_recover_op) |*o| std.crypto.secureZero(u8, std.mem.asBytes(o));
        self.verify_recover_op = null;
    }

    pub fn freeHeap(self: *Session, allocator: std.mem.Allocator) void {
        if (self.encrypt_op) |*o| switch (o.*) {
            .gcm => |*g| g.deinit(allocator),
            else => {},
        };
        if (self.decrypt_op) |*o| switch (o.*) {
            .gcm => |*g| g.deinit(allocator),
            else => {},
        };
    }
};

pub const Table = struct {
    slots: [config.max_sessions]?Session = @splat(null),

    pub fn open(self: *Table, slot: ck.CK_SLOT_ID, flags: ck.CK_FLAGS) ?ck.CK_SESSION_HANDLE {
        for (&self.slots, 0..) |*s, i| {
            if (s.* == null) {
                std.crypto.secureZero(u8, std.mem.asBytes(s));
                s.* = .{ .slot = slot, .flags = flags };
                return @intCast(i + 1);
            }
        }
        return null;
    }

    pub fn get(self: *Table, h: ck.CK_SESSION_HANDLE) ?*Session {
        if (h == 0 or h > config.max_sessions) return null;
        if (self.slots[h - 1]) |*s| return s;
        return null;
    }

    pub fn close(self: *Table, allocator: std.mem.Allocator, h: ck.CK_SESSION_HANDLE) bool {
        if (h == 0 or h > config.max_sessions) return false;
        if (self.slots[h - 1] == null) return false;
        if (self.slots[h - 1]) |*s| s.freeHeap(allocator);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.slots[h - 1]));
        self.slots[h - 1] = null;
        return true;
    }

    pub fn closeAll(self: *Table, allocator: std.mem.Allocator, slot: ck.CK_SLOT_ID) void {
        for (&self.slots) |*s| {
            if (s.*) |*sp| {
                if (sp.slot == slot) {
                    sp.freeHeap(allocator);
                    std.crypto.secureZero(u8, std.mem.asBytes(s));
                    s.* = null;
                }
            }
        }
    }

    pub fn wipeAll(self: *Table, allocator: std.mem.Allocator) void {
        for (&self.slots) |*s| {
            if (s.*) |*sp| sp.freeHeap(allocator);
        }
        std.crypto.secureZero(u8, std.mem.asBytes(&self.slots));
    }

    pub fn anyOpen(self: *Table) bool {
        for (&self.slots) |*s| {
            if (s.* != null) return true;
        }
        return false;
    }

    pub fn count(self: *Table) ck.CK_ULONG {
        var n: ck.CK_ULONG = 0;
        for (&self.slots) |*s| {
            if (s.* != null) n += 1;
        }
        return n;
    }

    pub fn countRw(self: *Table) ck.CK_ULONG {
        var n: ck.CK_ULONG = 0;
        for (&self.slots) |*s| {
            if (s.*) |*sp| {
                if ((sp.flags & ck.CKF_RW_SESSION) != 0) n += 1;
            }
        }
        return n;
    }
};

test "open returns nonzero handles and get resolves them" {
    var t: Table = .{};
    const h1 = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const h2 = t.open(0, ck.CKF_SERIAL_SESSION | ck.CKF_RW_SESSION).?;
    try std.testing.expect(h1 != 0 and h2 != 0 and h1 != h2);
    try std.testing.expectEqual(@as(ck.CK_ULONG, 2), t.count());
    try std.testing.expectEqual(@as(ck.CK_ULONG, 1), t.countRw());
    try std.testing.expect(t.get(h1) != null);
    try std.testing.expect(t.get(9999) == null);
}

test "close frees the slot and closeAll empties the table" {
    const a = std.testing.allocator;
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    try std.testing.expect(t.close(a, h));
    try std.testing.expect(!t.close(a, h));
    try std.testing.expect(!t.anyOpen());
    _ = t.open(0, ck.CKF_SERIAL_SESSION);
    t.closeAll(a, 0);
    try std.testing.expect(!t.anyOpen());
}

fn expectAllZero(bytes: []const u8) !void {
    for (bytes) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "EncryptOp.deinit zeros the AES key material" {
    var op: EncryptOp = .{ .aes = .{ .mode = .cbc, .encrypt = true, .key_len = 32 } };
    const key: []u8 = &op.aes.key_buf;
    @memset(key, 0xAA);
    op.deinit(std.testing.allocator);
    try expectAllZero(key);
}

test "DecryptOp.deinit zeros the AES key material" {
    var op: DecryptOp = .{ .aes = .{ .mode = .cbc, .encrypt = false, .key_len = 16 } };
    const key: []u8 = &op.aes.key_buf;
    @memset(key, 0xAA);
    op.deinit(std.testing.allocator);
    try expectAllZero(key);
}

test "GcmStream secure-grows across a realloc and deinit clears it" {
    const a = std.testing.allocator;
    var g: GcmStream = .{ .cipher = .{ .mode = .gcm, .encrypt = true, .key_len = 32 } };
    var part: [200]u8 = undefined;
    for (&part, 0..) |*b, i| b.* = @intCast(i & 0xff);
    try g.append(a, &part);
    try g.append(a, &part);
    try std.testing.expectEqual(@as(usize, 400), g.len);
    try std.testing.expectEqualSlices(u8, &part, g.data()[0..200]);
    try std.testing.expectEqualSlices(u8, &part, g.data()[200..400]);
    g.deinit(a);
    try std.testing.expect(g.buf == null);
    try std.testing.expectEqual(@as(usize, 0), g.len);
}

test "GcmStream enforces the DoS bound" {
    const a = std.testing.allocator;
    var g: GcmStream = .{ .cipher = .{ .mode = .gcm, .encrypt = true, .key_len = 16 } };
    defer g.deinit(a);
    g.len = config.max_gcm_stream_len;
    try std.testing.expectError(error.TooLarge, g.append(a, "x"));
}

test "SignOp.zeroize zeros the EC private scalar" {
    const scalar = [_]u8{0xAB} ** 32;
    var op: SignOp = .{ .ec = ecdsa.SignState.init(.p256, ck.CKM_ECDSA, &scalar).? };
    const sc: []u8 = &op.ec.scalar;
    op.zeroize();
    try expectAllZero(sc);
}

test "VerifyOp.zeroize zeros HMAC key state" {
    var op: VerifyOp = .{ .mac = undefined };
    const st: []u8 = std.mem.asBytes(&op.mac);
    @memset(st, 0xCD);
    op.zeroize();
    try expectAllZero(st);
}

test "endEncrypt clears the op and removes the secret from the slot" {
    const a = std.testing.allocator;
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.encrypt_op = .{ .aes = .{ .mode = .cbc, .encrypt = true, .key_len = 32 } };
    const key: []u8 = &sess.encrypt_op.?.aes.key_buf;
    @memset(key, 0x5C);
    sess.endEncrypt(a);
    try std.testing.expect(sess.encrypt_op == null);
    try std.testing.expect(std.mem.indexOfScalar(u8, key, 0x5C) == null);
}

test "close removes an active op's secret from the slot" {
    const a = std.testing.allocator;
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.decrypt_op = .{ .aes = .{ .mode = .cbc, .encrypt = false, .key_len = 32 } };
    const key: []u8 = &sess.decrypt_op.?.aes.key_buf;
    @memset(key, 0x5C);
    try std.testing.expect(t.close(a, h));
    try std.testing.expect(std.mem.indexOfScalar(u8, key, 0x5C) == null);
}

test "close frees an active GCM stream's heap buffer" {
    const a = std.testing.allocator;
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.encrypt_op = .{ .gcm = .{ .cipher = .{ .mode = .gcm, .encrypt = true, .key_len = 32 } } };
    try sess.encrypt_op.?.gcm.append(a, "buffered-plaintext-awaiting-final");
    try std.testing.expect(t.close(a, h));
    try std.testing.expect(!t.anyOpen());
}

test "wipeAll zeros secret material in every slot" {
    const a = std.testing.allocator;
    var t: Table = .{};
    const h = t.open(0, ck.CKF_SERIAL_SESSION).?;
    const sess = t.get(h).?;
    sess.sign_op = .{ .mac = undefined };
    const st: []u8 = std.mem.asBytes(&sess.sign_op.?.mac);
    @memset(st, 0xEF);
    t.wipeAll(a);
    try expectAllZero(st);
}
