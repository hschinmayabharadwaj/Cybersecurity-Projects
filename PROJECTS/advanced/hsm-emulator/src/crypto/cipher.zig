// ©AngelaMos | 2026
// cipher.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");

const aes = std.crypto.core.aes;
const aesgcm = std.crypto.aead.aes_gcm;

const block = config.aes_block_len;

pub const Mode = enum { cbc, cbc_pad, gcm };

pub const Error = error{
    KeySize,
    DataLenRange,
    EncryptedDataLenRange,
    EncryptedDataInvalid,
    AadTooLarge,
    IvInvalid,
};

pub fn modeOf(mech: ck.CK_MECHANISM_TYPE) ?Mode {
    return switch (mech) {
        ck.CKM_AES_CBC => .cbc,
        ck.CKM_AES_CBC_PAD => .cbc_pad,
        ck.CKM_AES_GCM => .gcm,
        else => null,
    };
}

pub fn validKeyLen(len: usize) bool {
    return len == config.aes_min_key_bytes or len == config.aes_max_key_bytes;
}

fn encBlockRaw(key: []const u8, in: *const [block]u8, out: *[block]u8) void {
    switch (key.len) {
        16 => aes.Aes128.initEnc(key[0..16].*).encrypt(out, in),
        32 => aes.Aes256.initEnc(key[0..32].*).encrypt(out, in),
        else => unreachable,
    }
}

fn decBlockRaw(key: []const u8, in: *const [block]u8, out: *[block]u8) void {
    switch (key.len) {
        16 => aes.Aes128.initDec(key[0..16].*).decrypt(out, in),
        32 => aes.Aes256.initDec(key[0..32].*).decrypt(out, in),
        else => unreachable,
    }
}

pub const Cipher = struct {
    mode: Mode,
    encrypt: bool,
    key_buf: [32]u8 = @splat(0),
    key_len: u8 = 0,
    chain: [block]u8 = @splat(0),
    partial: [block]u8 = @splat(0),
    partial_len: u8 = 0,
    held: [block]u8 = @splat(0),
    has_held: bool = false,
    iv: [config.gcm_iv_len]u8 = @splat(0),
    aad_buf: [config.max_gcm_aad_len]u8 = @splat(0),
    aad_len: usize = 0,

    fn key(self: *const Cipher) []const u8 {
        return self.key_buf[0..self.key_len];
    }

    fn cbcEncStep(self: *Cipher, in16: *const [block]u8, out16: *[block]u8) void {
        var x: [block]u8 = undefined;
        defer std.crypto.secureZero(u8, &x);
        for (0..block) |j| x[j] = in16[j] ^ self.chain[j];
        encBlockRaw(self.key(), &x, out16);
        self.chain = out16.*;
    }

    fn cbcDecStep(self: *Cipher, in16: *const [block]u8, out16: *[block]u8) void {
        var d: [block]u8 = undefined;
        defer std.crypto.secureZero(u8, &d);
        decBlockRaw(self.key(), in16, &d);
        for (0..block) |j| out16[j] = d[j] ^ self.chain[j];
        self.chain = in16.*;
    }

    pub fn encryptUpdate(self: *Cipher, input: []const u8, out: []u8) usize {
        var o: usize = 0;
        var i: usize = 0;
        while (i < input.len) {
            const take = @min(block - self.partial_len, input.len - i);
            @memcpy(self.partial[self.partial_len..][0..take], input[i .. i + take]);
            self.partial_len += @intCast(take);
            i += take;
            if (self.partial_len == block) {
                self.cbcEncStep(&self.partial, out[o..][0..block]);
                o += block;
                self.partial_len = 0;
            }
        }
        return o;
    }

    pub fn encryptFinal(self: *Cipher, out: []u8) Error!usize {
        if (self.mode == .cbc) {
            if (self.partial_len != 0) return Error.DataLenRange;
            return 0;
        }
        const padlen: u8 = @intCast(block - self.partial_len);
        for (self.partial_len..block) |j| self.partial[j] = padlen;
        self.cbcEncStep(&self.partial, out[0..block]);
        self.partial_len = 0;
        return block;
    }

    pub fn decryptUpdate(self: *Cipher, input: []const u8, out: []u8) usize {
        var o: usize = 0;
        var i: usize = 0;
        while (i < input.len) {
            const take = @min(block - self.partial_len, input.len - i);
            @memcpy(self.partial[self.partial_len..][0..take], input[i .. i + take]);
            self.partial_len += @intCast(take);
            i += take;
            if (self.partial_len == block) {
                if (self.mode == .cbc_pad) {
                    if (self.has_held) {
                        self.cbcDecStep(&self.held, out[o..][0..block]);
                        o += block;
                    }
                    self.held = self.partial;
                    self.has_held = true;
                } else {
                    self.cbcDecStep(&self.partial, out[o..][0..block]);
                    o += block;
                }
                self.partial_len = 0;
            }
        }
        return o;
    }

    pub fn decryptFinal(self: *Cipher, out: []u8) Error!usize {
        if (self.partial_len != 0) return Error.EncryptedDataLenRange;
        if (self.mode == .cbc) return 0;
        if (!self.has_held) return Error.EncryptedDataLenRange;
        var pt: [block]u8 = undefined;
        defer std.crypto.secureZero(u8, &pt);
        self.cbcDecStep(&self.held, &pt);
        self.has_held = false;
        const padlen = pt[block - 1];
        if (padlen == 0 or padlen > block) return Error.EncryptedDataInvalid;
        var bad: u8 = 0;
        for (0..block) |j| {
            const is_pad = j >= block - padlen;
            if (is_pad) bad |= pt[j] ^ padlen;
        }
        if (bad != 0) return Error.EncryptedDataInvalid;
        const keep = block - padlen;
        @memcpy(out[0..keep], pt[0..keep]);
        return keep;
    }

    pub fn gcmEncrypt(self: *Cipher, input: []const u8, out: []u8) usize {
        std.debug.assert(out.len >= input.len + config.gcm_tag_len);
        const tag: *[config.gcm_tag_len]u8 = out[input.len..][0..config.gcm_tag_len];
        const ad = self.aad_buf[0..self.aad_len];
        switch (self.key_len) {
            16 => aesgcm.Aes128Gcm.encrypt(out[0..input.len], tag, input, ad, self.iv, self.key_buf[0..16].*),
            32 => aesgcm.Aes256Gcm.encrypt(out[0..input.len], tag, input, ad, self.iv, self.key_buf[0..32].*),
            else => unreachable,
        }
        return input.len + config.gcm_tag_len;
    }

    pub fn gcmDecrypt(self: *Cipher, input: []const u8, out: []u8) Error!usize {
        if (input.len < config.gcm_tag_len) return Error.EncryptedDataLenRange;
        const ct_len = input.len - config.gcm_tag_len;
        std.debug.assert(out.len >= ct_len);
        const tag: [config.gcm_tag_len]u8 = input[ct_len..][0..config.gcm_tag_len].*;
        const ad = self.aad_buf[0..self.aad_len];
        switch (self.key_len) {
            16 => aesgcm.Aes128Gcm.decrypt(out[0..ct_len], input[0..ct_len], tag, ad, self.iv, self.key_buf[0..16].*) catch return Error.EncryptedDataInvalid,
            32 => aesgcm.Aes256Gcm.decrypt(out[0..ct_len], input[0..ct_len], tag, ad, self.iv, self.key_buf[0..32].*) catch return Error.EncryptedDataInvalid,
            else => unreachable,
        }
        return ct_len;
    }
};

pub fn encryptOutLen(mode: Mode, in_len: usize) usize {
    return switch (mode) {
        .cbc => in_len,
        .cbc_pad => (in_len / block + 1) * block,
        .gcm => in_len + config.gcm_tag_len,
    };
}

pub fn decryptOutLen(mode: Mode, in_len: usize) usize {
    return switch (mode) {
        .cbc, .cbc_pad => in_len,
        .gcm => if (in_len >= config.gcm_tag_len) in_len - config.gcm_tag_len else 0,
    };
}

pub const WrapError = error{ KeySize, DataLen, Integrity };

pub const key_wrap_overhead = 8;

const key_wrap_iv = [8]u8{ 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

fn xorCounter(a: *[8]u8, t: u64) void {
    var tb: [8]u8 = undefined;
    std.mem.writeInt(u64, &tb, t, .big);
    for (a, tb) |*x, y| x.* ^= y;
}

pub fn aesKeyWrap(kek: []const u8, plain: []const u8, out: []u8) WrapError!usize {
    if (kek.len != config.aes_min_key_bytes and kek.len != config.aes_max_key_bytes) return WrapError.KeySize;
    if (plain.len < 2 * key_wrap_overhead or plain.len % key_wrap_overhead != 0) return WrapError.DataLen;
    std.debug.assert(out.len >= plain.len + key_wrap_overhead);
    const n = plain.len / key_wrap_overhead;
    @memcpy(out[key_wrap_overhead..][0..plain.len], plain);
    const r = out[key_wrap_overhead..][0..plain.len];
    var a: [8]u8 = key_wrap_iv;
    var blk: [block]u8 = undefined;
    var enc: [block]u8 = undefined;
    defer {
        std.crypto.secureZero(u8, &a);
        std.crypto.secureZero(u8, &blk);
        std.crypto.secureZero(u8, &enc);
    }
    var j: usize = 0;
    while (j < 6) : (j += 1) {
        var i: usize = 0;
        while (i < n) : (i += 1) {
            @memcpy(blk[0..8], &a);
            @memcpy(blk[8..16], r[i * 8 ..][0..8]);
            encBlockRaw(kek, &blk, &enc);
            @memcpy(&a, enc[0..8]);
            xorCounter(&a, n * j + i + 1);
            @memcpy(r[i * 8 ..][0..8], enc[8..16]);
        }
    }
    @memcpy(out[0..8], &a);
    return plain.len + key_wrap_overhead;
}

pub fn aesKeyUnwrap(kek: []const u8, wrapped: []const u8, out: []u8) WrapError!usize {
    if (kek.len != config.aes_min_key_bytes and kek.len != config.aes_max_key_bytes) return WrapError.KeySize;
    if (wrapped.len < 3 * key_wrap_overhead or wrapped.len % key_wrap_overhead != 0) return WrapError.DataLen;
    const n = wrapped.len / key_wrap_overhead - 1;
    const plain_len = n * key_wrap_overhead;
    std.debug.assert(out.len >= plain_len);
    @memcpy(out[0..plain_len], wrapped[key_wrap_overhead..][0..plain_len]);
    const r = out[0..plain_len];
    var a: [8]u8 = undefined;
    @memcpy(&a, wrapped[0..8]);
    var blk: [block]u8 = undefined;
    var dec: [block]u8 = undefined;
    defer {
        std.crypto.secureZero(u8, &a);
        std.crypto.secureZero(u8, &blk);
        std.crypto.secureZero(u8, &dec);
    }
    var j: usize = 6;
    while (j > 0) {
        j -= 1;
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            xorCounter(&a, n * j + i + 1);
            @memcpy(blk[0..8], &a);
            @memcpy(blk[8..16], r[i * 8 ..][0..8]);
            decBlockRaw(kek, &blk, &dec);
            @memcpy(&a, dec[0..8]);
            @memcpy(r[i * 8 ..][0..8], dec[8..16]);
        }
    }
    var diff: u8 = 0;
    for (a, key_wrap_iv) |x, y| diff |= x ^ y;
    if (diff != 0) {
        std.crypto.secureZero(u8, out[0..plain_len]);
        return WrapError.Integrity;
    }
    return plain_len;
}

fn testKey() [32]u8 {
    var k: [32]u8 = undefined;
    for (0..32) |j| k[j] = @intCast(j);
    return k;
}

test "AES-256-CBC single-block matches a NIST SP800-38A vector" {
    const key = [_]u8{
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    const iv = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const pt = [_]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    const expect = [_]u8{ 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6 };

    var c: Cipher = .{ .mode = .cbc, .encrypt = true, .key_len = 32 };
    c.key_buf = key;
    c.chain = iv;
    var out: [16]u8 = undefined;
    const n = c.encryptUpdate(&pt, &out);
    try std.testing.expectEqual(@as(usize, 16), n);
    try std.testing.expectEqualSlices(u8, &expect, &out);
}

test "CBC-PAD round-trips arbitrary lengths" {
    const key = testKey();
    const iv = [_]u8{1} ** 16;
    for ([_]usize{ 0, 1, 15, 16, 17, 100 }) |len| {
        var pt: [100]u8 = undefined;
        for (0..len) |j| pt[j] = @intCast((j * 7) & 0xff);

        var enc: Cipher = .{ .mode = .cbc_pad, .encrypt = true, .key_len = 32 };
        enc.key_buf = key;
        enc.chain = iv;
        var ct: [128]u8 = undefined;
        var cn = enc.encryptUpdate(pt[0..len], &ct);
        cn += try enc.encryptFinal(ct[cn..]);
        try std.testing.expectEqual(encryptOutLen(.cbc_pad, len), cn);

        var dec: Cipher = .{ .mode = .cbc_pad, .encrypt = false, .key_len = 32 };
        dec.key_buf = key;
        dec.chain = iv;
        var back: [128]u8 = undefined;
        var bn = dec.decryptUpdate(ct[0..cn], &back);
        bn += try dec.decryptFinal(back[bn..]);
        try std.testing.expectEqual(len, bn);
        try std.testing.expectEqualSlices(u8, pt[0..len], back[0..bn]);
    }
}

test "CBC-PAD streaming in small chunks equals one-shot" {
    const key = testKey();
    const iv = [_]u8{2} ** 16;
    var pt: [70]u8 = undefined;
    for (0..70) |j| pt[j] = @intCast(j);

    var enc: Cipher = .{ .mode = .cbc_pad, .encrypt = true, .key_len = 16 };
    enc.key_buf = key;
    enc.chain = iv;
    var ct: [96]u8 = undefined;
    var cn = enc.encryptUpdate(&pt, &ct);
    cn += try enc.encryptFinal(ct[cn..]);

    var dec: Cipher = .{ .mode = .cbc_pad, .encrypt = false, .key_len = 16 };
    dec.key_buf = key;
    dec.chain = iv;
    var back: [96]u8 = undefined;
    var bn: usize = 0;
    var i: usize = 0;
    while (i < cn) : (i += 7) {
        const end = @min(i + 7, cn);
        bn += dec.decryptUpdate(ct[i..end], back[bn..]);
    }
    bn += try dec.decryptFinal(back[bn..]);
    try std.testing.expectEqual(@as(usize, 70), bn);
    try std.testing.expectEqualSlices(u8, &pt, back[0..bn]);
}

test "GCM round-trips and rejects a tampered tag" {
    const key = testKey();
    var c: Cipher = .{ .mode = .gcm, .encrypt = true, .key_len = 32 };
    c.key_buf = key;
    c.iv = [_]u8{7} ** 12;
    const pt = "authenticated secret";
    var ct: [64]u8 = undefined;
    const cn = c.gcmEncrypt(pt, &ct);
    try std.testing.expectEqual(pt.len + 16, cn);

    var d: Cipher = .{ .mode = .gcm, .encrypt = false, .key_len = 32 };
    d.key_buf = key;
    d.iv = [_]u8{7} ** 12;
    var back: [64]u8 = undefined;
    const bn = try d.gcmDecrypt(ct[0..cn], &back);
    try std.testing.expectEqualSlices(u8, pt, back[0..bn]);

    ct[0] ^= 0x01;
    var d2: Cipher = .{ .mode = .gcm, .encrypt = false, .key_len = 32 };
    d2.key_buf = key;
    d2.iv = [_]u8{7} ** 12;
    try std.testing.expectError(Error.EncryptedDataInvalid, d2.gcmDecrypt(ct[0..cn], &back));
}

test "AES-128 key wrap matches the RFC 3394 section 4.1 KAT and unwraps" {
    const kek = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const plain = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    const expect = [_]u8{ 0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5 };

    var out: [24]u8 = undefined;
    const n = try aesKeyWrap(&kek, &plain, &out);
    try std.testing.expectEqual(@as(usize, 24), n);
    try std.testing.expectEqualSlices(u8, &expect, &out);

    var back: [16]u8 = undefined;
    const m = try aesKeyUnwrap(&kek, &out, &back);
    try std.testing.expectEqual(@as(usize, 16), m);
    try std.testing.expectEqualSlices(u8, &plain, &back);
}

test "AES-256 key wrap round-trips 256-bit key material and rejects tampering" {
    const kek = testKey();
    var plain: [32]u8 = undefined;
    for (0..32) |k| plain[k] = @intCast((k * 11) & 0xff);

    var wrapped: [40]u8 = undefined;
    const n = try aesKeyWrap(&kek, &plain, &wrapped);
    try std.testing.expectEqual(@as(usize, 40), n);

    var back: [32]u8 = undefined;
    const m = try aesKeyUnwrap(&kek, &wrapped, &back);
    try std.testing.expectEqual(@as(usize, 32), m);
    try std.testing.expectEqualSlices(u8, &plain, &back);

    wrapped[3] ^= 0x01;
    try std.testing.expectError(WrapError.Integrity, aesKeyUnwrap(&kek, &wrapped, &back));
}

test "AES key wrap rejects bad input and KEK lengths" {
    const kek = testKey();
    var out: [64]u8 = undefined;
    try std.testing.expectError(WrapError.DataLen, aesKeyWrap(&kek, &[_]u8{0} ** 8, &out));
    try std.testing.expectError(WrapError.DataLen, aesKeyWrap(&kek, &[_]u8{0} ** 20, &out));
    try std.testing.expectError(WrapError.DataLen, aesKeyUnwrap(&kek, &[_]u8{0} ** 16, &out));
    try std.testing.expectError(WrapError.KeySize, aesKeyWrap(&[_]u8{0} ** 24, &[_]u8{0} ** 16, &out));
}
