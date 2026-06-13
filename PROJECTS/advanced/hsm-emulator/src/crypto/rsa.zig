// ©AngelaMos | 2026
// rsa.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const ossl = @import("openssl.zig");

pub const max_modulus_bytes: usize = config.rsa_max_key_bits / 8;
pub const max_sig_bytes: usize = max_modulus_bytes;
pub const pkcs1_v15_min_overhead: usize = 11;
const component_count = 8;

pub const Error = error{Crypto};

pub const Hash = enum {
    none,
    sha256,
    sha384,
    sha512,

    pub fn fromMech(mech: ck.CK_MECHANISM_TYPE) ?Hash {
        return switch (mech) {
            ck.CKM_SHA256 => .sha256,
            ck.CKM_SHA384 => .sha384,
            ck.CKM_SHA512 => .sha512,
            else => null,
        };
    }
};

fn mdOf(h: Hash) ?*const ossl.EVP_MD {
    return switch (h) {
        .none => null,
        .sha256 => ossl.EVP_sha256(),
        .sha384 => ossl.EVP_sha384(),
        .sha512 => ossl.EVP_sha512(),
    };
}

pub const SigScheme = enum { pkcs1, pss };

pub const SignParams = struct {
    scheme: SigScheme,
    digest: Hash,
    pss_hash: Hash = .sha256,
    salt_len: c_int = ossl.pss_saltlen_digest,
};

pub const CryptScheme = enum { pkcs1, oaep };

pub const CryptParams = struct {
    scheme: CryptScheme,
    oaep_hash: Hash = .sha256,
};

pub const VerifyResult = enum { ok, invalid };

pub const Buf = struct {
    bytes: [max_modulus_bytes]u8 = @splat(0),
    len: usize = 0,

    pub fn slice(self: *const Buf) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Generated = struct {
    bits: u32 = 0,
    n: Buf = .{},
    e: Buf = .{},
    d: Buf = .{},
    p: Buf = .{},
    q: Buf = .{},
    dmp1: Buf = .{},
    dmq1: Buf = .{},
    iqmp: Buf = .{},

    pub fn zeroize(self: *Generated) void {
        std.crypto.secureZero(u8, &self.d.bytes);
        std.crypto.secureZero(u8, &self.p.bytes);
        std.crypto.secureZero(u8, &self.q.bytes);
        std.crypto.secureZero(u8, &self.dmp1.bytes);
        std.crypto.secureZero(u8, &self.dmq1.bytes);
        std.crypto.secureZero(u8, &self.iqmp.bytes);
    }
};

pub const PublicComponents = struct {
    n: []const u8,
    e: []const u8,
};

pub const PrivateComponents = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dmp1: []const u8,
    dmq1: []const u8,
    iqmp: []const u8,
};

fn extractBn(pkey: *const ossl.EVP_PKEY, name: [*:0]const u8, buf: *Buf) Error!void {
    var bn: ?*ossl.BIGNUM = null;
    if (ossl.EVP_PKEY_get_bn_param(pkey, name, &bn) <= 0) return Error.Crypto;
    defer ossl.BN_clear_free(bn);
    const nbits = ossl.BN_num_bits(bn);
    if (nbits < 0) return Error.Crypto;
    const nbytes: usize = @intCast(@divFloor(nbits + 7, 8));
    if (nbytes == 0 or nbytes > max_modulus_bytes) return Error.Crypto;
    if (ossl.BN_bn2binpad(bn, &buf.bytes, @intCast(nbytes)) < 0) return Error.Crypto;
    buf.len = nbytes;
}

pub fn generate(bits: u32) Error!Generated {
    const ctx = ossl.EVP_PKEY_CTX_new_id(ossl.pkey_rsa, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_keygen_init(ctx) <= 0) return Error.Crypto;
    if (ossl.EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, @intCast(bits)) <= 0) return Error.Crypto;
    var pkey: ?*ossl.EVP_PKEY = null;
    if (ossl.EVP_PKEY_generate(ctx, &pkey) <= 0) return Error.Crypto;
    defer ossl.EVP_PKEY_free(pkey);

    const key = pkey orelse return Error.Crypto;
    var g: Generated = .{ .bits = @intCast(ossl.EVP_PKEY_get_bits(key)) };
    errdefer g.zeroize();
    try extractBn(key, ossl.param_n, &g.n);
    try extractBn(key, ossl.param_e, &g.e);
    try extractBn(key, ossl.param_d, &g.d);
    try extractBn(key, ossl.param_factor1, &g.p);
    try extractBn(key, ossl.param_factor2, &g.q);
    try extractBn(key, ossl.param_exponent1, &g.dmp1);
    try extractBn(key, ossl.param_exponent2, &g.dmq1);
    try extractBn(key, ossl.param_coefficient1, &g.iqmp);
    return g;
}

fn buildKey(names: []const [*:0]const u8, vals: []const []const u8, selection: c_int) Error!*ossl.EVP_PKEY {
    const bld = ossl.OSSL_PARAM_BLD_new() orelse return Error.Crypto;
    defer ossl.OSSL_PARAM_BLD_free(bld);

    var bns: [component_count]?*ossl.BIGNUM = @splat(null);
    defer for (bns[0..names.len]) |bn| ossl.BN_clear_free(bn);

    for (names, vals, 0..) |nm, v, i| {
        bns[i] = ossl.BN_bin2bn(v.ptr, @intCast(v.len), null) orelse return Error.Crypto;
        if (ossl.OSSL_PARAM_BLD_push_BN(bld, nm, bns[i]) <= 0) return Error.Crypto;
    }

    const params = ossl.OSSL_PARAM_BLD_to_param(bld) orelse return Error.Crypto;
    defer ossl.OSSL_PARAM_free(params);

    const ctx = ossl.EVP_PKEY_CTX_new_from_name(null, "RSA", null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_fromdata_init(ctx) <= 0) return Error.Crypto;
    var pkey: ?*ossl.EVP_PKEY = null;
    if (ossl.EVP_PKEY_fromdata(ctx, &pkey, selection, params) <= 0) return Error.Crypto;
    return pkey orelse Error.Crypto;
}

fn buildPublic(pc: PublicComponents) Error!*ossl.EVP_PKEY {
    return buildKey(
        &.{ ossl.param_n, ossl.param_e },
        &.{ pc.n, pc.e },
        ossl.selection_public_key,
    );
}

fn buildPrivate(sc: PrivateComponents) Error!*ossl.EVP_PKEY {
    return buildKey(
        &.{ ossl.param_n, ossl.param_e, ossl.param_d, ossl.param_factor1, ossl.param_factor2, ossl.param_exponent1, ossl.param_exponent2, ossl.param_coefficient1 },
        &.{ sc.n, sc.e, sc.d, sc.p, sc.q, sc.dmp1, sc.dmq1, sc.iqmp },
        ossl.selection_keypair,
    );
}

fn applyPss(pctx: ?*ossl.EVP_PKEY_CTX, p: SignParams, raw: bool) Error!void {
    if (ossl.EVP_PKEY_CTX_set_rsa_padding(pctx, ossl.pad_pss) <= 0) return Error.Crypto;
    if (raw) {
        if (ossl.EVP_PKEY_CTX_set_signature_md(pctx, mdOf(p.pss_hash)) <= 0) return Error.Crypto;
    }
    if (ossl.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, p.salt_len) <= 0) return Error.Crypto;
    if (ossl.EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, mdOf(p.pss_hash)) <= 0) return Error.Crypto;
}

pub fn sign(sc: PrivateComponents, p: SignParams, data: []const u8, out: []u8) Error!usize {
    const pkey = try buildPrivate(sc);
    defer ossl.EVP_PKEY_free(pkey);
    var siglen: usize = out.len;

    if (p.digest != .none) {
        const mdctx = ossl.EVP_MD_CTX_new() orelse return Error.Crypto;
        defer ossl.EVP_MD_CTX_free(mdctx);
        var pctx: ?*ossl.EVP_PKEY_CTX = null;
        if (ossl.EVP_DigestSignInit(mdctx, &pctx, mdOf(p.digest), null, pkey) <= 0) return Error.Crypto;
        if (p.scheme == .pss) try applyPss(pctx, p, false);
        if (ossl.EVP_DigestSign(mdctx, out.ptr, &siglen, data.ptr, data.len) <= 0) return Error.Crypto;
        return siglen;
    }

    const ctx = ossl.EVP_PKEY_CTX_new(pkey, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_sign_init(ctx) <= 0) return Error.Crypto;
    if (p.scheme == .pss) {
        try applyPss(ctx, p, true);
    } else {
        if (ossl.EVP_PKEY_CTX_set_rsa_padding(ctx, ossl.pad_pkcs1) <= 0) return Error.Crypto;
    }
    if (ossl.EVP_PKEY_sign(ctx, out.ptr, &siglen, data.ptr, data.len) <= 0) return Error.Crypto;
    return siglen;
}

pub fn verify(pc: PublicComponents, p: SignParams, data: []const u8, sig: []const u8) Error!VerifyResult {
    const pkey = try buildPublic(pc);
    defer ossl.EVP_PKEY_free(pkey);

    if (p.digest != .none) {
        const mdctx = ossl.EVP_MD_CTX_new() orelse return Error.Crypto;
        defer ossl.EVP_MD_CTX_free(mdctx);
        var pctx: ?*ossl.EVP_PKEY_CTX = null;
        if (ossl.EVP_DigestVerifyInit(mdctx, &pctx, mdOf(p.digest), null, pkey) <= 0) return Error.Crypto;
        if (p.scheme == .pss) try applyPss(pctx, p, false);
        return if (ossl.EVP_DigestVerify(mdctx, sig.ptr, sig.len, data.ptr, data.len) == 1) .ok else .invalid;
    }

    const ctx = ossl.EVP_PKEY_CTX_new(pkey, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_verify_init(ctx) <= 0) return Error.Crypto;
    if (p.scheme == .pss) {
        try applyPss(ctx, p, true);
    } else {
        if (ossl.EVP_PKEY_CTX_set_rsa_padding(ctx, ossl.pad_pkcs1) <= 0) return Error.Crypto;
    }
    return if (ossl.EVP_PKEY_verify(ctx, sig.ptr, sig.len, data.ptr, data.len) == 1) .ok else .invalid;
}

pub fn recover(pc: PublicComponents, sig: []const u8, out: []u8) Error!usize {
    const pkey = try buildPublic(pc);
    defer ossl.EVP_PKEY_free(pkey);
    const ctx = ossl.EVP_PKEY_CTX_new(pkey, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_verify_recover_init(ctx) <= 0) return Error.Crypto;
    if (ossl.EVP_PKEY_CTX_set_rsa_padding(ctx, ossl.pad_pkcs1) <= 0) return Error.Crypto;
    var outlen: usize = out.len;
    if (ossl.EVP_PKEY_verify_recover(ctx, out.ptr, &outlen, sig.ptr, sig.len) <= 0) return Error.Crypto;
    return outlen;
}

fn applyCryptPadding(ctx: ?*ossl.EVP_PKEY_CTX, p: CryptParams) Error!void {
    if (p.scheme == .oaep) {
        if (ossl.EVP_PKEY_CTX_set_rsa_padding(ctx, ossl.pad_oaep) <= 0) return Error.Crypto;
        if (ossl.EVP_PKEY_CTX_set_rsa_oaep_md(ctx, mdOf(p.oaep_hash)) <= 0) return Error.Crypto;
        if (ossl.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mdOf(p.oaep_hash)) <= 0) return Error.Crypto;
    } else {
        if (ossl.EVP_PKEY_CTX_set_rsa_padding(ctx, ossl.pad_pkcs1) <= 0) return Error.Crypto;
    }
}

pub fn encrypt(pc: PublicComponents, p: CryptParams, in: []const u8, out: []u8) Error!usize {
    const pkey = try buildPublic(pc);
    defer ossl.EVP_PKEY_free(pkey);
    const ctx = ossl.EVP_PKEY_CTX_new(pkey, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_encrypt_init(ctx) <= 0) return Error.Crypto;
    try applyCryptPadding(ctx, p);
    var outlen: usize = out.len;
    if (ossl.EVP_PKEY_encrypt(ctx, out.ptr, &outlen, in.ptr, in.len) <= 0) return Error.Crypto;
    return outlen;
}

pub fn decrypt(sc: PrivateComponents, p: CryptParams, in: []const u8, out: []u8) Error!usize {
    const pkey = try buildPrivate(sc);
    defer ossl.EVP_PKEY_free(pkey);
    const ctx = ossl.EVP_PKEY_CTX_new(pkey, null) orelse return Error.Crypto;
    defer ossl.EVP_PKEY_CTX_free(ctx);
    if (ossl.EVP_PKEY_decrypt_init(ctx) <= 0) return Error.Crypto;
    try applyCryptPadding(ctx, p);
    var outlen: usize = out.len;
    if (ossl.EVP_PKEY_decrypt(ctx, out.ptr, &outlen, in.ptr, in.len) <= 0) return Error.Crypto;
    return outlen;
}

fn testPriv(g: *const Generated) PrivateComponents {
    return .{
        .n = g.n.slice(),
        .e = g.e.slice(),
        .d = g.d.slice(),
        .p = g.p.slice(),
        .q = g.q.slice(),
        .dmp1 = g.dmp1.slice(),
        .dmq1 = g.dmq1.slice(),
        .iqmp = g.iqmp.slice(),
    };
}

fn testPub(g: *const Generated) PublicComponents {
    return .{ .n = g.n.slice(), .e = g.e.slice() };
}

test "generate yields a 2048-bit key with sane component sizes" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    try std.testing.expectEqual(@as(u32, 2048), g.bits);
    try std.testing.expectEqual(@as(usize, 256), g.n.len);
    try std.testing.expect(g.e.len >= 3 and g.e.len <= 4);
    try std.testing.expect(g.p.len == 128 and g.q.len == 128);
}

test "PKCS#1 v1.5 hash-then-sign round-trips and detects tamper" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    const params: SignParams = .{ .scheme = .pkcs1, .digest = .sha256 };
    var sig: [max_sig_bytes]u8 = undefined;
    const n = try sign(testPriv(&g), params, "enterprise message", &sig);
    try std.testing.expectEqual(@as(usize, 256), n);
    try std.testing.expectEqual(VerifyResult.ok, try verify(testPub(&g), params, "enterprise message", sig[0..n]));
    try std.testing.expectEqual(VerifyResult.invalid, try verify(testPub(&g), params, "enterprise messagX", sig[0..n]));
    sig[0] ^= 0x01;
    try std.testing.expectEqual(VerifyResult.invalid, try verify(testPub(&g), params, "enterprise message", sig[0..n]));
}

test "PSS hash-then-sign round-trips" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    const params: SignParams = .{ .scheme = .pss, .digest = .sha256, .pss_hash = .sha256 };
    var sig: [max_sig_bytes]u8 = undefined;
    const n = try sign(testPriv(&g), params, "pss payload", &sig);
    try std.testing.expectEqual(VerifyResult.ok, try verify(testPub(&g), params, "pss payload", sig[0..n]));
    try std.testing.expectEqual(VerifyResult.invalid, try verify(testPub(&g), params, "pss payloaX", sig[0..n]));
}

test "raw PKCS#1 v1.5 sign over a pre-hashed value round-trips" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    const params: SignParams = .{ .scheme = .pkcs1, .digest = .none };
    const prehash = [_]u8{0xa5} ** 32;
    var sig: [max_sig_bytes]u8 = undefined;
    const n = try sign(testPriv(&g), params, &prehash, &sig);
    try std.testing.expectEqual(VerifyResult.ok, try verify(testPub(&g), params, &prehash, sig[0..n]));
}

test "PKCS#1 v1.5 encrypt/decrypt round-trips" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    const params: CryptParams = .{ .scheme = .pkcs1 };
    const msg = "wrap me";
    var ct: [max_modulus_bytes]u8 = undefined;
    const cn = try encrypt(testPub(&g), params, msg, &ct);
    try std.testing.expectEqual(@as(usize, 256), cn);
    var pt: [max_modulus_bytes]u8 = undefined;
    const pn = try decrypt(testPriv(&g), params, ct[0..cn], &pt);
    try std.testing.expectEqualSlices(u8, msg, pt[0..pn]);
}

test "RSA sign-recover then verify-recover returns the original message" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    const params: SignParams = .{ .scheme = .pkcs1, .digest = .none };
    const msg = "recoverable enterprise payload";
    var sig: [max_sig_bytes]u8 = undefined;
    const n = try sign(testPriv(&g), params, msg, &sig);
    var rec: [max_modulus_bytes]u8 = undefined;
    const m = try recover(testPub(&g), sig[0..n], &rec);
    try std.testing.expectEqualSlices(u8, msg, rec[0..m]);
}

test "OAEP-SHA256 encrypt/decrypt round-trips" {
    var g = try generate(config.rsa_min_key_bits);
    defer g.zeroize();
    const params: CryptParams = .{ .scheme = .oaep, .oaep_hash = .sha256 };
    const msg = "oaep secret payload";
    var ct: [max_modulus_bytes]u8 = undefined;
    const cn = try encrypt(testPub(&g), params, msg, &ct);
    var pt: [max_modulus_bytes]u8 = undefined;
    const pn = try decrypt(testPriv(&g), params, ct[0..cn], &pt);
    try std.testing.expectEqualSlices(u8, msg, pt[0..pn]);
}
