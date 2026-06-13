// ©AngelaMos | 2026
// ecdsa.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const digest = @import("digest.zig");

const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;

pub const max_scalar = P384.SecretKey.encoded_length;
pub const max_point = P384.PublicKey.uncompressed_sec1_encoded_length;
pub const max_sig = P384.Signature.encoded_length;
pub const max_prehash = digest.max_digest_len;
pub const max_ec_point_der = 2 + max_point;

const der_octet_string: u8 = 0x04;
const der_long_form_bit: u8 = 0x80;

const oid_p256 = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };

pub const Error = error{
    Random,
    Generate,
    Crypto,
};

pub const Curve = enum {
    p256,
    p384,

    pub fn scalarLen(self: Curve) usize {
        return switch (self) {
            .p256 => P256.SecretKey.encoded_length,
            .p384 => P384.SecretKey.encoded_length,
        };
    }

    pub fn pointLen(self: Curve) usize {
        return switch (self) {
            .p256 => P256.PublicKey.uncompressed_sec1_encoded_length,
            .p384 => P384.PublicKey.uncompressed_sec1_encoded_length,
        };
    }

    pub fn sigLen(self: Curve) usize {
        return switch (self) {
            .p256 => P256.Signature.encoded_length,
            .p384 => P384.Signature.encoded_length,
        };
    }

    pub fn bits(self: Curve) ck.CK_ULONG {
        return switch (self) {
            .p256 => config.ec_min_key_bits,
            .p384 => config.ec_max_key_bits,
        };
    }

    pub fn oidDer(self: Curve) []const u8 {
        return switch (self) {
            .p256 => &oid_p256,
            .p384 => &oid_p384,
        };
    }
};

pub const HashMode = enum { raw, sha256 };

pub fn hashModeOf(mech: ck.CK_MECHANISM_TYPE) ?HashMode {
    return switch (mech) {
        ck.CKM_ECDSA => .raw,
        ck.CKM_ECDSA_SHA256 => .sha256,
        else => null,
    };
}

pub fn curveFromParams(ec_params: []const u8) ?Curve {
    if (std.mem.eql(u8, ec_params, &oid_p256)) return .p256;
    if (std.mem.eql(u8, ec_params, &oid_p384)) return .p384;
    return null;
}

pub fn wrapEcPoint(out: []u8, sec1: []const u8) []u8 {
    out[0] = der_octet_string;
    out[1] = @intCast(sec1.len);
    @memcpy(out[2..][0..sec1.len], sec1);
    return out[0 .. 2 + sec1.len];
}

pub fn unwrapEcPoint(der: []const u8) ?[]const u8 {
    if (der.len < 2 or der[0] != der_octet_string) return null;
    if (der[1] & der_long_form_bit == 0) {
        const len: usize = der[1];
        if (2 + len != der.len) return null;
        return der[2 .. 2 + len];
    }
    const nlen: usize = der[1] & ~der_long_form_bit;
    if (nlen == 0 or nlen > 2 or der.len < 2 + nlen) return null;
    var len: usize = 0;
    for (der[2 .. 2 + nlen]) |b| len = (len << 8) | b;
    if (2 + nlen + len != der.len) return null;
    return der[2 + nlen .. 2 + nlen + len];
}

pub const KeyMaterial = struct {
    curve: Curve,
    scalar: [max_scalar]u8 = @splat(0),
    point: [max_point]u8 = @splat(0),

    pub fn scalarBytes(self: *const KeyMaterial) []const u8 {
        return self.scalar[0..self.curve.scalarLen()];
    }

    pub fn pointBytes(self: *const KeyMaterial) []const u8 {
        return self.point[0..self.curve.pointLen()];
    }
};

pub fn generate(io: std.Io, curve: Curve) Error!KeyMaterial {
    return switch (curve) {
        .p256 => generateImpl(P256, io, curve),
        .p384 => generateImpl(P384, io, curve),
    };
}

fn generateImpl(comptime Scheme: type, io: std.Io, curve: Curve) Error!KeyMaterial {
    var attempt: usize = 0;
    while (attempt < config.ec_keygen_max_attempts) : (attempt += 1) {
        var seed: [Scheme.KeyPair.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        io.randomSecure(&seed) catch return Error.Random;
        const kp = Scheme.KeyPair.generateDeterministic(seed) catch continue;
        var km: KeyMaterial = .{ .curve = curve };
        const sk = kp.secret_key.toBytes();
        @memcpy(km.scalar[0..sk.len], &sk);
        const pt = kp.public_key.toUncompressedSec1();
        @memcpy(km.point[0..pt.len], &pt);
        return km;
    }
    return Error.Generate;
}

fn reduce(curve: Curve, dgst: []const u8, out: *[max_scalar]u8) []const u8 {
    const n = curve.scalarLen();
    @memset(out[0..n], 0);
    if (dgst.len >= n) {
        @memcpy(out[0..n], dgst[0..n]);
    } else {
        @memcpy(out[n - dgst.len .. n], dgst);
    }
    return out[0..n];
}

const Accum = struct {
    mode: HashMode,
    hasher: ?digest.Hasher = null,
    raw: [max_prehash]u8 = @splat(0),
    raw_len: usize = 0,

    fn init(mode: HashMode) Accum {
        return .{
            .mode = mode,
            .hasher = if (mode == .sha256) digest.Hasher.init(ck.CKM_SHA256) else null,
        };
    }

    fn update(self: *Accum, data: []const u8) void {
        switch (self.mode) {
            .sha256 => self.hasher.?.update(data),
            .raw => {
                const take = @min(max_prehash - self.raw_len, data.len);
                @memcpy(self.raw[self.raw_len..][0..take], data[0..take]);
                self.raw_len += take;
            },
        }
    }

    fn digestBytes(self: *Accum, buf: *[max_prehash]u8) []const u8 {
        switch (self.mode) {
            .raw => return self.raw[0..self.raw_len],
            .sha256 => {
                const dlen = self.hasher.?.digestLen();
                self.hasher.?.finalInto(buf[0..dlen]);
                return buf[0..dlen];
            },
        }
    }
};

pub const SignState = struct {
    curve: Curve,
    scalar: [max_scalar]u8 = @splat(0),
    acc: Accum,

    pub fn init(curve: Curve, mech: ck.CK_MECHANISM_TYPE, scalar: []const u8) ?SignState {
        const mode = hashModeOf(mech) orelse return null;
        if (scalar.len != curve.scalarLen()) return null;
        var st: SignState = .{ .curve = curve, .acc = Accum.init(mode) };
        @memcpy(st.scalar[0..scalar.len], scalar);
        return st;
    }

    pub fn update(self: *SignState, data: []const u8) void {
        self.acc.update(data);
    }

    pub fn sigLen(self: *const SignState) usize {
        return self.curve.sigLen();
    }

    pub fn finalInto(self: *SignState, io: std.Io, out: []u8) Error!usize {
        var dbuf: [max_prehash]u8 = undefined;
        const dgst = self.acc.digestBytes(&dbuf);
        var phbuf: [max_scalar]u8 = undefined;
        const prehash = reduce(self.curve, dgst, &phbuf);
        return switch (self.curve) {
            .p256 => signImpl(P256, self.scalar[0..P256.SecretKey.encoded_length], prehash, io, out),
            .p384 => signImpl(P384, self.scalar[0..P384.SecretKey.encoded_length], prehash, io, out),
        };
    }
};

fn signImpl(comptime Scheme: type, scalar: []const u8, prehash: []const u8, io: std.Io, out: []u8) Error!usize {
    const slen = Scheme.SecretKey.encoded_length;
    const siglen = Scheme.Signature.encoded_length;

    var sk: [slen]u8 = undefined;
    defer std.crypto.secureZero(u8, &sk);
    @memcpy(&sk, scalar[0..slen]);
    const kp = Scheme.KeyPair.fromSecretKey(.{ .bytes = sk }) catch return Error.Crypto;

    var ph: [slen]u8 = undefined;
    @memcpy(&ph, prehash[0..slen]);

    var noise: [slen]u8 = undefined;
    defer std.crypto.secureZero(u8, &noise);
    const nz: ?[slen]u8 = if (io.randomSecure(&noise)) |_| noise else |_| null;

    const sig = kp.signPrehashed(ph, nz) catch return Error.Crypto;
    const raw = sig.toBytes();
    @memcpy(out[0..siglen], &raw);
    return siglen;
}

pub const VerifyResult = enum { ok, invalid, len_range };

pub const VerifyState = struct {
    curve: Curve,
    point: [max_point]u8 = @splat(0),
    acc: Accum,

    pub fn init(curve: Curve, mech: ck.CK_MECHANISM_TYPE, point_sec1: []const u8) ?VerifyState {
        const mode = hashModeOf(mech) orelse return null;
        if (point_sec1.len != curve.pointLen()) return null;
        if (!validPoint(curve, point_sec1)) return null;
        var st: VerifyState = .{ .curve = curve, .acc = Accum.init(mode) };
        @memcpy(st.point[0..point_sec1.len], point_sec1);
        return st;
    }

    pub fn update(self: *VerifyState, data: []const u8) void {
        self.acc.update(data);
    }

    pub fn finalVerify(self: *VerifyState, sig: []const u8) VerifyResult {
        if (sig.len != self.curve.sigLen()) return .len_range;
        var dbuf: [max_prehash]u8 = undefined;
        const dgst = self.acc.digestBytes(&dbuf);
        var phbuf: [max_scalar]u8 = undefined;
        const prehash = reduce(self.curve, dgst, &phbuf);
        const point = self.point[0..self.curve.pointLen()];
        return switch (self.curve) {
            .p256 => verifyImpl(P256, point, prehash, sig),
            .p384 => verifyImpl(P384, point, prehash, sig),
        };
    }
};

fn validPoint(curve: Curve, point_sec1: []const u8) bool {
    switch (curve) {
        .p256 => {
            _ = P256.PublicKey.fromSec1(point_sec1) catch return false;
        },
        .p384 => {
            _ = P384.PublicKey.fromSec1(point_sec1) catch return false;
        },
    }
    return true;
}

fn verifyImpl(comptime Scheme: type, point: []const u8, prehash: []const u8, sig: []const u8) VerifyResult {
    const slen = Scheme.SecretKey.encoded_length;
    const siglen = Scheme.Signature.encoded_length;

    const pk = Scheme.PublicKey.fromSec1(point) catch return .invalid;

    var sb: [siglen]u8 = undefined;
    @memcpy(&sb, sig[0..siglen]);
    const signature = Scheme.Signature.fromBytes(sb);

    var ph: [slen]u8 = undefined;
    @memcpy(&ph, prehash[0..slen]);

    signature.verifyPrehashed(ph, pk) catch return .invalid;
    return .ok;
}

pub fn ecdh(curve: Curve, scalar: []const u8, peer_point_sec1: []const u8, out: []u8) Error!usize {
    return switch (curve) {
        .p256 => ecdhImpl(std.crypto.ecc.P256, 32, scalar, peer_point_sec1, out),
        .p384 => ecdhImpl(std.crypto.ecc.P384, 48, scalar, peer_point_sec1, out),
    };
}

fn ecdhImpl(comptime Pt: type, comptime n: usize, scalar: []const u8, peer_point_sec1: []const u8, out: []u8) Error!usize {
    if (scalar.len != n or out.len < n) return Error.Crypto;
    const peer = Pt.fromSec1(peer_point_sec1) catch return Error.Crypto;
    var s: [n]u8 = undefined;
    defer std.crypto.secureZero(u8, &s);
    @memcpy(&s, scalar[0..n]);
    const shared = peer.mul(s, .big) catch return Error.Crypto;
    const xb = shared.affineCoordinates().x.toBytes(.big);
    @memcpy(out[0..n], xb[0..n]);
    return n;
}

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 6979 P-256/SHA-256 sample vector verifies and rejects tampering" {
    const ux = hexToBytes("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6");
    const uy = hexToBytes("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    const point = [_]u8{0x04} ++ ux ++ uy;
    var sig = hexToBytes("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716") ++
        hexToBytes("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");

    var v = VerifyState.init(.p256, ck.CKM_ECDSA_SHA256, &point).?;
    v.update("sample");
    try std.testing.expectEqual(VerifyResult.ok, v.finalVerify(&sig));

    sig[0] ^= 0x01;
    var v2 = VerifyState.init(.p256, ck.CKM_ECDSA_SHA256, &point).?;
    v2.update("sample");
    try std.testing.expectEqual(VerifyResult.invalid, v2.finalVerify(&sig));
}

test "P-256 generate then hash-then-sign round-trips and detects tamper" {
    const io = std.testing.io;
    const km = try generate(io, .p256);

    var s = SignState.init(.p256, ck.CKM_ECDSA_SHA256, km.scalarBytes()).?;
    s.update("attack at dawn");
    var sig: [max_sig]u8 = undefined;
    const n = try s.finalInto(io, &sig);
    try std.testing.expectEqual(@as(usize, 64), n);

    var v = VerifyState.init(.p256, ck.CKM_ECDSA_SHA256, km.pointBytes()).?;
    v.update("attack at dawn");
    try std.testing.expectEqual(VerifyResult.ok, v.finalVerify(sig[0..n]));

    var v2 = VerifyState.init(.p256, ck.CKM_ECDSA_SHA256, km.pointBytes()).?;
    v2.update("attack at dusk");
    try std.testing.expectEqual(VerifyResult.invalid, v2.finalVerify(sig[0..n]));
}

test "P-256 raw prehash signing round-trips" {
    const io = std.testing.io;
    const km = try generate(io, .p256);
    const hash = [_]u8{0xab} ** 32;

    var s = SignState.init(.p256, ck.CKM_ECDSA, km.scalarBytes()).?;
    s.update(&hash);
    var sig: [max_sig]u8 = undefined;
    const n = try s.finalInto(io, &sig);

    var v = VerifyState.init(.p256, ck.CKM_ECDSA, km.pointBytes()).?;
    v.update(&hash);
    try std.testing.expectEqual(VerifyResult.ok, v.finalVerify(sig[0..n]));
}

test "P-384 generate sign verify round-trips with correct sizes" {
    const io = std.testing.io;
    const km = try generate(io, .p384);
    try std.testing.expectEqual(@as(usize, 48), km.scalarBytes().len);
    try std.testing.expectEqual(@as(usize, 97), km.pointBytes().len);

    var s = SignState.init(.p384, ck.CKM_ECDSA_SHA256, km.scalarBytes()).?;
    s.update("p384 message");
    var sig: [max_sig]u8 = undefined;
    const n = try s.finalInto(io, &sig);
    try std.testing.expectEqual(@as(usize, 96), n);

    var v = VerifyState.init(.p384, ck.CKM_ECDSA_SHA256, km.pointBytes()).?;
    v.update("p384 message");
    try std.testing.expectEqual(VerifyResult.ok, v.finalVerify(sig[0..n]));
}

test "P-384 raw prehash signing round-trips" {
    const io = std.testing.io;
    const km = try generate(io, .p384);
    const hash = [_]u8{0xcd} ** 48;

    var s = SignState.init(.p384, ck.CKM_ECDSA, km.scalarBytes()).?;
    s.update(&hash);
    var sig: [max_sig]u8 = undefined;
    const n = try s.finalInto(io, &sig);
    try std.testing.expectEqual(@as(usize, 96), n);

    var v = VerifyState.init(.p384, ck.CKM_ECDSA, km.pointBytes()).?;
    v.update(&hash);
    try std.testing.expectEqual(VerifyResult.ok, v.finalVerify(sig[0..n]));
}

test "wrong-length signature reports len_range" {
    const io = std.testing.io;
    const km = try generate(io, .p256);
    var v = VerifyState.init(.p256, ck.CKM_ECDSA_SHA256, km.pointBytes()).?;
    v.update("data");
    try std.testing.expectEqual(VerifyResult.len_range, v.finalVerify(&[_]u8{0} ** 63));
}

test "ECDH P-256 shared secret agrees on both sides and rejects a bad point" {
    const io = std.testing.io;
    const a = try generate(io, .p256);
    const b = try generate(io, .p256);
    var sa: [max_scalar]u8 = undefined;
    var sb: [max_scalar]u8 = undefined;
    const na = try ecdh(.p256, a.scalarBytes(), b.pointBytes(), &sa);
    const nb = try ecdh(.p256, b.scalarBytes(), a.pointBytes(), &sb);
    try std.testing.expectEqual(@as(usize, 32), na);
    try std.testing.expectEqualSlices(u8, sa[0..na], sb[0..nb]);

    const bad = [_]u8{0x04} ++ [_]u8{0xff} ** 64;
    try std.testing.expectError(Error.Crypto, ecdh(.p256, a.scalarBytes(), &bad, &sa));
}

test "ECDH P-384 shared secret agrees on both sides" {
    const io = std.testing.io;
    const a = try generate(io, .p384);
    const b = try generate(io, .p384);
    var sa: [max_scalar]u8 = undefined;
    var sb: [max_scalar]u8 = undefined;
    const na = try ecdh(.p384, a.scalarBytes(), b.pointBytes(), &sa);
    const nb = try ecdh(.p384, b.scalarBytes(), a.pointBytes(), &sb);
    try std.testing.expectEqual(@as(usize, 48), na);
    try std.testing.expectEqualSlices(u8, sa[0..na], sb[0..nb]);
}

test "curve OID mapping and EC point DER round-trip" {
    try std.testing.expectEqual(Curve.p256, curveFromParams(&oid_p256).?);
    try std.testing.expectEqual(Curve.p384, curveFromParams(&oid_p384).?);
    try std.testing.expect(curveFromParams(&[_]u8{ 0x06, 0x01, 0x00 }) == null);

    const sec1 = [_]u8{0x04} ++ [_]u8{0x11} ** 64;
    var buf: [max_ec_point_der]u8 = undefined;
    const der = wrapEcPoint(&buf, &sec1);
    try std.testing.expectEqual(@as(usize, 67), der.len);
    try std.testing.expectEqualSlices(u8, &sec1, unwrapEcPoint(der).?);
    try std.testing.expect(unwrapEcPoint(&[_]u8{0x05}) == null);
}
