// ©AngelaMos | 2026
// crypto_ops.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const state = @import("../core/state.zig");
const session = @import("../core/session.zig");
const object_store = @import("../core/object_store.zig");
const digest = @import("../crypto/digest.zig");
const mac = @import("../crypto/mac.zig");
const cipher = @import("../crypto/cipher.zig");
const ecdsa = @import("../crypto/ecdsa.zig");
const rsa = @import("../crypto/rsa.zig");

fn part(p: [*]ck.CK_BYTE, len: ck.CK_ULONG) []const u8 {
    return p[0..@intCast(len)];
}

fn ctEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

fn objectClass(obj: *const object_store.Object) ?ck.CK_OBJECT_CLASS {
    const v = obj.get(ck.CKA_CLASS) orelse return null;
    if (v.len != @sizeOf(ck.CK_OBJECT_CLASS)) return null;
    return std.mem.bytesToValue(ck.CK_OBJECT_CLASS, v[0..@sizeOf(ck.CK_OBJECT_CLASS)]);
}

fn keyType(obj: *const object_store.Object) ?ck.CK_KEY_TYPE {
    const v = obj.get(ck.CKA_KEY_TYPE) orelse return null;
    if (v.len != @sizeOf(ck.CK_KEY_TYPE)) return null;
    return std.mem.bytesToValue(ck.CK_KEY_TYPE, v[0..@sizeOf(ck.CK_KEY_TYPE)]);
}

const KeyVal = union(enum) {
    ok: []const u8,
    err: ck.CK_RV,
};

fn secretKeyValue(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE, usage: ck.CK_ATTRIBUTE_TYPE) KeyVal {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (objectClass(obj) != ck.CKO_SECRET_KEY) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (obj.has(usage) and !obj.getBool(usage)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    const a = obj.findPtr(ck.CKA_VALUE) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (a.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    return .{ .ok = a.value };
}

const EcKey = union(enum) {
    ok: struct { curve: ecdsa.Curve, material: []const u8 },
    err: ck.CK_RV,
};

fn ecPrivateKey(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE) EcKey {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (objectClass(obj) != ck.CKO_PRIVATE_KEY) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (keyType(obj) != ck.CKK_EC) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (obj.has(ck.CKA_SIGN) and !obj.getBool(ck.CKA_SIGN)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    const params = obj.get(ck.CKA_EC_PARAMS) orelse return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    const curve = ecdsa.curveFromParams(params) orelse return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    const sa = obj.findPtr(ck.CKA_VALUE) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (sa.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    if (sa.value.len != curve.scalarLen()) return .{ .err = ck.CKR_FUNCTION_FAILED };
    return .{ .ok = .{ .curve = curve, .material = sa.value } };
}

fn ecPublicKey(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE) EcKey {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (objectClass(obj) != ck.CKO_PUBLIC_KEY) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (keyType(obj) != ck.CKK_EC) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (obj.has(ck.CKA_VERIFY) and !obj.getBool(ck.CKA_VERIFY)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    const params = obj.get(ck.CKA_EC_PARAMS) orelse return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    const curve = ecdsa.curveFromParams(params) orelse return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    const der = obj.get(ck.CKA_EC_POINT) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    const point = ecdsa.unwrapEcPoint(der) orelse return .{ .err = ck.CKR_FUNCTION_FAILED };
    if (point.len != curve.pointLen()) return .{ .err = ck.CKR_FUNCTION_FAILED };
    return .{ .ok = .{ .curve = curve, .material = point } };
}

const RsaPriv = union(enum) {
    ok: rsa.PrivateComponents,
    err: ck.CK_RV,
};

const RsaPub = union(enum) {
    ok: rsa.PublicComponents,
    err: ck.CK_RV,
};

fn rsaPrivateComponents(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE, usage: ck.CK_ATTRIBUTE_TYPE) RsaPriv {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (objectClass(obj) != ck.CKO_PRIVATE_KEY) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (keyType(obj) != ck.CKK_RSA) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (obj.has(usage) and !obj.getBool(usage)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    if (obj.findPtr(ck.CKA_PRIVATE_EXPONENT)) |da| {
        if (da.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    }
    return .{ .ok = .{
        .n = obj.get(ck.CKA_MODULUS) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .e = obj.get(ck.CKA_PUBLIC_EXPONENT) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .d = obj.get(ck.CKA_PRIVATE_EXPONENT) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .p = obj.get(ck.CKA_PRIME_1) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .q = obj.get(ck.CKA_PRIME_2) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .dmp1 = obj.get(ck.CKA_EXPONENT_1) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .dmq1 = obj.get(ck.CKA_EXPONENT_2) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .iqmp = obj.get(ck.CKA_COEFFICIENT) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
    } };
}

fn rsaPublicComponents(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE, usage: ck.CK_ATTRIBUTE_TYPE) RsaPub {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (objectClass(obj) != ck.CKO_PUBLIC_KEY) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (keyType(obj) != ck.CKK_RSA) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (obj.has(usage) and !obj.getBool(usage)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    return .{ .ok = .{
        .n = obj.get(ck.CKA_MODULUS) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
        .e = obj.get(ck.CKA_PUBLIC_EXPONENT) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID },
    } };
}

fn isRsaSignMech(mech: ck.CK_MECHANISM_TYPE) bool {
    return switch (mech) {
        ck.CKM_RSA_PKCS, ck.CKM_SHA256_RSA_PKCS, ck.CKM_RSA_PKCS_PSS, ck.CKM_SHA256_RSA_PKCS_PSS => true,
        else => false,
    };
}

fn mgfHash(mgf: ck.CK_RSA_PKCS_MGF_TYPE) ?rsa.Hash {
    return switch (mgf) {
        ck.CKG_MGF1_SHA256 => .sha256,
        ck.CKG_MGF1_SHA384 => .sha384,
        ck.CKG_MGF1_SHA512 => .sha512,
        else => null,
    };
}

const SignParamsResult = union(enum) {
    ok: rsa.SignParams,
    err: ck.CK_RV,
};

fn parsePss(pMechanism: *ck.CK_MECHANISM, digest_hash: rsa.Hash) SignParamsResult {
    var params: rsa.SignParams = .{
        .scheme = .pss,
        .digest = digest_hash,
        .pss_hash = if (digest_hash == .none) .sha256 else digest_hash,
    };
    const p = pMechanism.pParameter orelse {
        if (digest_hash == .none) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
        return .{ .ok = params };
    };
    if (pMechanism.ulParameterLen != @sizeOf(ck.CK_RSA_PKCS_PSS_PARAMS)) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    const pp: *const ck.CK_RSA_PKCS_PSS_PARAMS = @ptrCast(@alignCast(p));
    const h = rsa.Hash.fromMech(pp.hashAlg) orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    if (digest_hash != .none and h != digest_hash) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    if (mgfHash(pp.mgf) != h) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    if (pp.sLen > rsa.max_modulus_bytes) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    params.pss_hash = h;
    params.salt_len = @intCast(pp.sLen);
    return .{ .ok = params };
}

fn rsaSignParams(pMechanism: *ck.CK_MECHANISM) SignParamsResult {
    return switch (pMechanism.mechanism) {
        ck.CKM_RSA_PKCS => .{ .ok = .{ .scheme = .pkcs1, .digest = .none } },
        ck.CKM_SHA256_RSA_PKCS => .{ .ok = .{ .scheme = .pkcs1, .digest = .sha256 } },
        ck.CKM_RSA_PKCS_PSS => parsePss(pMechanism, .none),
        ck.CKM_SHA256_RSA_PKCS_PSS => parsePss(pMechanism, .sha256),
        else => .{ .err = ck.CKR_MECHANISM_INVALID },
    };
}

const CryptParamsResult = union(enum) {
    ok: rsa.CryptParams,
    err: ck.CK_RV,
};

fn rsaCryptParams(pMechanism: *ck.CK_MECHANISM) CryptParamsResult {
    return switch (pMechanism.mechanism) {
        ck.CKM_RSA_PKCS => .{ .ok = .{ .scheme = .pkcs1 } },
        ck.CKM_RSA_PKCS_OAEP => blk: {
            const p = pMechanism.pParameter orelse break :blk .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (pMechanism.ulParameterLen != @sizeOf(ck.CK_RSA_PKCS_OAEP_PARAMS)) break :blk .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            const op: *const ck.CK_RSA_PKCS_OAEP_PARAMS = @ptrCast(@alignCast(p));
            const h = rsa.Hash.fromMech(op.hashAlg) orelse break :blk .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (mgfHash(op.mgf) != h) break :blk .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (op.ulSourceDataLen != 0) break :blk .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            break :blk .{ .ok = .{ .scheme = .oaep, .oaep_hash = h } };
        },
        else => .{ .err = ck.CKR_MECHANISM_INVALID },
    };
}

fn signLen(op: *const session.SignOp) ck.CK_ULONG {
    return switch (op.*) {
        .mac => |*m| @intCast(m.macLen()),
        .ec => |*e| @intCast(e.sigLen()),
        .rsa => |*r| @intCast(r.sig_len),
    };
}

fn emitSign(inst: *state.Instance, sess: *session.Session, pSignature: ?[*]ck.CK_BYTE, pulSignatureLen: *ck.CK_ULONG) ck.CK_RV {
    const op = &sess.sign_op.?;
    const slen = signLen(op);
    if (pSignature == null) {
        pulSignatureLen.* = slen;
        return ck.CKR_OK;
    }
    if (pulSignatureLen.* < slen) {
        pulSignatureLen.* = slen;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const out = pSignature.?[0..@intCast(slen)];
    switch (op.*) {
        .mac => |*m| m.finalInto(out),
        .ec => |*e| _ = e.finalInto(inst.io(), out) catch {
            sess.endSign();
            return ck.CKR_FUNCTION_FAILED;
        },
        .rsa => return ck.CKR_FUNCTION_FAILED,
    }
    pulSignatureLen.* = slen;
    sess.endSign();
    return ck.CKR_OK;
}

fn finalizeVerify(sess: *session.Session, pSignature: [*]ck.CK_BYTE, ulSignatureLen: ck.CK_ULONG) ck.CK_RV {
    const sig = pSignature[0..@intCast(ulSignatureLen)];
    const rv = switch (sess.verify_op.?) {
        .mac => |*m| blk: {
            const mlen: ck.CK_ULONG = @intCast(m.macLen());
            var computed: [mac.max_mac_len]u8 = undefined;
            m.finalInto(computed[0..@intCast(mlen)]);
            if (ulSignatureLen != mlen) break :blk ck.CKR_SIGNATURE_LEN_RANGE;
            if (!ctEql(computed[0..@intCast(mlen)], sig)) break :blk ck.CKR_SIGNATURE_INVALID;
            break :blk ck.CKR_OK;
        },
        .ec => |*e| switch (e.finalVerify(sig)) {
            .ok => ck.CKR_OK,
            .invalid => ck.CKR_SIGNATURE_INVALID,
            .len_range => ck.CKR_SIGNATURE_LEN_RANGE,
        },
        .rsa => ck.CKR_FUNCTION_FAILED,
    };
    sess.endVerify();
    return rv;
}

fn signInitOp(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE, pMechanism: *ck.CK_MECHANISM) union(enum) { ok: session.SignOp, err: ck.CK_RV } {
    const mech = pMechanism.mechanism;
    if (mac.macLenOf(mech) != null) {
        const val = switch (secretKeyValue(inst, hKey, ck.CKA_SIGN)) {
            .err => |rv| return .{ .err = rv },
            .ok => |v| v,
        };
        return .{ .ok = .{ .mac = mac.Mac.init(mech, val) orelse return .{ .err = ck.CKR_MECHANISM_INVALID } } };
    }
    if (ecdsa.hashModeOf(mech) != null) {
        const k = switch (ecPrivateKey(inst, hKey)) {
            .err => |rv| return .{ .err = rv },
            .ok => |v| v,
        };
        return .{ .ok = .{ .ec = ecdsa.SignState.init(k.curve, mech, k.material) orelse return .{ .err = ck.CKR_MECHANISM_INVALID } } };
    }
    if (isRsaSignMech(mech)) {
        const params = switch (rsaSignParams(pMechanism)) {
            .err => |rv| return .{ .err = rv },
            .ok => |p| p,
        };
        const pc = switch (rsaPrivateComponents(inst, hKey, ck.CKA_SIGN)) {
            .err => |rv| return .{ .err = rv },
            .ok => |c| c,
        };
        return .{ .ok = .{ .rsa = .{ .key = hKey, .params = params, .sig_len = pc.n.len } } };
    }
    return .{ .err = ck.CKR_MECHANISM_INVALID };
}

fn verifyInitOp(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE, pMechanism: *ck.CK_MECHANISM) union(enum) { ok: session.VerifyOp, err: ck.CK_RV } {
    const mech = pMechanism.mechanism;
    if (mac.macLenOf(mech) != null) {
        const val = switch (secretKeyValue(inst, hKey, ck.CKA_VERIFY)) {
            .err => |rv| return .{ .err = rv },
            .ok => |v| v,
        };
        return .{ .ok = .{ .mac = mac.Mac.init(mech, val) orelse return .{ .err = ck.CKR_MECHANISM_INVALID } } };
    }
    if (ecdsa.hashModeOf(mech) != null) {
        const k = switch (ecPublicKey(inst, hKey)) {
            .err => |rv| return .{ .err = rv },
            .ok => |v| v,
        };
        return .{ .ok = .{ .ec = ecdsa.VerifyState.init(k.curve, mech, k.material) orelse return .{ .err = ck.CKR_MECHANISM_INVALID } } };
    }
    if (isRsaSignMech(mech)) {
        const params = switch (rsaSignParams(pMechanism)) {
            .err => |rv| return .{ .err = rv },
            .ok => |p| p,
        };
        const pc = switch (rsaPublicComponents(inst, hKey, ck.CKA_VERIFY)) {
            .err => |rv| return .{ .err = rv },
            .ok => |c| c,
        };
        return .{ .ok = .{ .rsa = .{ .key = hKey, .params = params, .sig_len = pc.n.len } } };
    }
    return .{ .err = ck.CKR_MECHANISM_INVALID };
}

fn mapCipherErr(e: cipher.Error) ck.CK_RV {
    return switch (e) {
        cipher.Error.DataLenRange => ck.CKR_DATA_LEN_RANGE,
        cipher.Error.EncryptedDataLenRange => ck.CKR_ENCRYPTED_DATA_LEN_RANGE,
        cipher.Error.EncryptedDataInvalid => ck.CKR_ENCRYPTED_DATA_INVALID,
        cipher.Error.KeySize => ck.CKR_KEY_SIZE_RANGE,
        cipher.Error.AadTooLarge => ck.CKR_ARGUMENTS_BAD,
        cipher.Error.IvInvalid => ck.CKR_MECHANISM_PARAM_INVALID,
    };
}

const CipherInit = union(enum) {
    ok: cipher.Cipher,
    err: ck.CK_RV,
};

fn buildCipher(inst: *state.Instance, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE, encrypt: bool, usage: ck.CK_ATTRIBUTE_TYPE) CipherInit {
    const mode = cipher.modeOf(pMechanism.mechanism) orelse return .{ .err = ck.CKR_MECHANISM_INVALID };
    const val = switch (secretKeyValue(inst, hKey, usage)) {
        .err => |rv| return .{ .err = rv },
        .ok => |v| v,
    };
    if (!cipher.validKeyLen(val.len)) return .{ .err = ck.CKR_KEY_SIZE_RANGE };

    var c: cipher.Cipher = .{ .mode = mode, .encrypt = encrypt, .key_len = @intCast(val.len) };
    @memcpy(c.key_buf[0..val.len], val);

    switch (mode) {
        .cbc, .cbc_pad => {
            const p = pMechanism.pParameter orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (pMechanism.ulParameterLen != config.aes_block_len) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            @memcpy(&c.chain, @as([*]const u8, @ptrCast(p))[0..config.aes_block_len]);
        },
        .gcm => {
            const p = pMechanism.pParameter orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (pMechanism.ulParameterLen != @sizeOf(ck.CK_GCM_PARAMS)) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            const gp: *const ck.CK_GCM_PARAMS = @ptrCast(@alignCast(p));
            if (gp.ulIvLen != config.gcm_iv_len) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (gp.ulIvBits != 0 and gp.ulIvBits != config.gcm_iv_bits) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            if (gp.ulTagBits != config.gcm_tag_bits) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            const ivp = gp.pIv orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
            @memcpy(&c.iv, ivp[0..config.gcm_iv_len]);
            const aad_len: usize = @intCast(gp.ulAADLen);
            if (aad_len > config.max_gcm_aad_len) return .{ .err = ck.CKR_ARGUMENTS_BAD };
            if (aad_len > 0) {
                const ap = gp.pAAD orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
                @memcpy(c.aad_buf[0..aad_len], ap[0..aad_len]);
            }
            c.aad_len = aad_len;
        },
    }
    return .{ .ok = c };
}

fn updateOutLen(op: *const cipher.Cipher, in_len: usize) ck.CK_ULONG {
    return @intCast(((op.partial_len + in_len) / config.aes_block_len) * config.aes_block_len);
}

const NeedResult = union(enum) { ok: ck.CK_ULONG, err: ck.CK_RV };
const EmitResult = union(enum) { ok: usize, err: ck.CK_RV };

fn encUpdateNeed(op: *const session.EncryptOp, in_len: usize) NeedResult {
    return switch (op.*) {
        .rsa => .{ .err = ck.CKR_FUNCTION_NOT_SUPPORTED },
        .aes => |*c| .{ .ok = updateOutLen(c, in_len) },
        .gcm => .{ .ok = 0 },
    };
}

fn encUpdateEmit(inst: *state.Instance, op: *session.EncryptOp, in: []const u8, out: []u8) EmitResult {
    switch (op.*) {
        .rsa => return .{ .err = ck.CKR_FUNCTION_NOT_SUPPORTED },
        .aes => |*c| return .{ .ok = c.encryptUpdate(in, out) },
        .gcm => |*g| {
            g.append(inst.allocator(), in) catch |e| return .{ .err = switch (e) {
                error.OutOfMemory => ck.CKR_HOST_MEMORY,
                error.TooLarge => ck.CKR_DATA_LEN_RANGE,
            } };
            return .{ .ok = 0 };
        },
    }
}

fn decUpdateNeed(op: *const session.DecryptOp, in_len: usize) NeedResult {
    return switch (op.*) {
        .rsa => .{ .err = ck.CKR_FUNCTION_NOT_SUPPORTED },
        .aes => |*c| .{ .ok = updateOutLen(c, in_len) },
        .gcm => .{ .ok = 0 },
    };
}

fn decUpdateEmit(inst: *state.Instance, op: *session.DecryptOp, in: []const u8, out: []u8) EmitResult {
    switch (op.*) {
        .rsa => return .{ .err = ck.CKR_FUNCTION_NOT_SUPPORTED },
        .aes => |*c| return .{ .ok = c.decryptUpdate(in, out) },
        .gcm => |*g| {
            g.append(inst.allocator(), in) catch |e| return .{ .err = switch (e) {
                error.OutOfMemory => ck.CKR_HOST_MEMORY,
                error.TooLarge => ck.CKR_ENCRYPTED_DATA_LEN_RANGE,
            } };
            return .{ .ok = 0 };
        },
    }
}

fn decryptSideDualOk(op: *const session.DecryptOp) bool {
    return switch (op.*) {
        .aes => |*c| c.mode == .cbc,
        else => false,
    };
}

fn emitDigest(sess: *session.Session, pDigest: ?[*]ck.CK_BYTE, pulDigestLen: *ck.CK_ULONG) ck.CK_RV {
    const op = &sess.digest_op.?;
    const dlen: ck.CK_ULONG = @intCast(op.digestLen());
    if (pDigest == null) {
        pulDigestLen.* = dlen;
        return ck.CKR_OK;
    }
    if (pulDigestLen.* < dlen) {
        pulDigestLen.* = dlen;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    op.finalInto(pDigest.?[0..@intCast(dlen)]);
    pulDigestLen.* = dlen;
    sess.endDigest();
    return ck.CKR_OK;
}

fn isRsaCryptMech(mech: ck.CK_MECHANISM_TYPE) bool {
    return mech == ck.CKM_RSA_PKCS or mech == ck.CKM_RSA_PKCS_OAEP;
}

const RsaCryptResult = union(enum) {
    ok: session.RsaCrypt,
    err: ck.CK_RV,
};

fn rsaCryptInit(inst: *state.Instance, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE, private: bool, usage: ck.CK_ATTRIBUTE_TYPE) RsaCryptResult {
    const params = switch (rsaCryptParams(pMechanism)) {
        .err => |rv| return .{ .err = rv },
        .ok => |p| p,
    };
    const mod_len = if (private) switch (rsaPrivateComponents(inst, hKey, usage)) {
        .err => |rv| return .{ .err = rv },
        .ok => |c| c.n.len,
    } else switch (rsaPublicComponents(inst, hKey, usage)) {
        .err => |rv| return .{ .err = rv },
        .ok => |c| c.n.len,
    };
    return .{ .ok = .{ .key = hKey, .params = params, .out_len = mod_len } };
}

pub fn C_EncryptInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.encrypt_op != null) return ck.CKR_OPERATION_ACTIVE;
    if (cipher.modeOf(pMechanism.mechanism) != null) {
        const c = switch (buildCipher(inst, pMechanism, hKey, true, ck.CKA_ENCRYPT)) {
            .err => |rv| return rv,
            .ok => |built| built,
        };
        sess.encrypt_op = if (c.mode == .gcm) .{ .gcm = .{ .cipher = c } } else .{ .aes = c };
        return ck.CKR_OK;
    }
    if (isRsaCryptMech(pMechanism.mechanism)) {
        sess.encrypt_op = .{ .rsa = switch (rsaCryptInit(inst, pMechanism, hKey, false, ck.CKA_ENCRYPT)) {
            .err => |rv| return rv,
            .ok => |o| o,
        } };
        return ck.CKR_OK;
    }
    return ck.CKR_MECHANISM_INVALID;
}

pub fn C_Encrypt(hSession: ck.CK_SESSION_HANDLE, pData: [*]ck.CK_BYTE, ulDataLen: ck.CK_ULONG, pEncryptedData: ?[*]ck.CK_BYTE, pulEncryptedDataLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.encrypt_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    const in = part(pData, ulDataLen);

    switch (op.*) {
        .aes => |*c| {
            const need: ck.CK_ULONG = @intCast(cipher.encryptOutLen(c.mode, in.len));
            if (pEncryptedData == null) {
                pulEncryptedDataLen.* = need;
                return ck.CKR_OK;
            }
            if (pulEncryptedDataLen.* < need) {
                pulEncryptedDataLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const out = pEncryptedData.?[0..@intCast(need)];
            var n = c.encryptUpdate(in, out);
            n += c.encryptFinal(out[n..]) catch |e| {
                sess.endEncrypt(inst.allocator());
                return mapCipherErr(e);
            };
            pulEncryptedDataLen.* = @intCast(n);
            sess.endEncrypt(inst.allocator());
            return ck.CKR_OK;
        },
        .gcm => |*g| {
            const need: ck.CK_ULONG = @intCast(cipher.encryptOutLen(.gcm, in.len));
            if (pEncryptedData == null) {
                pulEncryptedDataLen.* = need;
                return ck.CKR_OK;
            }
            if (pulEncryptedDataLen.* < need) {
                pulEncryptedDataLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = g.cipher.gcmEncrypt(in, pEncryptedData.?[0..@intCast(need)]);
            pulEncryptedDataLen.* = @intCast(n);
            sess.endEncrypt(inst.allocator());
            return ck.CKR_OK;
        },
        .rsa => |*r| {
            const need: ck.CK_ULONG = @intCast(r.out_len);
            if (pEncryptedData == null) {
                pulEncryptedDataLen.* = need;
                return ck.CKR_OK;
            }
            if (pulEncryptedDataLen.* < need) {
                pulEncryptedDataLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const pc = switch (rsaPublicComponents(inst, r.key, ck.CKA_ENCRYPT)) {
                .err => |rv| {
                    sess.endEncrypt(inst.allocator());
                    return rv;
                },
                .ok => |c| c,
            };
            const n = rsa.encrypt(pc, r.params, in, pEncryptedData.?[0..@intCast(need)]) catch {
                sess.endEncrypt(inst.allocator());
                return ck.CKR_DATA_LEN_RANGE;
            };
            pulEncryptedDataLen.* = @intCast(n);
            sess.endEncrypt(inst.allocator());
            return ck.CKR_OK;
        },
    }
}

pub fn C_EncryptUpdate(hSession: ck.CK_SESSION_HANDLE, pPart: [*]ck.CK_BYTE, ulPartLen: ck.CK_ULONG, pEncryptedPart: ?[*]ck.CK_BYTE, pulEncryptedPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.encrypt_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    const in = part(pPart, ulPartLen);
    const need = switch (encUpdateNeed(op, in.len)) {
        .err => |rv| return rv,
        .ok => |n| n,
    };
    if (pEncryptedPart == null) {
        pulEncryptedPartLen.* = need;
        return ck.CKR_OK;
    }
    if (pulEncryptedPartLen.* < need) {
        pulEncryptedPartLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const wrote = switch (encUpdateEmit(inst, op, in, pEncryptedPart.?[0..@intCast(need)])) {
        .err => |rv| {
            sess.endEncrypt(inst.allocator());
            return rv;
        },
        .ok => |n| n,
    };
    pulEncryptedPartLen.* = @intCast(wrote);
    return ck.CKR_OK;
}

pub fn C_EncryptFinal(hSession: ck.CK_SESSION_HANDLE, pLastEncryptedPart: ?[*]ck.CK_BYTE, pulLastEncryptedPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.encrypt_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (op.*) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        .aes => |*c| {
            const need: ck.CK_ULONG = if (c.mode == .cbc_pad) config.aes_block_len else 0;
            if (pLastEncryptedPart == null) {
                pulLastEncryptedPartLen.* = need;
                return ck.CKR_OK;
            }
            if (pulLastEncryptedPartLen.* < need) {
                pulLastEncryptedPartLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = c.encryptFinal(pLastEncryptedPart.?[0..@intCast(need)]) catch |e| {
                sess.endEncrypt(inst.allocator());
                return mapCipherErr(e);
            };
            pulLastEncryptedPartLen.* = @intCast(n);
            sess.endEncrypt(inst.allocator());
            return ck.CKR_OK;
        },
        .gcm => |*g| {
            const need: ck.CK_ULONG = @intCast(g.len + config.gcm_tag_len);
            if (pLastEncryptedPart == null) {
                pulLastEncryptedPartLen.* = need;
                return ck.CKR_OK;
            }
            if (pulLastEncryptedPartLen.* < need) {
                pulLastEncryptedPartLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = g.cipher.gcmEncrypt(g.data(), pLastEncryptedPart.?[0..@intCast(need)]);
            pulLastEncryptedPartLen.* = @intCast(n);
            sess.endEncrypt(inst.allocator());
            return ck.CKR_OK;
        },
    }
}

pub fn C_DecryptInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.decrypt_op != null) return ck.CKR_OPERATION_ACTIVE;
    if (cipher.modeOf(pMechanism.mechanism) != null) {
        const c = switch (buildCipher(inst, pMechanism, hKey, false, ck.CKA_DECRYPT)) {
            .err => |rv| return rv,
            .ok => |built| built,
        };
        sess.decrypt_op = if (c.mode == .gcm) .{ .gcm = .{ .cipher = c } } else .{ .aes = c };
        return ck.CKR_OK;
    }
    if (isRsaCryptMech(pMechanism.mechanism)) {
        sess.decrypt_op = .{ .rsa = switch (rsaCryptInit(inst, pMechanism, hKey, true, ck.CKA_DECRYPT)) {
            .err => |rv| return rv,
            .ok => |o| o,
        } };
        return ck.CKR_OK;
    }
    return ck.CKR_MECHANISM_INVALID;
}

pub fn C_Decrypt(hSession: ck.CK_SESSION_HANDLE, pEncryptedData: [*]ck.CK_BYTE, ulEncryptedDataLen: ck.CK_ULONG, pData: ?[*]ck.CK_BYTE, pulDataLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.decrypt_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    const in = part(pEncryptedData, ulEncryptedDataLen);

    switch (op.*) {
        .aes => |*c| {
            const need: ck.CK_ULONG = @intCast(cipher.decryptOutLen(c.mode, in.len));
            if (pData == null) {
                pulDataLen.* = need;
                return ck.CKR_OK;
            }
            if (pulDataLen.* < need) {
                pulDataLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const out = pData.?[0..@intCast(need)];
            var n = c.decryptUpdate(in, out);
            n += c.decryptFinal(out[n..]) catch |e| {
                sess.endDecrypt(inst.allocator());
                return mapCipherErr(e);
            };
            pulDataLen.* = @intCast(n);
            sess.endDecrypt(inst.allocator());
            return ck.CKR_OK;
        },
        .gcm => |*g| {
            const need: ck.CK_ULONG = @intCast(cipher.decryptOutLen(.gcm, in.len));
            if (pData == null) {
                pulDataLen.* = need;
                return ck.CKR_OK;
            }
            if (pulDataLen.* < need) {
                pulDataLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = g.cipher.gcmDecrypt(in, pData.?[0..@intCast(need)]) catch |e| {
                sess.endDecrypt(inst.allocator());
                return mapCipherErr(e);
            };
            pulDataLen.* = @intCast(n);
            sess.endDecrypt(inst.allocator());
            return ck.CKR_OK;
        },
        .rsa => |*r| {
            const need: ck.CK_ULONG = @intCast(r.out_len);
            if (pData == null) {
                pulDataLen.* = need;
                return ck.CKR_OK;
            }
            if (pulDataLen.* < need) {
                pulDataLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const sc = switch (rsaPrivateComponents(inst, r.key, ck.CKA_DECRYPT)) {
                .err => |rv| {
                    sess.endDecrypt(inst.allocator());
                    return rv;
                },
                .ok => |c| c,
            };
            const n = rsa.decrypt(sc, r.params, in, pData.?[0..@intCast(need)]) catch {
                sess.endDecrypt(inst.allocator());
                return ck.CKR_ENCRYPTED_DATA_INVALID;
            };
            pulDataLen.* = @intCast(n);
            sess.endDecrypt(inst.allocator());
            return ck.CKR_OK;
        },
    }
}

pub fn C_DecryptUpdate(hSession: ck.CK_SESSION_HANDLE, pEncryptedPart: [*]ck.CK_BYTE, ulEncryptedPartLen: ck.CK_ULONG, pPart: ?[*]ck.CK_BYTE, pulPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.decrypt_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    const in = part(pEncryptedPart, ulEncryptedPartLen);
    const need = switch (decUpdateNeed(op, in.len)) {
        .err => |rv| return rv,
        .ok => |n| n,
    };
    if (pPart == null) {
        pulPartLen.* = need;
        return ck.CKR_OK;
    }
    if (pulPartLen.* < need) {
        pulPartLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const wrote = switch (decUpdateEmit(inst, op, in, pPart.?[0..@intCast(need)])) {
        .err => |rv| {
            sess.endDecrypt(inst.allocator());
            return rv;
        },
        .ok => |n| n,
    };
    pulPartLen.* = @intCast(wrote);
    return ck.CKR_OK;
}

pub fn C_DecryptFinal(hSession: ck.CK_SESSION_HANDLE, pLastPart: ?[*]ck.CK_BYTE, pulLastPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.decrypt_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (op.*) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        .aes => |*c| {
            const need: ck.CK_ULONG = if (c.mode == .cbc_pad) config.aes_block_len else 0;
            if (pLastPart == null) {
                pulLastPartLen.* = need;
                return ck.CKR_OK;
            }
            if (pulLastPartLen.* < need) {
                pulLastPartLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = c.decryptFinal(pLastPart.?[0..@intCast(need)]) catch |e| {
                sess.endDecrypt(inst.allocator());
                return mapCipherErr(e);
            };
            pulLastPartLen.* = @intCast(n);
            sess.endDecrypt(inst.allocator());
            return ck.CKR_OK;
        },
        .gcm => |*g| {
            const need: ck.CK_ULONG = @intCast(cipher.decryptOutLen(.gcm, g.len));
            if (pLastPart == null) {
                pulLastPartLen.* = need;
                return ck.CKR_OK;
            }
            if (pulLastPartLen.* < need) {
                pulLastPartLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = g.cipher.gcmDecrypt(g.data(), pLastPart.?[0..@intCast(need)]) catch |e| {
                sess.endDecrypt(inst.allocator());
                return mapCipherErr(e);
            };
            pulLastPartLen.* = @intCast(n);
            sess.endDecrypt(inst.allocator());
            return ck.CKR_OK;
        },
    }
}

pub fn C_DigestInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.digest_op != null) return ck.CKR_OPERATION_ACTIVE;
    sess.digest_op = digest.Hasher.init(pMechanism.mechanism) orelse return ck.CKR_MECHANISM_INVALID;
    return ck.CKR_OK;
}

pub fn C_Digest(hSession: ck.CK_SESSION_HANDLE, pData: [*]ck.CK_BYTE, ulDataLen: ck.CK_ULONG, pDigest: ?[*]ck.CK_BYTE, pulDigestLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.digest_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    const dlen: ck.CK_ULONG = @intCast(sess.digest_op.?.digestLen());
    if (pDigest == null) {
        pulDigestLen.* = dlen;
        return ck.CKR_OK;
    }
    if (pulDigestLen.* < dlen) {
        pulDigestLen.* = dlen;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    sess.digest_op.?.update(part(pData, ulDataLen));
    return emitDigest(sess, pDigest, pulDigestLen);
}

pub fn C_DigestUpdate(hSession: ck.CK_SESSION_HANDLE, pPart: [*]ck.CK_BYTE, ulPartLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.digest_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    sess.digest_op.?.update(part(pPart, ulPartLen));
    return ck.CKR_OK;
}

pub fn C_DigestKey(hSession: ck.CK_SESSION_HANDLE, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.digest_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    const obj = inst.objects.getPtr(hKey) orelse return ck.CKR_KEY_HANDLE_INVALID;
    if (!object_store.visible(obj, inst.logged_in)) return ck.CKR_KEY_HANDLE_INVALID;
    if (objectClass(obj) != ck.CKO_SECRET_KEY) return ck.CKR_KEY_INDIGESTIBLE;
    const sa = obj.findPtr(ck.CKA_VALUE) orelse return ck.CKR_KEY_INDIGESTIBLE;
    if (sa.sealed) return ck.CKR_USER_NOT_LOGGED_IN;
    sess.digest_op.?.update(sa.value);
    return ck.CKR_OK;
}

pub fn C_DigestFinal(hSession: ck.CK_SESSION_HANDLE, pDigest: ?[*]ck.CK_BYTE, pulDigestLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.digest_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    return emitDigest(sess, pDigest, pulDigestLen);
}

pub fn C_SignInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_op != null) return ck.CKR_OPERATION_ACTIVE;
    sess.sign_op = switch (signInitOp(inst, hKey, pMechanism)) {
        .err => |rv| return rv,
        .ok => |op| op,
    };
    return ck.CKR_OK;
}

pub fn C_Sign(hSession: ck.CK_SESSION_HANDLE, pData: [*]ck.CK_BYTE, ulDataLen: ck.CK_ULONG, pSignature: ?[*]ck.CK_BYTE, pulSignatureLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    const slen = signLen(&sess.sign_op.?);
    if (pSignature == null) {
        pulSignatureLen.* = slen;
        return ck.CKR_OK;
    }
    if (pulSignatureLen.* < slen) {
        pulSignatureLen.* = slen;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    switch (sess.sign_op.?) {
        .rsa => |op| {
            const out = pSignature.?[0..@intCast(slen)];
            const sc = switch (rsaPrivateComponents(inst, op.key, ck.CKA_SIGN)) {
                .err => |rv| {
                    sess.endSign();
                    return rv;
                },
                .ok => |c| c,
            };
            const n = rsa.sign(sc, op.params, part(pData, ulDataLen), out) catch {
                sess.endSign();
                return ck.CKR_FUNCTION_FAILED;
            };
            pulSignatureLen.* = @intCast(n);
            sess.endSign();
            return ck.CKR_OK;
        },
        else => {
            sess.sign_op.?.update(part(pData, ulDataLen));
            return emitSign(inst, sess, pSignature, pulSignatureLen);
        },
    }
}

pub fn C_SignUpdate(hSession: ck.CK_SESSION_HANDLE, pPart: [*]ck.CK_BYTE, ulPartLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (sess.sign_op.?) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        else => {},
    }
    sess.sign_op.?.update(part(pPart, ulPartLen));
    return ck.CKR_OK;
}

pub fn C_SignFinal(hSession: ck.CK_SESSION_HANDLE, pSignature: ?[*]ck.CK_BYTE, pulSignatureLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (sess.sign_op.?) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        else => {},
    }
    return emitSign(inst, sess, pSignature, pulSignatureLen);
}

pub fn C_SignRecoverInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_recover_op != null) return ck.CKR_OPERATION_ACTIVE;
    if (pMechanism.mechanism != ck.CKM_RSA_PKCS) return ck.CKR_MECHANISM_INVALID;
    const pc = switch (rsaPrivateComponents(inst, hKey, ck.CKA_SIGN_RECOVER)) {
        .err => |rv| return rv,
        .ok => |c| c,
    };
    sess.sign_recover_op = .{ .key = hKey, .out_len = pc.n.len };
    return ck.CKR_OK;
}

pub fn C_SignRecover(hSession: ck.CK_SESSION_HANDLE, pData: [*]ck.CK_BYTE, ulDataLen: ck.CK_ULONG, pSignature: ?[*]ck.CK_BYTE, pulSignatureLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.sign_recover_op) |o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    const need: ck.CK_ULONG = @intCast(op.out_len);
    if (pSignature == null) {
        pulSignatureLen.* = need;
        return ck.CKR_OK;
    }
    if (pulSignatureLen.* < need) {
        pulSignatureLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const in = part(pData, ulDataLen);
    if (in.len + rsa.pkcs1_v15_min_overhead > op.out_len) {
        sess.endSignRecover();
        return ck.CKR_DATA_LEN_RANGE;
    }
    const sc = switch (rsaPrivateComponents(inst, op.key, ck.CKA_SIGN_RECOVER)) {
        .err => |rv| {
            sess.endSignRecover();
            return rv;
        },
        .ok => |c| c,
    };
    const n = rsa.sign(sc, .{ .scheme = .pkcs1, .digest = .none }, in, pSignature.?[0..@intCast(need)]) catch {
        sess.endSignRecover();
        return ck.CKR_FUNCTION_FAILED;
    };
    pulSignatureLen.* = @intCast(n);
    sess.endSignRecover();
    return ck.CKR_OK;
}

pub fn C_VerifyInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.verify_op != null) return ck.CKR_OPERATION_ACTIVE;
    sess.verify_op = switch (verifyInitOp(inst, hKey, pMechanism)) {
        .err => |rv| return rv,
        .ok => |op| op,
    };
    return ck.CKR_OK;
}

pub fn C_Verify(hSession: ck.CK_SESSION_HANDLE, pData: [*]ck.CK_BYTE, ulDataLen: ck.CK_ULONG, pSignature: [*]ck.CK_BYTE, ulSignatureLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.verify_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (sess.verify_op.?) {
        .rsa => |op| {
            const data = part(pData, ulDataLen);
            sess.endVerify();
            if (ulSignatureLen != op.sig_len) return ck.CKR_SIGNATURE_LEN_RANGE;
            const pc = switch (rsaPublicComponents(inst, op.key, ck.CKA_VERIFY)) {
                .err => |rv| return rv,
                .ok => |c| c,
            };
            const r = rsa.verify(pc, op.params, data, pSignature[0..@intCast(ulSignatureLen)]) catch return ck.CKR_FUNCTION_FAILED;
            return switch (r) {
                .ok => ck.CKR_OK,
                .invalid => ck.CKR_SIGNATURE_INVALID,
            };
        },
        else => {
            sess.verify_op.?.update(part(pData, ulDataLen));
            return finalizeVerify(sess, pSignature, ulSignatureLen);
        },
    }
}

pub fn C_VerifyUpdate(hSession: ck.CK_SESSION_HANDLE, pPart: [*]ck.CK_BYTE, ulPartLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.verify_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (sess.verify_op.?) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        else => {},
    }
    sess.verify_op.?.update(part(pPart, ulPartLen));
    return ck.CKR_OK;
}

pub fn C_VerifyFinal(hSession: ck.CK_SESSION_HANDLE, pSignature: [*]ck.CK_BYTE, ulSignatureLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.verify_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (sess.verify_op.?) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        else => {},
    }
    return finalizeVerify(sess, pSignature, ulSignatureLen);
}

pub fn C_VerifyRecoverInit(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.verify_recover_op != null) return ck.CKR_OPERATION_ACTIVE;
    if (pMechanism.mechanism != ck.CKM_RSA_PKCS) return ck.CKR_MECHANISM_INVALID;
    const pc = switch (rsaPublicComponents(inst, hKey, ck.CKA_VERIFY_RECOVER)) {
        .err => |rv| return rv,
        .ok => |c| c,
    };
    sess.verify_recover_op = .{ .key = hKey, .out_len = pc.n.len };
    return ck.CKR_OK;
}

pub fn C_VerifyRecover(hSession: ck.CK_SESSION_HANDLE, pSignature: [*]ck.CK_BYTE, ulSignatureLen: ck.CK_ULONG, pData: ?[*]ck.CK_BYTE, pulDataLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    const op = if (sess.verify_recover_op) |o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    if (pData == null) {
        pulDataLen.* = @intCast(op.out_len);
        return ck.CKR_OK;
    }
    if (ulSignatureLen != op.out_len) {
        sess.endVerifyRecover();
        return ck.CKR_SIGNATURE_LEN_RANGE;
    }
    const pc = switch (rsaPublicComponents(inst, op.key, ck.CKA_VERIFY_RECOVER)) {
        .err => |rv| {
            sess.endVerifyRecover();
            return rv;
        },
        .ok => |c| c,
    };
    var tmp: [rsa.max_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &tmp);
    const m = rsa.recover(pc, part(pSignature, ulSignatureLen), &tmp) catch {
        sess.endVerifyRecover();
        return ck.CKR_SIGNATURE_INVALID;
    };
    if (pulDataLen.* < m) {
        pulDataLen.* = @intCast(m);
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    @memcpy(pData.?[0..m], tmp[0..m]);
    pulDataLen.* = @intCast(m);
    sess.endVerifyRecover();
    return ck.CKR_OK;
}

pub fn C_DigestEncryptUpdate(hSession: ck.CK_SESSION_HANDLE, pPart: [*]ck.CK_BYTE, ulPartLen: ck.CK_ULONG, pEncryptedPart: ?[*]ck.CK_BYTE, pulEncryptedPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.digest_op == null or sess.encrypt_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    const op = &sess.encrypt_op.?;
    const in = part(pPart, ulPartLen);
    const need = switch (encUpdateNeed(op, in.len)) {
        .err => |rv| return rv,
        .ok => |n| n,
    };
    if (pEncryptedPart == null) {
        pulEncryptedPartLen.* = need;
        return ck.CKR_OK;
    }
    if (pulEncryptedPartLen.* < need) {
        pulEncryptedPartLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    sess.digest_op.?.update(in);
    const wrote = switch (encUpdateEmit(inst, op, in, pEncryptedPart.?[0..@intCast(need)])) {
        .err => |rv| {
            sess.endEncrypt(inst.allocator());
            return rv;
        },
        .ok => |n| n,
    };
    pulEncryptedPartLen.* = @intCast(wrote);
    return ck.CKR_OK;
}

pub fn C_DecryptDigestUpdate(hSession: ck.CK_SESSION_HANDLE, pEncryptedPart: [*]ck.CK_BYTE, ulEncryptedPartLen: ck.CK_ULONG, pPart: ?[*]ck.CK_BYTE, pulPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.decrypt_op == null or sess.digest_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    const op = &sess.decrypt_op.?;
    if (!decryptSideDualOk(op)) return ck.CKR_FUNCTION_NOT_SUPPORTED;
    const in = part(pEncryptedPart, ulEncryptedPartLen);
    const need = switch (decUpdateNeed(op, in.len)) {
        .err => |rv| return rv,
        .ok => |n| n,
    };
    if (pPart == null) {
        pulPartLen.* = need;
        return ck.CKR_OK;
    }
    if (pulPartLen.* < need) {
        pulPartLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const out = pPart.?[0..@intCast(need)];
    const wrote = switch (decUpdateEmit(inst, op, in, out)) {
        .err => |rv| {
            sess.endDecrypt(inst.allocator());
            return rv;
        },
        .ok => |n| n,
    };
    sess.digest_op.?.update(out[0..wrote]);
    pulPartLen.* = @intCast(wrote);
    return ck.CKR_OK;
}

pub fn C_SignEncryptUpdate(hSession: ck.CK_SESSION_HANDLE, pPart: [*]ck.CK_BYTE, ulPartLen: ck.CK_ULONG, pEncryptedPart: ?[*]ck.CK_BYTE, pulEncryptedPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_op == null or sess.encrypt_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    switch (sess.sign_op.?) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        else => {},
    }
    const op = &sess.encrypt_op.?;
    const in = part(pPart, ulPartLen);
    const need = switch (encUpdateNeed(op, in.len)) {
        .err => |rv| return rv,
        .ok => |n| n,
    };
    if (pEncryptedPart == null) {
        pulEncryptedPartLen.* = need;
        return ck.CKR_OK;
    }
    if (pulEncryptedPartLen.* < need) {
        pulEncryptedPartLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    sess.sign_op.?.update(in);
    const wrote = switch (encUpdateEmit(inst, op, in, pEncryptedPart.?[0..@intCast(need)])) {
        .err => |rv| {
            sess.endEncrypt(inst.allocator());
            return rv;
        },
        .ok => |n| n,
    };
    pulEncryptedPartLen.* = @intCast(wrote);
    return ck.CKR_OK;
}

pub fn C_DecryptVerifyUpdate(hSession: ck.CK_SESSION_HANDLE, pEncryptedPart: [*]ck.CK_BYTE, ulEncryptedPartLen: ck.CK_ULONG, pPart: ?[*]ck.CK_BYTE, pulPartLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.decrypt_op == null or sess.verify_op == null) return ck.CKR_OPERATION_NOT_INITIALIZED;
    const op = &sess.decrypt_op.?;
    if (!decryptSideDualOk(op)) return ck.CKR_FUNCTION_NOT_SUPPORTED;
    switch (sess.verify_op.?) {
        .rsa => return ck.CKR_FUNCTION_NOT_SUPPORTED,
        else => {},
    }
    const in = part(pEncryptedPart, ulEncryptedPartLen);
    const need = switch (decUpdateNeed(op, in.len)) {
        .err => |rv| return rv,
        .ok => |n| n,
    };
    if (pPart == null) {
        pulPartLen.* = need;
        return ck.CKR_OK;
    }
    if (pulPartLen.* < need) {
        pulPartLen.* = need;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const out = pPart.?[0..@intCast(need)];
    const wrote = switch (decUpdateEmit(inst, op, in, out)) {
        .err => |rv| {
            sess.endDecrypt(inst.allocator());
            return rv;
        },
        .ok => |n| n,
    };
    sess.verify_op.?.update(out[0..wrote]);
    pulPartLen.* = @intCast(wrote);
    return ck.CKR_OK;
}
