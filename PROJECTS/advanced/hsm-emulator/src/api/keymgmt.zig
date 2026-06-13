// ©AngelaMos | 2026
// keymgmt.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const state = @import("../core/state.zig");
const session = @import("../core/session.zig");
const object_store = @import("../core/object_store.zig");
const object = @import("object.zig");
const ecdsa = @import("../crypto/ecdsa.zig");
const rsa = @import("../crypto/rsa.zig");
const cipher = @import("../crypto/cipher.zig");

const Object = object_store.Object;

fn attrBytes(a: ck.CK_ATTRIBUTE) []const u8 {
    const ptr = a.pValue orelse return &.{};
    return @as([*]const u8, @ptrCast(ptr))[0..@intCast(a.ulValueLen)];
}

fn ulongFrom(bytes: []const u8) ?ck.CK_ULONG {
    if (bytes.len != @sizeOf(ck.CK_ULONG)) return null;
    return std.mem.bytesToValue(ck.CK_ULONG, bytes[0..@sizeOf(ck.CK_ULONG)]);
}

pub fn C_GenerateKey(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, pTemplate: [*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG, phKey: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (pMechanism.mechanism != ck.CKM_AES_KEY_GEN) return ck.CKR_MECHANISM_INVALID;

    const allocator = inst.allocator();
    const template = if (ulCount == 0) &[_]ck.CK_ATTRIBUTE{} else pTemplate[0..@intCast(ulCount)];

    var key_len: usize = 0;
    var have_len = false;
    for (template) |a| {
        if (a.type == ck.CKA_VALUE_LEN) {
            const v = ulongFrom(attrBytes(a)) orelse return ck.CKR_ATTRIBUTE_VALUE_INVALID;
            key_len = @intCast(v);
            have_len = true;
        }
    }
    if (!have_len) return ck.CKR_TEMPLATE_INCOMPLETE;
    if (key_len != config.aes_min_key_bytes and key_len != config.aes_max_key_bytes) return ck.CKR_KEY_SIZE_RANGE;

    var obj: Object = .{};
    var moved = false;
    defer if (!moved) obj.deinit(allocator);

    for (template) |a| {
        obj.set(allocator, a.type, attrBytes(a)) catch |e| return object_store.mapSetErr(e);
    }

    var key_bytes: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key_bytes);
    inst.io().randomSecure(key_bytes[0..key_len]) catch return ck.CKR_FUNCTION_FAILED;

    var class_val: ck.CK_OBJECT_CLASS = ck.CKO_SECRET_KEY;
    var type_val: ck.CK_KEY_TYPE = ck.CKK_AES;
    obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val)) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val)) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_VALUE, key_bytes[0..key_len]) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE}) catch |e| return object_store.mapSetErr(e);
    const kgm: ck.CK_MECHANISM_TYPE = ck.CKM_AES_KEY_GEN;
    obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&kgm)) catch |e| return object_store.mapSetErr(e);

    if (!obj.has(ck.CKA_SENSITIVE)) obj.set(allocator, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE}) catch |e| return object_store.mapSetErr(e);
    if (!obj.has(ck.CKA_EXTRACTABLE)) obj.set(allocator, ck.CKA_EXTRACTABLE, &[_]u8{ck.CK_FALSE}) catch |e| return object_store.mapSetErr(e);
    const always_sensitive: u8 = if (obj.getBool(ck.CKA_SENSITIVE)) ck.CK_TRUE else ck.CK_FALSE;
    const never_extractable: u8 = if (!obj.getBool(ck.CKA_EXTRACTABLE)) ck.CK_TRUE else ck.CK_FALSE;
    obj.set(allocator, ck.CKA_ALWAYS_SENSITIVE, &[_]u8{always_sensitive}) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_NEVER_EXTRACTABLE, &[_]u8{never_extractable}) catch |e| return object_store.mapSetErr(e);

    object.materializeDefaults(&obj, allocator, ck.CKO_SECRET_KEY) catch |e| return object_store.mapSetErr(e);

    moved = true;
    return object.insertNew(inst, sess, obj, phKey);
}

fn ecParamsFrom(template: []const ck.CK_ATTRIBUTE) ?[]const u8 {
    for (template) |a| {
        if (a.type == ck.CKA_EC_PARAMS) return attrBytes(a);
    }
    return null;
}

fn modulusBitsFrom(template: []const ck.CK_ATTRIBUTE) ?ck.CK_ULONG {
    for (template) |a| {
        if (a.type == ck.CKA_MODULUS_BITS) return ulongFrom(attrBytes(a));
    }
    return null;
}

fn applySensitivityDefaults(obj: *Object, allocator: std.mem.Allocator, kgm: ck.CK_MECHANISM_TYPE) !void {
    try obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE});
    if (!obj.has(ck.CKA_SENSITIVE)) try obj.set(allocator, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE});
    if (!obj.has(ck.CKA_EXTRACTABLE)) try obj.set(allocator, ck.CKA_EXTRACTABLE, &[_]u8{ck.CK_FALSE});
    const always_sensitive: u8 = if (obj.getBool(ck.CKA_SENSITIVE)) ck.CK_TRUE else ck.CK_FALSE;
    const never_extractable: u8 = if (!obj.getBool(ck.CKA_EXTRACTABLE)) ck.CK_TRUE else ck.CK_FALSE;
    try obj.set(allocator, ck.CKA_ALWAYS_SENSITIVE, &[_]u8{always_sensitive});
    try obj.set(allocator, ck.CKA_NEVER_EXTRACTABLE, &[_]u8{never_extractable});
    const m: ck.CK_MECHANISM_TYPE = kgm;
    try obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&m));
}

fn buildEcPublic(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, curve: ecdsa.Curve, point: []const u8) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PUBLIC_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_EC;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_EC_PARAMS, curve.oidDer());
    var der_buf: [ecdsa.max_ec_point_der]u8 = undefined;
    try obj.set(allocator, ck.CKA_EC_POINT, ecdsa.wrapEcPoint(&der_buf, point));
    try obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE});
    const kgm: ck.CK_MECHANISM_TYPE = ck.CKM_EC_KEY_PAIR_GEN;
    try obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&kgm));
    try object.materializeDefaults(obj, allocator, ck.CKO_PUBLIC_KEY);
}

fn buildEcPrivate(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, curve: ecdsa.Curve, scalar: []const u8) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PRIVATE_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_EC;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_EC_PARAMS, curve.oidDer());
    try obj.set(allocator, ck.CKA_VALUE, scalar);
    try applySensitivityDefaults(obj, allocator, ck.CKM_EC_KEY_PAIR_GEN);
    try object.materializeDefaults(obj, allocator, ck.CKO_PRIVATE_KEY);
}

fn buildRsaPublic(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, g: *const rsa.Generated) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PUBLIC_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_RSA;
    const bits: ck.CK_ULONG = g.bits;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_MODULUS, g.n.slice());
    try obj.set(allocator, ck.CKA_PUBLIC_EXPONENT, g.e.slice());
    try obj.set(allocator, ck.CKA_MODULUS_BITS, std.mem.asBytes(&bits));
    try obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_TRUE});
    const kgm: ck.CK_MECHANISM_TYPE = ck.CKM_RSA_PKCS_KEY_PAIR_GEN;
    try obj.set(allocator, ck.CKA_KEY_GEN_MECHANISM, std.mem.asBytes(&kgm));
    try object.materializeDefaults(obj, allocator, ck.CKO_PUBLIC_KEY);
}

fn buildRsaPrivate(obj: *Object, allocator: std.mem.Allocator, template: []const ck.CK_ATTRIBUTE, g: *const rsa.Generated) !void {
    for (template) |a| try obj.set(allocator, a.type, attrBytes(a));
    const class_val: ck.CK_OBJECT_CLASS = ck.CKO_PRIVATE_KEY;
    const type_val: ck.CK_KEY_TYPE = ck.CKK_RSA;
    try obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&class_val));
    try obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&type_val));
    try obj.set(allocator, ck.CKA_MODULUS, g.n.slice());
    try obj.set(allocator, ck.CKA_PUBLIC_EXPONENT, g.e.slice());
    try obj.set(allocator, ck.CKA_PRIVATE_EXPONENT, g.d.slice());
    try obj.set(allocator, ck.CKA_PRIME_1, g.p.slice());
    try obj.set(allocator, ck.CKA_PRIME_2, g.q.slice());
    try obj.set(allocator, ck.CKA_EXPONENT_1, g.dmp1.slice());
    try obj.set(allocator, ck.CKA_EXPONENT_2, g.dmq1.slice());
    try obj.set(allocator, ck.CKA_COEFFICIENT, g.iqmp.slice());
    try applySensitivityDefaults(obj, allocator, ck.CKM_RSA_PKCS_KEY_PAIR_GEN);
    try object.materializeDefaults(obj, allocator, ck.CKO_PRIVATE_KEY);
}

pub fn C_GenerateKeyPair(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, pPublicKeyTemplate: [*]ck.CK_ATTRIBUTE, ulPublicKeyAttributeCount: ck.CK_ULONG, pPrivateKeyTemplate: [*]ck.CK_ATTRIBUTE, ulPrivateKeyAttributeCount: ck.CK_ULONG, phPublicKey: *ck.CK_OBJECT_HANDLE, phPrivateKey: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;

    const allocator = inst.allocator();
    const pub_template = if (ulPublicKeyAttributeCount == 0) &[_]ck.CK_ATTRIBUTE{} else pPublicKeyTemplate[0..@intCast(ulPublicKeyAttributeCount)];
    const priv_template = if (ulPrivateKeyAttributeCount == 0) &[_]ck.CK_ATTRIBUTE{} else pPrivateKeyTemplate[0..@intCast(ulPrivateKeyAttributeCount)];

    var pub_obj: Object = .{};
    var pub_moved = false;
    defer if (!pub_moved) pub_obj.deinit(allocator);
    var priv_obj: Object = .{};
    var priv_moved = false;
    defer if (!priv_moved) priv_obj.deinit(allocator);

    switch (pMechanism.mechanism) {
        ck.CKM_EC_KEY_PAIR_GEN => {
            const params = ecParamsFrom(pub_template) orelse return ck.CKR_TEMPLATE_INCOMPLETE;
            const curve = ecdsa.curveFromParams(params) orelse return ck.CKR_DOMAIN_PARAMS_INVALID;
            var km = ecdsa.generate(inst.io(), curve) catch return ck.CKR_FUNCTION_FAILED;
            defer std.crypto.secureZero(u8, &km.scalar);
            buildEcPublic(&pub_obj, allocator, pub_template, curve, km.pointBytes()) catch |e| return object_store.mapSetErr(e);
            buildEcPrivate(&priv_obj, allocator, priv_template, curve, km.scalarBytes()) catch |e| return object_store.mapSetErr(e);
        },
        ck.CKM_RSA_PKCS_KEY_PAIR_GEN => {
            const bits = modulusBitsFrom(pub_template) orelse return ck.CKR_TEMPLATE_INCOMPLETE;
            if (bits < config.rsa_min_key_bits or bits > config.rsa_max_key_bits) return ck.CKR_KEY_SIZE_RANGE;
            var g = rsa.generate(@intCast(bits)) catch return ck.CKR_FUNCTION_FAILED;
            defer g.zeroize();
            buildRsaPublic(&pub_obj, allocator, pub_template, &g) catch |e| return object_store.mapSetErr(e);
            buildRsaPrivate(&priv_obj, allocator, priv_template, &g) catch |e| return object_store.mapSetErr(e);
        },
        else => return ck.CKR_MECHANISM_INVALID,
    }

    const pub_is_token = pub_obj.isToken();
    pub_moved = true;
    const pub_rv = object.insertNew(inst, sess, pub_obj, phPublicKey);
    if (pub_rv != ck.CKR_OK) return pub_rv;

    priv_moved = true;
    const priv_rv = object.insertNew(inst, sess, priv_obj, phPrivateKey);
    if (priv_rv != ck.CKR_OK) {
        _ = inst.objects.destroy(allocator, phPublicKey.*);
        if (pub_is_token) object_store.save(inst.io(), allocator, &inst.objects, inst.mk) catch {};
        return priv_rv;
    }
    return ck.CKR_OK;
}

fn buildSecretKeyObject(
    inst: *state.Instance,
    sess: *session.Session,
    template: []const ck.CK_ATTRIBUTE,
    value: []const u8,
    base_always_sensitive: bool,
    base_never_extractable: bool,
    phKey: *ck.CK_OBJECT_HANDLE,
) ck.CK_RV {
    const allocator = inst.allocator();
    var obj: Object = .{};
    var moved = false;
    defer if (!moved) obj.deinit(allocator);

    for (template) |a| {
        if (a.type == ck.CKA_VALUE_LEN or a.type == ck.CKA_VALUE) continue;
        obj.set(allocator, a.type, attrBytes(a)) catch |e| return object_store.mapSetErr(e);
    }

    if (!obj.has(ck.CKA_CLASS)) {
        const cls: ck.CK_OBJECT_CLASS = ck.CKO_SECRET_KEY;
        obj.set(allocator, ck.CKA_CLASS, std.mem.asBytes(&cls)) catch |e| return object_store.mapSetErr(e);
    }
    if (!obj.has(ck.CKA_KEY_TYPE)) {
        const kt: ck.CK_KEY_TYPE = ck.CKK_GENERIC_SECRET;
        obj.set(allocator, ck.CKA_KEY_TYPE, std.mem.asBytes(&kt)) catch |e| return object_store.mapSetErr(e);
    }
    obj.set(allocator, ck.CKA_VALUE, value) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_LOCAL, &[_]u8{ck.CK_FALSE}) catch |e| return object_store.mapSetErr(e);

    if (!obj.has(ck.CKA_SENSITIVE)) obj.set(allocator, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE}) catch |e| return object_store.mapSetErr(e);
    if (!obj.has(ck.CKA_EXTRACTABLE)) obj.set(allocator, ck.CKA_EXTRACTABLE, &[_]u8{ck.CK_FALSE}) catch |e| return object_store.mapSetErr(e);
    const always_sensitive: u8 = if (obj.getBool(ck.CKA_SENSITIVE) and base_always_sensitive) ck.CK_TRUE else ck.CK_FALSE;
    const never_extractable: u8 = if (!obj.getBool(ck.CKA_EXTRACTABLE) and base_never_extractable) ck.CK_TRUE else ck.CK_FALSE;
    obj.set(allocator, ck.CKA_ALWAYS_SENSITIVE, &[_]u8{always_sensitive}) catch |e| return object_store.mapSetErr(e);
    obj.set(allocator, ck.CKA_NEVER_EXTRACTABLE, &[_]u8{never_extractable}) catch |e| return object_store.mapSetErr(e);

    object.materializeDefaults(&obj, allocator, ck.CKO_SECRET_KEY) catch |e| return object_store.mapSetErr(e);

    moved = true;
    return object.insertNew(inst, sess, obj, phKey);
}

const SecretVal = union(enum) {
    ok: []const u8,
    err: ck.CK_RV,
};

fn wrapTargetValue(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE) SecretVal {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (classOf(obj) != ck.CKO_SECRET_KEY) return .{ .err = ck.CKR_KEY_NOT_WRAPPABLE };
    if (obj.has(ck.CKA_EXTRACTABLE) and !obj.getBool(ck.CKA_EXTRACTABLE)) return .{ .err = ck.CKR_KEY_UNEXTRACTABLE };
    const sa = obj.findPtr(ck.CKA_VALUE) orelse return .{ .err = ck.CKR_KEY_NOT_WRAPPABLE };
    if (sa.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    return .{ .ok = sa.value };
}

fn aesKekValue(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE, usage: ck.CK_ATTRIBUTE_TYPE, handle_err: ck.CK_RV, type_err: ck.CK_RV, size_err: ck.CK_RV) SecretVal {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = handle_err };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = handle_err };
    if (classOf(obj) != ck.CKO_SECRET_KEY or keyTypeOf(obj) != ck.CKK_AES) return .{ .err = type_err };
    if (obj.has(usage) and !obj.getBool(usage)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    const sa = obj.findPtr(ck.CKA_VALUE) orelse return .{ .err = handle_err };
    if (sa.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    if (!cipher.validKeyLen(sa.value.len)) return .{ .err = size_err };
    return .{ .ok = sa.value };
}

const RsaPubVal = union(enum) {
    ok: rsa.PublicComponents,
    err: ck.CK_RV,
};

fn rsaWrapPublic(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE) RsaPubVal {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_WRAPPING_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_WRAPPING_KEY_HANDLE_INVALID };
    if (classOf(obj) != ck.CKO_PUBLIC_KEY or keyTypeOf(obj) != ck.CKK_RSA) return .{ .err = ck.CKR_WRAPPING_KEY_TYPE_INCONSISTENT };
    if (obj.has(ck.CKA_WRAP) and !obj.getBool(ck.CKA_WRAP)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    return .{ .ok = .{
        .n = obj.get(ck.CKA_MODULUS) orelse return .{ .err = ck.CKR_WRAPPING_KEY_HANDLE_INVALID },
        .e = obj.get(ck.CKA_PUBLIC_EXPONENT) orelse return .{ .err = ck.CKR_WRAPPING_KEY_HANDLE_INVALID },
    } };
}

const RsaPrivVal = union(enum) {
    ok: rsa.PrivateComponents,
    err: ck.CK_RV,
};

fn rsaUnwrapPrivate(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE) RsaPrivVal {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID };
    if (classOf(obj) != ck.CKO_PRIVATE_KEY or keyTypeOf(obj) != ck.CKK_RSA) return .{ .err = ck.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT };
    if (obj.has(ck.CKA_UNWRAP) and !obj.getBool(ck.CKA_UNWRAP)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    if (obj.findPtr(ck.CKA_PRIVATE_EXPONENT)) |da| {
        if (da.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    }
    return .{ .ok = .{
        .n = obj.get(ck.CKA_MODULUS) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .e = obj.get(ck.CKA_PUBLIC_EXPONENT) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .d = obj.get(ck.CKA_PRIVATE_EXPONENT) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .p = obj.get(ck.CKA_PRIME_1) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .q = obj.get(ck.CKA_PRIME_2) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .dmp1 = obj.get(ck.CKA_EXPONENT_1) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .dmq1 = obj.get(ck.CKA_EXPONENT_2) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
        .iqmp = obj.get(ck.CKA_COEFFICIENT) orelse return .{ .err = ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID },
    } };
}

fn mgfHash(mgf: ck.CK_RSA_PKCS_MGF_TYPE) ?rsa.Hash {
    return switch (mgf) {
        ck.CKG_MGF1_SHA256 => .sha256,
        ck.CKG_MGF1_SHA384 => .sha384,
        ck.CKG_MGF1_SHA512 => .sha512,
        else => null,
    };
}

const OaepVal = union(enum) {
    ok: rsa.CryptParams,
    err: ck.CK_RV,
};

fn oaepParams(pMechanism: *ck.CK_MECHANISM) OaepVal {
    const p = pMechanism.pParameter orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    if (pMechanism.ulParameterLen != @sizeOf(ck.CK_RSA_PKCS_OAEP_PARAMS)) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    const op: *const ck.CK_RSA_PKCS_OAEP_PARAMS = @ptrCast(@alignCast(p));
    const h = rsa.Hash.fromMech(op.hashAlg) orelse return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    if (mgfHash(op.mgf) != h) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    if (op.ulSourceDataLen != 0) return .{ .err = ck.CKR_MECHANISM_PARAM_INVALID };
    return .{ .ok = .{ .scheme = .oaep, .oaep_hash = h } };
}

pub fn C_WrapKey(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hWrappingKey: ck.CK_OBJECT_HANDLE, hKey: ck.CK_OBJECT_HANDLE, pWrappedKey: ?[*]ck.CK_BYTE, pulWrappedKeyLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    _ = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;

    const target = switch (wrapTargetValue(inst, hKey)) {
        .err => |rv| return rv,
        .ok => |v| v,
    };

    switch (pMechanism.mechanism) {
        ck.CKM_AES_KEY_WRAP => {
            const kek = switch (aesKekValue(inst, hWrappingKey, ck.CKA_WRAP, ck.CKR_WRAPPING_KEY_HANDLE_INVALID, ck.CKR_WRAPPING_KEY_TYPE_INCONSISTENT, ck.CKR_WRAPPING_KEY_SIZE_RANGE)) {
                .err => |rv| return rv,
                .ok => |v| v,
            };
            if (target.len < 2 * cipher.key_wrap_overhead or target.len % cipher.key_wrap_overhead != 0) return ck.CKR_KEY_NOT_WRAPPABLE;
            const need: ck.CK_ULONG = @intCast(target.len + cipher.key_wrap_overhead);
            if (pWrappedKey == null) {
                pulWrappedKeyLen.* = need;
                return ck.CKR_OK;
            }
            if (pulWrappedKeyLen.* < need) {
                pulWrappedKeyLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = cipher.aesKeyWrap(kek, target, pWrappedKey.?[0..@intCast(need)]) catch return ck.CKR_FUNCTION_FAILED;
            pulWrappedKeyLen.* = @intCast(n);
            return ck.CKR_OK;
        },
        ck.CKM_RSA_PKCS_OAEP => {
            const params = switch (oaepParams(pMechanism)) {
                .err => |rv| return rv,
                .ok => |p| p,
            };
            const pc = switch (rsaWrapPublic(inst, hWrappingKey)) {
                .err => |rv| return rv,
                .ok => |c| c,
            };
            const need: ck.CK_ULONG = @intCast(pc.n.len);
            if (pWrappedKey == null) {
                pulWrappedKeyLen.* = need;
                return ck.CKR_OK;
            }
            if (pulWrappedKeyLen.* < need) {
                pulWrappedKeyLen.* = need;
                return ck.CKR_BUFFER_TOO_SMALL;
            }
            const n = rsa.encrypt(pc, params, target, pWrappedKey.?[0..@intCast(need)]) catch return ck.CKR_KEY_SIZE_RANGE;
            pulWrappedKeyLen.* = @intCast(n);
            return ck.CKR_OK;
        },
        else => return ck.CKR_MECHANISM_INVALID,
    }
}

pub fn C_UnwrapKey(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hUnwrappingKey: ck.CK_OBJECT_HANDLE, pWrappedKey: [*]ck.CK_BYTE, ulWrappedKeyLen: ck.CK_ULONG, pTemplate: [*]ck.CK_ATTRIBUTE, ulAttributeCount: ck.CK_ULONG, phKey: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;

    const wrapped = pWrappedKey[0..@intCast(ulWrappedKeyLen)];
    const template = if (ulAttributeCount == 0) &[_]ck.CK_ATTRIBUTE{} else pTemplate[0..@intCast(ulAttributeCount)];

    var buf: [rsa.max_modulus_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);

    const recovered: []const u8 = switch (pMechanism.mechanism) {
        ck.CKM_AES_KEY_WRAP => blk: {
            const kek = switch (aesKekValue(inst, hUnwrappingKey, ck.CKA_UNWRAP, ck.CKR_UNWRAPPING_KEY_HANDLE_INVALID, ck.CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, ck.CKR_UNWRAPPING_KEY_SIZE_RANGE)) {
                .err => |rv| return rv,
                .ok => |v| v,
            };
            if (wrapped.len < 3 * cipher.key_wrap_overhead or wrapped.len % cipher.key_wrap_overhead != 0) return ck.CKR_WRAPPED_KEY_LEN_RANGE;
            if (wrapped.len - cipher.key_wrap_overhead > buf.len) return ck.CKR_WRAPPED_KEY_LEN_RANGE;
            const n = cipher.aesKeyUnwrap(kek, wrapped, &buf) catch |e| switch (e) {
                cipher.WrapError.Integrity => return ck.CKR_WRAPPED_KEY_INVALID,
                else => return ck.CKR_WRAPPED_KEY_LEN_RANGE,
            };
            break :blk buf[0..n];
        },
        ck.CKM_RSA_PKCS_OAEP => blk: {
            const params = switch (oaepParams(pMechanism)) {
                .err => |rv| return rv,
                .ok => |p| p,
            };
            const sc = switch (rsaUnwrapPrivate(inst, hUnwrappingKey)) {
                .err => |rv| return rv,
                .ok => |c| c,
            };
            const n = rsa.decrypt(sc, params, wrapped, &buf) catch return ck.CKR_WRAPPED_KEY_INVALID;
            break :blk buf[0..n];
        },
        else => return ck.CKR_MECHANISM_INVALID,
    };

    var final = recovered;
    for (template) |a| {
        if (a.type == ck.CKA_VALUE_LEN) {
            const v = ulongFrom(attrBytes(a)) orelse return ck.CKR_ATTRIBUTE_VALUE_INVALID;
            const vlen: usize = @intCast(v);
            if (vlen == 0 or vlen > recovered.len) return ck.CKR_ATTRIBUTE_VALUE_INVALID;
            final = recovered[0..vlen];
        }
    }

    return buildSecretKeyObject(inst, sess, template, final, false, false, phKey);
}

fn classOf(obj: *const Object) ?ck.CK_OBJECT_CLASS {
    const v = obj.get(ck.CKA_CLASS) orelse return null;
    if (v.len != @sizeOf(ck.CK_OBJECT_CLASS)) return null;
    return std.mem.bytesToValue(ck.CK_OBJECT_CLASS, v[0..@sizeOf(ck.CK_OBJECT_CLASS)]);
}

fn keyTypeOf(obj: *const Object) ?ck.CK_KEY_TYPE {
    const v = obj.get(ck.CKA_KEY_TYPE) orelse return null;
    if (v.len != @sizeOf(ck.CK_KEY_TYPE)) return null;
    return std.mem.bytesToValue(ck.CK_KEY_TYPE, v[0..@sizeOf(ck.CK_KEY_TYPE)]);
}

const EcDeriveBase = union(enum) {
    ok: struct {
        curve: ecdsa.Curve,
        scalar: []const u8,
        always_sensitive: bool,
        never_extractable: bool,
    },
    err: ck.CK_RV,
};

fn ecDeriveBaseKey(inst: *state.Instance, hKey: ck.CK_OBJECT_HANDLE) EcDeriveBase {
    const obj = inst.objects.getPtr(hKey) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (!object_store.visible(obj, inst.logged_in)) return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (classOf(obj) != ck.CKO_PRIVATE_KEY) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (keyTypeOf(obj) != ck.CKK_EC) return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    if (obj.has(ck.CKA_DERIVE) and !obj.getBool(ck.CKA_DERIVE)) return .{ .err = ck.CKR_KEY_FUNCTION_NOT_PERMITTED };
    const params = obj.get(ck.CKA_EC_PARAMS) orelse return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    const curve = ecdsa.curveFromParams(params) orelse return .{ .err = ck.CKR_KEY_TYPE_INCONSISTENT };
    const sa = obj.findPtr(ck.CKA_VALUE) orelse return .{ .err = ck.CKR_KEY_HANDLE_INVALID };
    if (sa.sealed) return .{ .err = ck.CKR_USER_NOT_LOGGED_IN };
    if (sa.value.len != curve.scalarLen()) return .{ .err = ck.CKR_FUNCTION_FAILED };
    return .{ .ok = .{
        .curve = curve,
        .scalar = sa.value,
        .always_sensitive = obj.getBool(ck.CKA_ALWAYS_SENSITIVE),
        .never_extractable = obj.getBool(ck.CKA_NEVER_EXTRACTABLE),
    } };
}

fn peerPointSec1(curve: ecdsa.Curve, data: []const u8) ?[]const u8 {
    if (data.len == curve.pointLen()) return data;
    const inner = ecdsa.unwrapEcPoint(data) orelse return null;
    if (inner.len == curve.pointLen()) return inner;
    return null;
}

pub fn C_DeriveKey(hSession: ck.CK_SESSION_HANDLE, pMechanism: *ck.CK_MECHANISM, hBaseKey: ck.CK_OBJECT_HANDLE, pTemplate: ?[*]ck.CK_ATTRIBUTE, ulCount: ck.CK_ULONG, phKey: *ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (pMechanism.mechanism != ck.CKM_ECDH1_DERIVE) return ck.CKR_MECHANISM_INVALID;

    const p = pMechanism.pParameter orelse return ck.CKR_MECHANISM_PARAM_INVALID;
    if (pMechanism.ulParameterLen != @sizeOf(ck.CK_ECDH1_DERIVE_PARAMS)) return ck.CKR_MECHANISM_PARAM_INVALID;
    const dp: *const ck.CK_ECDH1_DERIVE_PARAMS = @ptrCast(@alignCast(p));
    if (dp.kdf != ck.CKD_NULL) return ck.CKR_MECHANISM_PARAM_INVALID;
    if (dp.ulSharedDataLen != 0) return ck.CKR_MECHANISM_PARAM_INVALID;
    const peer = (dp.pPublicData orelse return ck.CKR_MECHANISM_PARAM_INVALID)[0..@intCast(dp.ulPublicDataLen)];

    const base = switch (ecDeriveBaseKey(inst, hBaseKey)) {
        .err => |rv| return rv,
        .ok => |b| b,
    };

    const peer_sec1 = peerPointSec1(base.curve, peer) orelse return ck.CKR_MECHANISM_PARAM_INVALID;
    var secret: [ecdsa.max_scalar]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    const slen = ecdsa.ecdh(base.curve, base.scalar, peer_sec1, &secret) catch return ck.CKR_FUNCTION_FAILED;

    const template = if (ulCount == 0) &[_]ck.CK_ATTRIBUTE{} else (pTemplate orelse return ck.CKR_ARGUMENTS_BAD)[0..@intCast(ulCount)];

    var value_len: usize = slen;
    for (template) |a| {
        if (a.type == ck.CKA_VALUE_LEN) {
            const v = ulongFrom(attrBytes(a)) orelse return ck.CKR_ATTRIBUTE_VALUE_INVALID;
            value_len = @intCast(v);
        }
    }
    if (value_len == 0 or value_len > slen) return ck.CKR_ATTRIBUTE_VALUE_INVALID;

    return buildSecretKeyObject(inst, sess, template, secret[0..value_len], base.always_sensitive, base.never_extractable, phKey);
}
