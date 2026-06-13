// ©AngelaMos | 2026
// slot_token.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const util = @import("../util.zig");
const state = @import("../core/state.zig");
const pin = @import("../crypto/pin.zig");
const keystore = @import("../crypto/keystore.zig");
const token = @import("../core/token.zig");
const object_store = @import("../core/object_store.zig");

fn requireInit() ?ck.CK_RV {
    return if (state.isInitialized()) null else ck.CKR_CRYPTOKI_NOT_INITIALIZED;
}

fn pinSlice(p: ?[*]ck.CK_UTF8CHAR, len: ck.CK_ULONG) []const u8 {
    return if (p) |ptr| ptr[0..@intCast(len)] else &.{};
}

fn pinLenOk(len: ck.CK_ULONG) bool {
    return len >= config.min_pin_len and len <= config.max_pin_len;
}

fn labelFrom(p: ?[*]ck.CK_UTF8CHAR) [config.label_len]u8 {
    var out: [config.label_len]u8 = @splat(' ');
    if (p) |lp| @memcpy(&out, lp[0..config.label_len]);
    return out;
}

fn pinStateFlags(fail: u32, low: ck.CK_FLAGS, final_try: ck.CK_FLAGS, locked: ck.CK_FLAGS) ck.CK_FLAGS {
    const f: ck.CK_ULONG = fail;
    const max = config.login_max_attempts;
    if (f >= max) return locked;
    if (f == max - 1) return final_try;
    if (f > 0) return low;
    return 0;
}

pub fn C_GetSlotList(_: ck.CK_BBOOL, pSlotList: ?[*]ck.CK_SLOT_ID, pulCount: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    if (requireInit()) |rv| return rv;
    if (pSlotList == null) {
        pulCount.* = config.slot_count;
        return ck.CKR_OK;
    }
    if (pulCount.* < config.slot_count) {
        pulCount.* = config.slot_count;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    pSlotList.?[0] = config.slot_id;
    pulCount.* = config.slot_count;
    return ck.CKR_OK;
}

pub fn C_GetSlotInfo(slotID: ck.CK_SLOT_ID, pInfo: *ck.CK_SLOT_INFO) callconv(.c) ck.CK_RV {
    if (requireInit()) |rv| return rv;
    if (slotID != config.slot_id) return ck.CKR_SLOT_ID_INVALID;
    pInfo.* = .{
        .slotDescription = util.padded(64, config.slot_description),
        .manufacturerID = util.padded(32, config.manufacturer_id),
        .flags = ck.CKF_TOKEN_PRESENT | ck.CKF_HW_SLOT,
        .hardwareVersion = config.hardware_version,
        .firmwareVersion = config.firmware_version,
    };
    return ck.CKR_OK;
}

pub fn C_GetTokenInfo(slotID: ck.CK_SLOT_ID, pInfo: *ck.CK_TOKEN_INFO) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (slotID != config.slot_id) return ck.CKR_SLOT_ID_INVALID;

    var flags: ck.CK_FLAGS = ck.CKF_RNG | ck.CKF_LOGIN_REQUIRED;
    if (inst.token.initialized) flags |= ck.CKF_TOKEN_INITIALIZED;
    if (inst.token.user != null) flags |= ck.CKF_USER_PIN_INITIALIZED;
    flags |= pinStateFlags(inst.token.user_fail, ck.CKF_USER_PIN_COUNT_LOW, ck.CKF_USER_PIN_FINAL_TRY, ck.CKF_USER_PIN_LOCKED);
    flags |= pinStateFlags(inst.token.so_fail, ck.CKF_SO_PIN_COUNT_LOW, ck.CKF_SO_PIN_FINAL_TRY, ck.CKF_SO_PIN_LOCKED);

    pInfo.* = .{
        .label = if (inst.token.initialized) inst.token.label else util.padded(32, config.token_label),
        .manufacturerID = util.padded(32, config.manufacturer_id),
        .model = util.padded(16, config.token_model),
        .serialNumber = util.padded(16, config.token_serial),
        .flags = flags,
        .ulMaxSessionCount = config.max_sessions,
        .ulSessionCount = inst.sessions.count(),
        .ulMaxRwSessionCount = config.max_sessions,
        .ulRwSessionCount = inst.sessions.countRw(),
        .ulMaxPinLen = config.max_pin_len,
        .ulMinPinLen = config.min_pin_len,
        .ulTotalPublicMemory = ck.CK_UNAVAILABLE_INFORMATION,
        .ulFreePublicMemory = ck.CK_UNAVAILABLE_INFORMATION,
        .ulTotalPrivateMemory = ck.CK_UNAVAILABLE_INFORMATION,
        .ulFreePrivateMemory = ck.CK_UNAVAILABLE_INFORMATION,
        .hardwareVersion = config.hardware_version,
        .firmwareVersion = config.firmware_version,
        .utcTime = util.padded(16, ""),
    };
    return ck.CKR_OK;
}

pub fn C_GetMechanismList(slotID: ck.CK_SLOT_ID, pMechanismList: ?[*]ck.CK_MECHANISM_TYPE, pulCount: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    if (requireInit()) |rv| return rv;
    if (slotID != config.slot_id) return ck.CKR_SLOT_ID_INVALID;
    const n: ck.CK_ULONG = config.supported_mechanisms.len;
    if (pMechanismList == null) {
        pulCount.* = n;
        return ck.CKR_OK;
    }
    if (pulCount.* < n) {
        pulCount.* = n;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    for (config.supported_mechanisms, 0..) |m, i| pMechanismList.?[i] = m;
    pulCount.* = n;
    return ck.CKR_OK;
}

pub fn C_GetMechanismInfo(slotID: ck.CK_SLOT_ID, mechType: ck.CK_MECHANISM_TYPE, pInfo: *ck.CK_MECHANISM_INFO) callconv(.c) ck.CK_RV {
    if (requireInit()) |rv| return rv;
    if (slotID != config.slot_id) return ck.CKR_SLOT_ID_INVALID;
    pInfo.* = switch (mechType) {
        ck.CKM_SHA256, ck.CKM_SHA384, ck.CKM_SHA512 => .{
            .ulMinKeySize = 0,
            .ulMaxKeySize = 0,
            .flags = ck.CKF_DIGEST,
        },
        ck.CKM_SHA256_HMAC, ck.CKM_SHA384_HMAC, ck.CKM_SHA512_HMAC => .{
            .ulMinKeySize = config.hmac_min_key_bytes,
            .ulMaxKeySize = config.hmac_max_key_bytes,
            .flags = ck.CKF_SIGN | ck.CKF_VERIFY,
        },
        ck.CKM_AES_KEY_GEN => .{
            .ulMinKeySize = config.aes_min_key_bytes,
            .ulMaxKeySize = config.aes_max_key_bytes,
            .flags = ck.CKF_GENERATE,
        },
        ck.CKM_AES_CBC, ck.CKM_AES_CBC_PAD, ck.CKM_AES_GCM => .{
            .ulMinKeySize = config.aes_min_key_bytes,
            .ulMaxKeySize = config.aes_max_key_bytes,
            .flags = ck.CKF_ENCRYPT | ck.CKF_DECRYPT,
        },
        ck.CKM_AES_KEY_WRAP => .{
            .ulMinKeySize = config.aes_min_key_bytes,
            .ulMaxKeySize = config.aes_max_key_bytes,
            .flags = ck.CKF_WRAP | ck.CKF_UNWRAP,
        },
        ck.CKM_EC_KEY_PAIR_GEN => .{
            .ulMinKeySize = config.ec_min_key_bits,
            .ulMaxKeySize = config.ec_max_key_bits,
            .flags = ck.CKF_GENERATE_KEY_PAIR | ck.CKF_EC_NAMEDCURVE,
        },
        ck.CKM_ECDSA, ck.CKM_ECDSA_SHA256 => .{
            .ulMinKeySize = config.ec_min_key_bits,
            .ulMaxKeySize = config.ec_max_key_bits,
            .flags = ck.CKF_SIGN | ck.CKF_VERIFY | ck.CKF_EC_NAMEDCURVE,
        },
        ck.CKM_ECDH1_DERIVE => .{
            .ulMinKeySize = config.ec_min_key_bits,
            .ulMaxKeySize = config.ec_max_key_bits,
            .flags = ck.CKF_DERIVE | ck.CKF_EC_NAMEDCURVE,
        },
        ck.CKM_RSA_PKCS_KEY_PAIR_GEN => .{
            .ulMinKeySize = config.rsa_min_key_bits,
            .ulMaxKeySize = config.rsa_max_key_bits,
            .flags = ck.CKF_GENERATE_KEY_PAIR,
        },
        ck.CKM_RSA_PKCS => .{
            .ulMinKeySize = config.rsa_min_key_bits,
            .ulMaxKeySize = config.rsa_max_key_bits,
            .flags = ck.CKF_SIGN | ck.CKF_VERIFY | ck.CKF_ENCRYPT | ck.CKF_DECRYPT | ck.CKF_SIGN_RECOVER | ck.CKF_VERIFY_RECOVER,
        },
        ck.CKM_SHA256_RSA_PKCS, ck.CKM_RSA_PKCS_PSS, ck.CKM_SHA256_RSA_PKCS_PSS => .{
            .ulMinKeySize = config.rsa_min_key_bits,
            .ulMaxKeySize = config.rsa_max_key_bits,
            .flags = ck.CKF_SIGN | ck.CKF_VERIFY,
        },
        ck.CKM_RSA_PKCS_OAEP => .{
            .ulMinKeySize = config.rsa_min_key_bits,
            .ulMaxKeySize = config.rsa_max_key_bits,
            .flags = ck.CKF_ENCRYPT | ck.CKF_DECRYPT | ck.CKF_WRAP | ck.CKF_UNWRAP,
        },
        else => return ck.CKR_MECHANISM_INVALID,
    };
    return ck.CKR_OK;
}

pub fn C_InitToken(slotID: ck.CK_SLOT_ID, pPin: ?[*]ck.CK_UTF8CHAR, ulPinLen: ck.CK_ULONG, pLabel: ?[*]ck.CK_UTF8CHAR) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != config.slot_id) {
        state.mutex.unlock();
        return ck.CKR_SLOT_ID_INVALID;
    }

    if (inst.sessions.anyOpen()) {
        state.mutex.unlock();
        return ck.CKR_SESSION_EXISTS;
    }
    const was_init = inst.token.initialized;
    if (!was_init and !pinLenOk(ulPinLen)) {
        state.mutex.unlock();
        return ck.CKR_PIN_LEN_RANGE;
    }
    if (was_init and inst.token.so_fail >= config.login_max_attempts) {
        state.mutex.unlock();
        return ck.CKR_PIN_LOCKED;
    }
    var snap_so = inst.token.so;
    const gen = state.cryptoBegin();
    const io = inst.io();
    const allocator = inst.allocator();
    state.mutex.unlock();
    defer std.crypto.secureZero(u8, &snap_so.hash);

    const new_label = labelFrom(pLabel);

    if (was_init) {
        const ok = pin.verify(io, allocator, pinSlice(pPin, ulPinLen), &snap_so.salt, &snap_so.hash) catch {
            state.cryptoAbort();
            return ck.CKR_FUNCTION_FAILED;
        };
        state.mutex.lock();
        defer state.mutex.unlock();
        state.cryptoEnd();
        if (state.currentGeneration() != gen) return ck.CKR_FUNCTION_FAILED;
        if (!ok) {
            inst.token.so_fail += 1;
            token.save(inst.io(), inst.token) catch {};
            return ck.CKR_PIN_INCORRECT;
        }
        inst.token.user = null;
        inst.token.user_mk = null;
        inst.wipeMasterKey();
        inst.token.user_fail = 0;
        inst.token.so_fail = 0;
        inst.token.label = new_label;
        inst.logged_in = null;
        state.bumpGeneration();
        inst.objects.clear(inst.allocator());
        token.save(inst.io(), inst.token) catch {};
        object_store.save(inst.io(), inst.allocator(), &inst.objects, inst.mk) catch {};
        return ck.CKR_OK;
    }

    var salt: pin.Salt = undefined;
    pin.genSalt(io, &salt) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };
    var hash: pin.Hash = undefined;
    defer std.crypto.secureZero(u8, &hash);
    pin.derive(io, allocator, pinSlice(pPin, ulPinLen), &salt, &hash) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };

    state.mutex.lock();
    defer state.mutex.unlock();
    state.cryptoEnd();
    inst.token.initialized = true;
    inst.token.so = .{ .salt = salt, .hash = hash };
    inst.token.user = null;
    inst.token.user_mk = null;
    inst.wipeMasterKey();
    inst.token.so_fail = 0;
    inst.token.user_fail = 0;
    inst.token.label = new_label;
    inst.logged_in = null;
    state.bumpGeneration();
    inst.objects.clear(inst.allocator());
    token.save(inst.io(), inst.token) catch {};
    object_store.save(inst.io(), inst.allocator(), &inst.objects, inst.mk) catch {};
    return ck.CKR_OK;
}

pub fn C_InitPIN(hSession: ck.CK_SESSION_HANDLE, pPin: ?[*]ck.CK_UTF8CHAR, ulPinLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;

    if (inst.sessions.get(hSession) == null) {
        state.mutex.unlock();
        return ck.CKR_SESSION_HANDLE_INVALID;
    }
    if (inst.logged_in != ck.CKU_SO) {
        state.mutex.unlock();
        return ck.CKR_USER_NOT_LOGGED_IN;
    }
    if (!pinLenOk(ulPinLen)) {
        state.mutex.unlock();
        return ck.CKR_PIN_LEN_RANGE;
    }
    _ = state.cryptoBegin();
    const io = inst.io();
    const allocator = inst.allocator();
    state.mutex.unlock();

    var salt: pin.Salt = undefined;
    pin.genSalt(io, &salt) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };
    var hash: pin.Hash = undefined;
    defer std.crypto.secureZero(u8, &hash);
    pin.derive(io, allocator, pinSlice(pPin, ulPinLen), &salt, &hash) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };

    var mk: keystore.MasterKey = undefined;
    defer std.crypto.secureZero(u8, &mk);
    keystore.generateMasterKey(io, &mk) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };
    const wrapped = keystore.wrap(io, allocator, pinSlice(pPin, ulPinLen), &mk) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };

    state.mutex.lock();
    defer state.mutex.unlock();
    state.cryptoEnd();
    inst.token.user = .{ .salt = salt, .hash = hash };
    inst.token.user_mk = wrapped;
    inst.token.user_fail = 0;
    state.bumpGeneration();
    token.save(inst.io(), inst.token) catch {};
    return ck.CKR_OK;
}

pub fn C_SetPIN(hSession: ck.CK_SESSION_HANDLE, pOldPin: ?[*]ck.CK_UTF8CHAR, ulOldLen: ck.CK_ULONG, pNewPin: ?[*]ck.CK_UTF8CHAR, ulNewLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;

    const sess = inst.sessions.get(hSession) orelse {
        state.mutex.unlock();
        return ck.CKR_SESSION_HANDLE_INVALID;
    };
    if ((sess.flags & ck.CKF_RW_SESSION) == 0) {
        state.mutex.unlock();
        return ck.CKR_SESSION_READ_ONLY;
    }
    const as_so = inst.logged_in == ck.CKU_SO;
    var salt: pin.Salt = undefined;
    var hash: pin.Hash = undefined;
    var wrapped_mk: ?keystore.Wrapped = null;
    if (as_so) {
        if (!inst.token.initialized) {
            state.mutex.unlock();
            return ck.CKR_USER_PIN_NOT_INITIALIZED;
        }
        salt = inst.token.so.salt;
        hash = inst.token.so.hash;
    } else {
        const u = inst.token.user orelse {
            state.mutex.unlock();
            return ck.CKR_USER_PIN_NOT_INITIALIZED;
        };
        salt = u.salt;
        hash = u.hash;
        wrapped_mk = inst.token.user_mk;
    }
    if (!pinLenOk(ulNewLen)) {
        state.mutex.unlock();
        return ck.CKR_PIN_LEN_RANGE;
    }
    const gen = state.cryptoBegin();
    const io = inst.io();
    const allocator = inst.allocator();
    state.mutex.unlock();
    defer std.crypto.secureZero(u8, &hash);

    const old_ok = pin.verify(io, allocator, pinSlice(pOldPin, ulOldLen), &salt, &hash) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };
    if (!old_ok) {
        state.cryptoAbort();
        return ck.CKR_PIN_INCORRECT;
    }

    var nsalt: pin.Salt = undefined;
    pin.genSalt(io, &nsalt) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };
    var nhash: pin.Hash = undefined;
    defer std.crypto.secureZero(u8, &nhash);
    pin.derive(io, allocator, pinSlice(pNewPin, ulNewLen), &nsalt, &nhash) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };

    var new_mk_wrap: ?keystore.Wrapped = null;
    if (!as_so) {
        if (wrapped_mk) |w| {
            var mk: keystore.MasterKey = undefined;
            defer std.crypto.secureZero(u8, &mk);
            const unwrapped = keystore.unwrap(io, allocator, pinSlice(pOldPin, ulOldLen), &w, &mk) catch {
                state.cryptoAbort();
                return ck.CKR_FUNCTION_FAILED;
            };
            if (!unwrapped) {
                state.cryptoAbort();
                return ck.CKR_FUNCTION_FAILED;
            }
            new_mk_wrap = keystore.rewrap(io, allocator, pinSlice(pNewPin, ulNewLen), &mk) catch {
                state.cryptoAbort();
                return ck.CKR_FUNCTION_FAILED;
            };
        }
    }

    state.mutex.lock();
    defer state.mutex.unlock();
    state.cryptoEnd();
    if (state.currentGeneration() != gen) return ck.CKR_FUNCTION_FAILED;
    if (as_so) {
        inst.token.so = .{ .salt = nsalt, .hash = nhash };
        inst.token.so_fail = 0;
    } else {
        inst.token.user = .{ .salt = nsalt, .hash = nhash };
        if (new_mk_wrap) |w| inst.token.user_mk = w;
        inst.token.user_fail = 0;
    }
    state.bumpGeneration();
    token.save(inst.io(), inst.token) catch {};
    return ck.CKR_OK;
}
