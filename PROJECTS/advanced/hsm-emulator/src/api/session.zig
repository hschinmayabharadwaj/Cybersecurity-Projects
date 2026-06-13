// ©AngelaMos | 2026
// session.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const state = @import("../core/state.zig");
const pin = @import("../crypto/pin.zig");
const keystore = @import("../crypto/keystore.zig");
const token = @import("../core/token.zig");
const object_store = @import("../core/object_store.zig");
const digest = @import("../crypto/digest.zig");

fn pinSlice(p: ?[*]ck.CK_UTF8CHAR, len: ck.CK_ULONG) []const u8 {
    return if (p) |ptr| ptr[0..@intCast(len)] else &.{};
}

fn sessionState(flags: ck.CK_FLAGS, logged_in: ?ck.CK_USER_TYPE) ck.CK_STATE {
    const rw = (flags & ck.CKF_RW_SESSION) != 0;
    if (logged_in) |u| {
        if (u == ck.CKU_SO) return ck.CKS_RW_SO_FUNCTIONS;
        return if (rw) ck.CKS_RW_USER_FUNCTIONS else ck.CKS_RO_USER_FUNCTIONS;
    }
    return if (rw) ck.CKS_RW_PUBLIC_SESSION else ck.CKS_RO_PUBLIC_SESSION;
}

pub fn C_OpenSession(slotID: ck.CK_SLOT_ID, flags: ck.CK_FLAGS, pApplication: ?*anyopaque, notify: ck.CK_NOTIFY, phSession: *ck.CK_SESSION_HANDLE) callconv(.c) ck.CK_RV {
    _ = pApplication;
    _ = notify;
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (slotID != config.slot_id) return ck.CKR_SLOT_ID_INVALID;
    if ((flags & ck.CKF_SERIAL_SESSION) == 0) return ck.CKR_SESSION_PARALLEL_NOT_SUPPORTED;
    if ((flags & ck.CKF_RW_SESSION) == 0 and inst.logged_in == ck.CKU_SO) {
        return ck.CKR_SESSION_READ_WRITE_SO_EXISTS;
    }
    const h = inst.sessions.open(slotID, flags) orelse return ck.CKR_SESSION_COUNT;
    phSession.* = h;
    return ck.CKR_OK;
}

pub fn C_CloseSession(hSession: ck.CK_SESSION_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (!inst.sessions.close(inst.allocator(), hSession)) return ck.CKR_SESSION_HANDLE_INVALID;
    if (!inst.sessions.anyOpen()) {
        inst.relock();
        inst.logged_in = null;
    }
    return ck.CKR_OK;
}

pub fn C_CloseAllSessions(slotID: ck.CK_SLOT_ID) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (slotID != config.slot_id) return ck.CKR_SLOT_ID_INVALID;
    inst.sessions.closeAll(inst.allocator(), slotID);
    inst.relock();
    inst.logged_in = null;
    return ck.CKR_OK;
}

pub fn C_GetSessionInfo(hSession: ck.CK_SESSION_HANDLE, pInfo: *ck.CK_SESSION_INFO) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const s = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    pInfo.* = .{
        .slotID = s.slot,
        .state = sessionState(s.flags, inst.logged_in),
        .flags = s.flags,
        .ulDeviceError = 0,
    };
    return ck.CKR_OK;
}

pub fn C_GetOperationState(hSession: ck.CK_SESSION_HANDLE, pOperationState: ?[*]ck.CK_BYTE, pulOperationStateLen: *ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (sess.sign_op != null or sess.verify_op != null or sess.encrypt_op != null or
        sess.decrypt_op != null or sess.sign_recover_op != null or sess.verify_recover_op != null)
    {
        return ck.CKR_STATE_UNSAVEABLE;
    }
    const d = if (sess.digest_op) |*o| o else return ck.CKR_OPERATION_NOT_INITIALIZED;
    const total: ck.CK_ULONG = @intCast(config.op_state_header_len + d.stateLen());
    if (pOperationState == null) {
        pulOperationStateLen.* = total;
        return ck.CKR_OK;
    }
    if (pulOperationStateLen.* < total) {
        pulOperationStateLen.* = total;
        return ck.CKR_BUFFER_TOO_SMALL;
    }
    const out = pOperationState.?[0..@intCast(total)];
    out[0] = config.op_state_version;
    out[1] = d.stateTag();
    d.writeState(out[config.op_state_header_len..]);
    pulOperationStateLen.* = total;
    return ck.CKR_OK;
}

pub fn C_SetOperationState(hSession: ck.CK_SESSION_HANDLE, pOperationState: [*]ck.CK_BYTE, ulOperationStateLen: ck.CK_ULONG, hEncryptionKey: ck.CK_OBJECT_HANDLE, hAuthenticationKey: ck.CK_OBJECT_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    const sess = inst.sessions.get(hSession) orelse return ck.CKR_SESSION_HANDLE_INVALID;
    if (hEncryptionKey != ck.CK_INVALID_HANDLE or hAuthenticationKey != ck.CK_INVALID_HANDLE) {
        return ck.CKR_KEY_NOT_NEEDED;
    }
    const blob = pOperationState[0..@intCast(ulOperationStateLen)];
    if (blob.len < config.op_state_header_len) return ck.CKR_SAVED_STATE_INVALID;
    if (blob[0] != config.op_state_version) return ck.CKR_SAVED_STATE_INVALID;
    const restored = digest.Hasher.fromState(blob[1], blob[config.op_state_header_len..]) orelse return ck.CKR_SAVED_STATE_INVALID;
    sess.endDigest();
    sess.digest_op = restored;
    return ck.CKR_OK;
}

pub fn C_Login(hSession: ck.CK_SESSION_HANDLE, userType: ck.CK_USER_TYPE, pPin: ?[*]ck.CK_UTF8CHAR, ulPinLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    if (userType != ck.CKU_SO and userType != ck.CKU_USER) {
        state.mutex.unlock();
        return ck.CKR_USER_TYPE_INVALID;
    }

    if (inst.sessions.get(hSession) == null) {
        state.mutex.unlock();
        return ck.CKR_SESSION_HANDLE_INVALID;
    }
    if (inst.logged_in != null) {
        state.mutex.unlock();
        return ck.CKR_USER_ALREADY_LOGGED_IN;
    }
    var salt: pin.Salt = undefined;
    var hash: pin.Hash = undefined;
    var wrapped_mk: ?keystore.Wrapped = null;
    if (userType == ck.CKU_SO) {
        if (inst.sessions.count() > inst.sessions.countRw()) {
            state.mutex.unlock();
            return ck.CKR_SESSION_READ_ONLY_EXISTS;
        }
        if (!inst.token.initialized) {
            state.mutex.unlock();
            return ck.CKR_USER_PIN_NOT_INITIALIZED;
        }
        if (inst.token.so_fail >= config.login_max_attempts) {
            state.mutex.unlock();
            return ck.CKR_PIN_LOCKED;
        }
        salt = inst.token.so.salt;
        hash = inst.token.so.hash;
    } else {
        const u = inst.token.user orelse {
            state.mutex.unlock();
            return ck.CKR_USER_PIN_NOT_INITIALIZED;
        };
        if (inst.token.user_fail >= config.login_max_attempts) {
            state.mutex.unlock();
            return ck.CKR_PIN_LOCKED;
        }
        salt = u.salt;
        hash = u.hash;
        wrapped_mk = inst.token.user_mk;
    }
    const gen = state.cryptoBegin();
    const io = inst.io();
    const allocator = inst.allocator();
    state.mutex.unlock();
    defer std.crypto.secureZero(u8, &hash);

    const ok = pin.verify(io, allocator, pinSlice(pPin, ulPinLen), &salt, &hash) catch {
        state.cryptoAbort();
        return ck.CKR_FUNCTION_FAILED;
    };

    var mk: keystore.MasterKey = undefined;
    defer std.crypto.secureZero(u8, &mk);
    var have_mk = false;
    if (ok and userType == ck.CKU_USER) {
        if (wrapped_mk) |w| {
            have_mk = keystore.unwrap(io, allocator, pinSlice(pPin, ulPinLen), &w, &mk) catch {
                state.cryptoAbort();
                return ck.CKR_FUNCTION_FAILED;
            };
            if (!have_mk) {
                state.cryptoAbort();
                return ck.CKR_FUNCTION_FAILED;
            }
        }
    }

    state.mutex.lock();
    defer state.mutex.unlock();
    state.cryptoEnd();
    if (state.currentGeneration() != gen) return ck.CKR_FUNCTION_FAILED;
    if (inst.sessions.get(hSession) == null) return ck.CKR_SESSION_HANDLE_INVALID;
    if (inst.logged_in != null) return ck.CKR_USER_ALREADY_LOGGED_IN;
    if (ok) {
        if (userType == ck.CKU_SO) inst.token.so_fail = 0 else inst.token.user_fail = 0;
        inst.logged_in = userType;
        if (have_mk) {
            inst.mk = mk;
            object_store.unlock(allocator, &inst.objects, mk) catch {
                inst.relock();
                inst.logged_in = null;
                return ck.CKR_FUNCTION_FAILED;
            };
        }
        token.save(inst.io(), inst.token) catch {};
        return ck.CKR_OK;
    }
    if (userType == ck.CKU_SO) inst.token.so_fail += 1 else inst.token.user_fail += 1;
    token.save(inst.io(), inst.token) catch {};
    return ck.CKR_PIN_INCORRECT;
}

pub fn C_Logout(hSession: ck.CK_SESSION_HANDLE) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (inst.sessions.get(hSession) == null) return ck.CKR_SESSION_HANDLE_INVALID;
    if (inst.logged_in == null) return ck.CKR_USER_NOT_LOGGED_IN;
    inst.relock();
    inst.logged_in = null;
    return ck.CKR_OK;
}
