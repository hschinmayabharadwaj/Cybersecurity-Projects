// ©AngelaMos | 2026
// random.zig

const ck = @import("../ck.zig");
const state = @import("../core/state.zig");

pub fn C_SeedRandom(hSession: ck.CK_SESSION_HANDLE, _: [*]ck.CK_BYTE, _: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (inst.sessions.get(hSession) == null) return ck.CKR_SESSION_HANDLE_INVALID;
    return ck.CKR_RANDOM_SEED_NOT_SUPPORTED;
}

pub fn C_GenerateRandom(hSession: ck.CK_SESSION_HANDLE, pRandomData: [*]ck.CK_BYTE, ulRandomLen: ck.CK_ULONG) callconv(.c) ck.CK_RV {
    const inst = state.acquire() orelse return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    defer state.mutex.unlock();
    if (inst.sessions.get(hSession) == null) return ck.CKR_SESSION_HANDLE_INVALID;
    if (ulRandomLen == 0) return ck.CKR_OK;
    inst.io().randomSecure(pRandomData[0..@intCast(ulRandomLen)]) catch return ck.CKR_FUNCTION_FAILED;
    return ck.CKR_OK;
}
