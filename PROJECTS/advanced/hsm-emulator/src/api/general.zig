// ©AngelaMos | 2026
// general.zig

const ck = @import("../ck.zig");
const config = @import("../config.zig");
const util = @import("../util.zig");
const state = @import("../core/state.zig");

pub fn C_Initialize(pInitArgs: ?*anyopaque) callconv(.c) ck.CK_RV {
    state.mutex.lock();
    defer state.mutex.unlock();
    if (state.isInitialized()) return ck.CKR_CRYPTOKI_ALREADY_INITIALIZED;
    switch (state.parseInitArgs(pInitArgs)) {
        .err => |rv| return rv,
        .ok => |locking| state.initialize(locking),
    }
    return ck.CKR_OK;
}

pub fn C_Finalize(pReserved: ?*anyopaque) callconv(.c) ck.CK_RV {
    if (pReserved != null) return ck.CKR_ARGUMENTS_BAD;
    return state.finalize();
}

pub fn C_GetInfo(pInfo: *ck.CK_INFO) callconv(.c) ck.CK_RV {
    state.mutex.lock();
    defer state.mutex.unlock();
    if (!state.isInitialized()) return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    pInfo.* = .{
        .cryptokiVersion = config.cryptoki_version,
        .manufacturerID = util.padded(32, config.manufacturer_id),
        .flags = 0,
        .libraryDescription = util.padded(32, config.library_description),
        .libraryVersion = config.library_version,
    };
    return ck.CKR_OK;
}

pub fn C_GetFunctionStatus(_: ck.CK_SESSION_HANDLE) callconv(.c) ck.CK_RV {
    return ck.CKR_FUNCTION_NOT_PARALLEL;
}

pub fn C_CancelFunction(_: ck.CK_SESSION_HANDLE) callconv(.c) ck.CK_RV {
    return ck.CKR_FUNCTION_NOT_PARALLEL;
}

pub fn C_WaitForSlotEvent(flags: ck.CK_FLAGS, pSlot: *ck.CK_SLOT_ID, pReserved: ?*anyopaque) callconv(.c) ck.CK_RV {
    _ = pSlot;
    if (!state.isInitialized()) return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    if (pReserved != null) return ck.CKR_ARGUMENTS_BAD;
    if ((flags & ck.CKF_DONT_BLOCK) != 0) return ck.CKR_NO_EVENT;
    return ck.CKR_FUNCTION_NOT_SUPPORTED;
}
