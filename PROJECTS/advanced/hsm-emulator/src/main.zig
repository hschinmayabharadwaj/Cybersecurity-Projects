// ©AngelaMos | 2026
// main.zig

const std = @import("std");
const ck = @import("ck.zig");
const general = @import("api/general.zig");
const slot_token = @import("api/slot_token.zig");
const session = @import("api/session.zig");
const object = @import("api/object.zig");
const crypto_ops = @import("api/crypto_ops.zig");
const keymgmt = @import("api/keymgmt.zig");
const random = @import("api/random.zig");

comptime {
    std.debug.assert(@sizeOf(ck.CK_FUNCTION_LIST) == 69 * @sizeOf(usize));
    std.debug.assert(@sizeOf(ck.CK_ATTRIBUTE) == 24);
}

export fn C_GetFunctionList(ppFunctionList: *?*ck.CK_FUNCTION_LIST) callconv(.c) ck.CK_RV {
    ppFunctionList.* = &function_list;
    return ck.CKR_OK;
}

var function_list: ck.CK_FUNCTION_LIST = .{
    .version = ck.CK_VERSION{ .major = 2, .minor = 40 },
    .C_Initialize = general.C_Initialize,
    .C_Finalize = general.C_Finalize,
    .C_GetInfo = general.C_GetInfo,
    .C_GetFunctionList = C_GetFunctionList,
    .C_GetSlotList = slot_token.C_GetSlotList,
    .C_GetSlotInfo = slot_token.C_GetSlotInfo,
    .C_GetTokenInfo = slot_token.C_GetTokenInfo,
    .C_GetMechanismList = slot_token.C_GetMechanismList,
    .C_GetMechanismInfo = slot_token.C_GetMechanismInfo,
    .C_InitToken = slot_token.C_InitToken,
    .C_InitPIN = slot_token.C_InitPIN,
    .C_SetPIN = slot_token.C_SetPIN,
    .C_OpenSession = session.C_OpenSession,
    .C_CloseSession = session.C_CloseSession,
    .C_CloseAllSessions = session.C_CloseAllSessions,
    .C_GetSessionInfo = session.C_GetSessionInfo,
    .C_GetOperationState = session.C_GetOperationState,
    .C_SetOperationState = session.C_SetOperationState,
    .C_Login = session.C_Login,
    .C_Logout = session.C_Logout,
    .C_CreateObject = object.C_CreateObject,
    .C_CopyObject = object.C_CopyObject,
    .C_DestroyObject = object.C_DestroyObject,
    .C_GetObjectSize = object.C_GetObjectSize,
    .C_GetAttributeValue = object.C_GetAttributeValue,
    .C_SetAttributeValue = object.C_SetAttributeValue,
    .C_FindObjectsInit = object.C_FindObjectsInit,
    .C_FindObjects = object.C_FindObjects,
    .C_FindObjectsFinal = object.C_FindObjectsFinal,
    .C_EncryptInit = crypto_ops.C_EncryptInit,
    .C_Encrypt = crypto_ops.C_Encrypt,
    .C_EncryptUpdate = crypto_ops.C_EncryptUpdate,
    .C_EncryptFinal = crypto_ops.C_EncryptFinal,
    .C_DecryptInit = crypto_ops.C_DecryptInit,
    .C_Decrypt = crypto_ops.C_Decrypt,
    .C_DecryptUpdate = crypto_ops.C_DecryptUpdate,
    .C_DecryptFinal = crypto_ops.C_DecryptFinal,
    .C_DigestInit = crypto_ops.C_DigestInit,
    .C_Digest = crypto_ops.C_Digest,
    .C_DigestUpdate = crypto_ops.C_DigestUpdate,
    .C_DigestKey = crypto_ops.C_DigestKey,
    .C_DigestFinal = crypto_ops.C_DigestFinal,
    .C_SignInit = crypto_ops.C_SignInit,
    .C_Sign = crypto_ops.C_Sign,
    .C_SignUpdate = crypto_ops.C_SignUpdate,
    .C_SignFinal = crypto_ops.C_SignFinal,
    .C_SignRecoverInit = crypto_ops.C_SignRecoverInit,
    .C_SignRecover = crypto_ops.C_SignRecover,
    .C_VerifyInit = crypto_ops.C_VerifyInit,
    .C_Verify = crypto_ops.C_Verify,
    .C_VerifyUpdate = crypto_ops.C_VerifyUpdate,
    .C_VerifyFinal = crypto_ops.C_VerifyFinal,
    .C_VerifyRecoverInit = crypto_ops.C_VerifyRecoverInit,
    .C_VerifyRecover = crypto_ops.C_VerifyRecover,
    .C_DigestEncryptUpdate = crypto_ops.C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = crypto_ops.C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = crypto_ops.C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = crypto_ops.C_DecryptVerifyUpdate,
    .C_GenerateKey = keymgmt.C_GenerateKey,
    .C_GenerateKeyPair = keymgmt.C_GenerateKeyPair,
    .C_WrapKey = keymgmt.C_WrapKey,
    .C_UnwrapKey = keymgmt.C_UnwrapKey,
    .C_DeriveKey = keymgmt.C_DeriveKey,
    .C_SeedRandom = random.C_SeedRandom,
    .C_GenerateRandom = random.C_GenerateRandom,
    .C_GetFunctionStatus = general.C_GetFunctionStatus,
    .C_CancelFunction = general.C_CancelFunction,
    .C_WaitForSlotEvent = general.C_WaitForSlotEvent,
};
