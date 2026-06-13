// ©AngelaMos | 2026
// abi_test.zig

const std = @import("std");
const ck = @import("ck");
const p11c = @import("p11c");

const ptr = @sizeOf(usize);

test "scalar ABI widths match Cryptoki LP64" {
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(ck.CK_BYTE));
    try std.testing.expectEqual(@as(usize, 1), @sizeOf(ck.CK_BBOOL));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(ck.CK_ULONG));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(ck.CK_RV));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(ck.CK_SESSION_HANDLE));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(ck.CK_OBJECT_HANDLE));
}

test "CK_VERSION is two packed bytes" {
    try std.testing.expectEqual(@as(usize, 2), @sizeOf(ck.CK_VERSION));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(ck.CK_VERSION, "major"));
    try std.testing.expectEqual(@as(usize, 1), @offsetOf(ck.CK_VERSION, "minor"));
}

test "CK_ATTRIBUTE layout (type, pValue, ulValueLen)" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ck.CK_ATTRIBUTE));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(ck.CK_ATTRIBUTE, "type"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(ck.CK_ATTRIBUTE, "pValue"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(ck.CK_ATTRIBUTE, "ulValueLen"));
}

test "CK_MECHANISM layout" {
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(ck.CK_MECHANISM));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(ck.CK_MECHANISM, "mechanism"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(ck.CK_MECHANISM, "pParameter"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(ck.CK_MECHANISM, "ulParameterLen"));
}

test "CK_INFO natural-alignment layout" {
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(ck.CK_INFO, "flags"));
    try std.testing.expectEqual(@as(usize, 88), @sizeOf(ck.CK_INFO));
}

test "CK_TOKEN_INFO natural-alignment layout" {
    try std.testing.expectEqual(@as(usize, 96), @offsetOf(ck.CK_TOKEN_INFO, "flags"));
    try std.testing.expectEqual(@as(usize, 208), @sizeOf(ck.CK_TOKEN_INFO));
}

test "CK_FUNCTION_LIST is version + 68 pointers in canonical order" {
    try std.testing.expectEqual(69 * ptr, @sizeOf(ck.CK_FUNCTION_LIST));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(ck.CK_FUNCTION_LIST, "version"));
    try std.testing.expectEqual(ptr, @offsetOf(ck.CK_FUNCTION_LIST, "C_Initialize"));
    try std.testing.expectEqual(5 * ptr, @offsetOf(ck.CK_FUNCTION_LIST, "C_GetSlotList"));
    try std.testing.expectEqual(68 * ptr, @offsetOf(ck.CK_FUNCTION_LIST, "C_WaitForSlotEvent"));
}

test "key return codes have canonical values" {
    try std.testing.expectEqual(@as(ck.CK_RV, 0x00000000), ck.CKR_OK);
    try std.testing.expectEqual(@as(ck.CK_RV, 0x00000054), ck.CKR_FUNCTION_NOT_SUPPORTED);
    try std.testing.expectEqual(@as(ck.CK_RV, 0x00000150), ck.CKR_BUFFER_TOO_SMALL);
    try std.testing.expectEqual(@as(ck.CK_RV, 0x00000190), ck.CKR_CRYPTOKI_NOT_INITIALIZED);
}

fn expectSameLayout(comptime A: type, comptime B: type) !void {
    try std.testing.expectEqual(@sizeOf(A), @sizeOf(B));
    try std.testing.expectEqual(@alignOf(A), @alignOf(B));
    const fa = @typeInfo(A).@"struct".fields;
    const fb = @typeInfo(B).@"struct".fields;
    try std.testing.expectEqual(fa.len, fb.len);
    inline for (fa) |f| {
        try std.testing.expectEqual(@offsetOf(A, f.name), @offsetOf(B, f.name));
    }
}

test "hand-coded structs match OASIS-translated layout byte-for-byte" {
    try expectSameLayout(ck.CK_VERSION, p11c.CK_VERSION);
    try expectSameLayout(ck.CK_INFO, p11c.CK_INFO);
    try expectSameLayout(ck.CK_SLOT_INFO, p11c.CK_SLOT_INFO);
    try expectSameLayout(ck.CK_TOKEN_INFO, p11c.CK_TOKEN_INFO);
    try expectSameLayout(ck.CK_SESSION_INFO, p11c.CK_SESSION_INFO);
    try expectSameLayout(ck.CK_MECHANISM_INFO, p11c.CK_MECHANISM_INFO);
    try expectSameLayout(ck.CK_ATTRIBUTE, p11c.CK_ATTRIBUTE);
    try expectSameLayout(ck.CK_MECHANISM, p11c.CK_MECHANISM);
    try expectSameLayout(ck.CK_GCM_PARAMS, p11c.CK_GCM_PARAMS);
    try expectSameLayout(ck.CK_RSA_PKCS_PSS_PARAMS, p11c.CK_RSA_PKCS_PSS_PARAMS);
    try expectSameLayout(ck.CK_RSA_PKCS_OAEP_PARAMS, p11c.CK_RSA_PKCS_OAEP_PARAMS);
    try expectSameLayout(ck.CK_ECDH1_DERIVE_PARAMS, p11c.CK_ECDH1_DERIVE_PARAMS);
    try expectSameLayout(ck.CK_DATE, p11c.CK_DATE);
    try expectSameLayout(ck.CK_C_INITIALIZE_ARGS, p11c.CK_C_INITIALIZE_ARGS);
}

test "hand-coded CK_FUNCTION_LIST matches OASIS 68-entry order and size" {
    try expectSameLayout(ck.CK_FUNCTION_LIST, p11c.CK_FUNCTION_LIST);
}

test "every hand-coded constant equals its OASIS value" {
    @setEvalBranchQuota(20000);
    comptime var checked: usize = 0;
    inline for (@typeInfo(ck).@"struct".decls) |d| {
        if (@hasDecl(p11c, d.name)) {
            const value = @field(ck, d.name);
            const T = @TypeOf(value);
            if (T == type) continue;
            const info = @typeInfo(T);
            if (info != .int and info != .comptime_int) continue;
            const ours: u64 = @intCast(value);
            const theirs: u64 = @intCast(@field(p11c, d.name));
            if (ours != theirs) {
                std.debug.print("constant {s}: ck=0x{X} oasis=0x{X}\n", .{ d.name, ours, theirs });
                return error.ConstantMismatch;
            }
            checked += 1;
        }
    }
    try std.testing.expect(checked >= 100);
}

fn fnInfo(comptime FnPtr: type) std.builtin.Type.Fn {
    const fn_ptr = @typeInfo(FnPtr).optional.child;
    return @typeInfo(@typeInfo(fn_ptr).pointer.child).@"fn";
}

fn expectSameFnAbi(comptime name: []const u8, comptime A: type, comptime B: type) !void {
    const fa = fnInfo(A);
    const fb = fnInfo(B);
    if (fa.params.len != fb.params.len) {
        std.debug.print("fn {s}: param count ck={d} oasis={d}\n", .{ name, fa.params.len, fb.params.len });
        return error.FnAbiMismatch;
    }
    if (@sizeOf(fa.return_type.?) != @sizeOf(fb.return_type.?)) {
        std.debug.print("fn {s}: return-type size ck={d} oasis={d}\n", .{ name, @sizeOf(fa.return_type.?), @sizeOf(fb.return_type.?) });
        return error.FnAbiMismatch;
    }
    inline for (0..@min(fa.params.len, fb.params.len)) |i| {
        const ours = fa.params[i].type.?;
        const theirs = fb.params[i].type.?;
        if (@sizeOf(ours) != @sizeOf(theirs) or @alignOf(ours) != @alignOf(theirs)) {
            std.debug.print("fn {s}: param {d} ck={d}/{d} oasis={d}/{d}\n", .{ name, i, @sizeOf(ours), @alignOf(ours), @sizeOf(theirs), @alignOf(theirs) });
            return error.FnAbiMismatch;
        }
    }
}

test "every CK_FUNCTION_LIST entry matches the OASIS C ABI signature" {
    try std.testing.expectEqual(@as(usize, 3), fnInfo(ck.CK_C_GetSlotList).params.len);
    const cf = @typeInfo(ck.CK_FUNCTION_LIST).@"struct".fields;
    const pf = @typeInfo(p11c.CK_FUNCTION_LIST).@"struct".fields;
    inline for (cf, pf) |a, b| {
        comptime std.debug.assert(std.mem.eql(u8, a.name, b.name));
        if (comptime !std.mem.eql(u8, a.name, "version")) {
            try expectSameFnAbi(a.name, a.type, b.type);
        }
    }
}
