// ©AngelaMos | 2026
// object_store.zig

const std = @import("std");
const ck = @import("../ck.zig");
const config = @import("../config.zig");
const env = @import("env.zig");
const keystore = @import("../crypto/keystore.zig");

fn secureFree(allocator: std.mem.Allocator, value: []u8) void {
    std.crypto.secureZero(u8, value);
    allocator.free(value);
}

pub const Attribute = struct {
    type: ck.CK_ATTRIBUTE_TYPE,
    value: []u8,
    sealed: bool = false,
};

fn isSecretMaterial(t: ck.CK_ATTRIBUTE_TYPE) bool {
    return switch (t) {
        ck.CKA_VALUE,
        ck.CKA_PRIVATE_EXPONENT,
        ck.CKA_PRIME_1,
        ck.CKA_PRIME_2,
        ck.CKA_EXPONENT_1,
        ck.CKA_EXPONENT_2,
        ck.CKA_COEFFICIENT,
        => true,
        else => false,
    };
}

pub const Object = struct {
    attrs: std.ArrayList(Attribute) = .empty,

    pub fn deinit(self: *Object, allocator: std.mem.Allocator) void {
        for (self.attrs.items) |a| secureFree(allocator, a.value);
        self.attrs.deinit(allocator);
        self.* = .{};
    }

    pub fn findPtr(self: *Object, t: ck.CK_ATTRIBUTE_TYPE) ?*Attribute {
        for (self.attrs.items) |*a| {
            if (a.type == t) return a;
        }
        return null;
    }

    pub fn get(self: *const Object, t: ck.CK_ATTRIBUTE_TYPE) ?[]const u8 {
        for (self.attrs.items) |a| {
            if (a.type == t) return a.value;
        }
        return null;
    }

    pub fn has(self: *const Object, t: ck.CK_ATTRIBUTE_TYPE) bool {
        return self.get(t) != null;
    }

    pub fn getBool(self: *const Object, t: ck.CK_ATTRIBUTE_TYPE) bool {
        const v = self.get(t) orelse return false;
        return v.len >= 1 and v[0] != ck.CK_FALSE;
    }

    pub fn isToken(self: *const Object) bool {
        return self.getBool(ck.CKA_TOKEN);
    }

    pub fn isPrivate(self: *const Object) bool {
        return self.getBool(ck.CKA_PRIVATE);
    }

    pub fn shouldSeal(self: *const Object, t: ck.CK_ATTRIBUTE_TYPE) bool {
        if (!isSecretMaterial(t)) return false;
        if (self.getBool(ck.CKA_SENSITIVE)) return true;
        return self.has(ck.CKA_EXTRACTABLE) and !self.getBool(ck.CKA_EXTRACTABLE);
    }

    pub fn hasSealable(self: *const Object) bool {
        for (self.attrs.items) |a| {
            if (self.shouldSeal(a.type)) return true;
        }
        return false;
    }

    pub fn set(self: *Object, allocator: std.mem.Allocator, t: ck.CK_ATTRIBUTE_TYPE, bytes: []const u8) !void {
        if (bytes.len > config.max_attr_value_len) return error.AttrTooLarge;
        if (self.findPtr(t)) |a| {
            const dup = try allocator.dupe(u8, bytes);
            secureFree(allocator, a.value);
            a.value = dup;
            a.sealed = false;
            return;
        }
        if (self.attrs.items.len >= config.max_attributes_per_object) return error.TooManyAttributes;
        const dup = try allocator.dupe(u8, bytes);
        errdefer secureFree(allocator, dup);
        try self.attrs.append(allocator, .{ .type = t, .value = dup });
    }

    pub fn sizeBytes(self: *const Object) ck.CK_ULONG {
        var total: ck.CK_ULONG = 0;
        for (self.attrs.items) |a| total += @intCast(a.value.len);
        return total;
    }

    pub fn clone(self: *const Object, allocator: std.mem.Allocator) !Object {
        var out: Object = .{};
        errdefer out.deinit(allocator);
        for (self.attrs.items) |a| {
            try out.set(allocator, a.type, a.value);
            out.findPtr(a.type).?.sealed = a.sealed;
        }
        return out;
    }
};

pub fn visible(obj: *const Object, logged_in: ?ck.CK_USER_TYPE) bool {
    if (!obj.isPrivate()) return true;
    return logged_in == ck.CKU_USER;
}

pub fn mapSetErr(e: anyerror) ck.CK_RV {
    return switch (e) {
        error.OutOfMemory => ck.CKR_HOST_MEMORY,
        error.AttrTooLarge => ck.CKR_ATTRIBUTE_VALUE_INVALID,
        error.TooManyAttributes => ck.CKR_TEMPLATE_INCONSISTENT,
        else => ck.CKR_FUNCTION_FAILED,
    };
}

const Entry = struct {
    handle: ck.CK_OBJECT_HANDLE,
    obj: Object,
};

pub const Store = struct {
    slots: [config.max_objects]?Entry = @splat(null),
    next_handle: ck.CK_OBJECT_HANDLE = 1,

    pub fn insert(self: *Store, obj: Object) ?ck.CK_OBJECT_HANDLE {
        for (&self.slots) |*slot| {
            if (slot.* == null) {
                const h = self.next_handle;
                slot.* = .{ .handle = h, .obj = obj };
                self.next_handle += 1;
                return h;
            }
        }
        return null;
    }

    pub fn getPtr(self: *Store, h: ck.CK_OBJECT_HANDLE) ?*Object {
        if (h == ck.CK_INVALID_HANDLE) return null;
        for (&self.slots) |*slot| {
            if (slot.*) |*e| {
                if (e.handle == h) return &e.obj;
            }
        }
        return null;
    }

    pub fn destroy(self: *Store, allocator: std.mem.Allocator, h: ck.CK_OBJECT_HANDLE) bool {
        if (h == ck.CK_INVALID_HANDLE) return false;
        for (&self.slots) |*slot| {
            if (slot.*) |*e| {
                if (e.handle == h) {
                    e.obj.deinit(allocator);
                    slot.* = null;
                    return true;
                }
            }
        }
        return false;
    }

    pub fn count(self: *const Store) usize {
        var n: usize = 0;
        for (self.slots) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    pub fn clear(self: *Store, allocator: std.mem.Allocator) void {
        for (&self.slots) |*slot| {
            if (slot.*) |*e| {
                e.obj.deinit(allocator);
                slot.* = null;
            }
        }
        self.next_handle = 1;
    }

    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        self.clear(allocator);
    }
};

fn appendU32(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    const x: u32 = v;
    try buf.appendSlice(allocator, std.mem.asBytes(&x));
}

fn appendU64(buf: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u64) !void {
    const x: u64 = v;
    try buf.appendSlice(allocator, std.mem.asBytes(&x));
}

fn readU32(bytes: []const u8, cursor: *usize) !u32 {
    const w = @sizeOf(u32);
    if (cursor.* + w > bytes.len) return error.Truncated;
    const v = std.mem.bytesToValue(u32, bytes[cursor.*..][0..w]);
    cursor.* += w;
    return v;
}

fn readU64(bytes: []const u8, cursor: *usize) !u64 {
    const w = @sizeOf(u64);
    if (cursor.* + w > bytes.len) return error.Truncated;
    const v = std.mem.bytesToValue(u64, bytes[cursor.*..][0..w]);
    cursor.* += w;
    return v;
}

pub fn serialize(io: std.Io, allocator: std.mem.Allocator, store: *const Store, mk: ?keystore.MasterKey) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try appendU32(&buf, allocator, config.object_record_magic);
    try appendU32(&buf, allocator, config.object_record_version);

    var n: u32 = 0;
    for (store.slots) |slot| {
        if (slot) |e| {
            if (e.obj.isToken()) n += 1;
        }
    }
    try appendU32(&buf, allocator, n);

    for (store.slots) |slot| {
        if (slot) |e| {
            if (!e.obj.isToken()) continue;
            try appendU32(&buf, allocator, @intCast(e.obj.attrs.items.len));
            for (e.obj.attrs.items) |a| {
                try appendU64(&buf, allocator, @intCast(a.type));
                if (!a.sealed and e.obj.shouldSeal(a.type)) {
                    const key = mk orelse return error.NoMasterKey;
                    const scratch = try allocator.alloc(u8, keystore.sealedLen(a.value.len));
                    defer allocator.free(scratch);
                    const wrote = try keystore.seal(io, &key, std.mem.asBytes(&a.type), a.value, scratch);
                    try appendU64(&buf, allocator, @intCast(wrote));
                    try buf.appendSlice(allocator, scratch[0..wrote]);
                } else {
                    try appendU64(&buf, allocator, @intCast(a.value.len));
                    try buf.appendSlice(allocator, a.value);
                }
            }
        }
    }

    return buf.toOwnedSlice(allocator);
}

fn parse(allocator: std.mem.Allocator, store: *Store, bytes: []const u8) !void {
    var c: usize = 0;
    const magic = try readU32(bytes, &c);
    const version = try readU32(bytes, &c);
    if (magic != config.object_record_magic or version != config.object_record_version) return error.BadHeader;

    const obj_count = try readU32(bytes, &c);
    var i: u32 = 0;
    while (i < obj_count) : (i += 1) {
        var obj: Object = .{};
        var inserted = false;
        defer if (!inserted) obj.deinit(allocator);

        const attr_count = try readU32(bytes, &c);
        if (attr_count > config.max_attributes_per_object) return error.TooManyAttributes;

        var j: u32 = 0;
        while (j < attr_count) : (j += 1) {
            const t = try readU64(bytes, &c);
            const len = try readU64(bytes, &c);
            if (len > config.max_attr_value_len) return error.AttrTooLarge;
            const n: usize = @intCast(len);
            if (c + n > bytes.len) return error.Truncated;
            try obj.set(allocator, @intCast(t), bytes[c .. c + n]);
            c += n;
        }

        for (obj.attrs.items) |*a| {
            if (obj.shouldSeal(a.type)) a.sealed = true;
        }

        if (store.insert(obj) == null) return error.StoreFull;
        inserted = true;
    }
}

pub fn save(io: std.Io, allocator: std.mem.Allocator, store: *const Store, mk: ?keystore.MasterKey) !void {
    const data = try serialize(io, allocator, store, mk);
    defer allocator.free(data);

    var buf: [config.path_buf_len]u8 = undefined;
    const path = try env.resolvePath(&buf, config.object_path_env, config.object_path_default);

    var tmp_buf: [config.path_buf_len + 8]u8 = undefined;
    const tmp = try std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path});
    const dir = std.Io.Dir.cwd();
    try dir.writeFile(io, .{ .sub_path = tmp, .data = data });
    try dir.rename(tmp, dir, path, io);
}

pub fn unlock(allocator: std.mem.Allocator, store: *Store, mk: keystore.MasterKey) !void {
    for (&store.slots) |*slot| {
        if (slot.*) |*e| {
            if (!e.obj.isToken()) continue;
            for (e.obj.attrs.items) |*a| {
                if (!a.sealed) continue;
                if (a.value.len < keystore.seal_overhead) return error.Corrupt;
                const plain = try allocator.alloc(u8, a.value.len - keystore.seal_overhead);
                _ = keystore.unseal(&mk, std.mem.asBytes(&a.type), a.value, plain) catch {
                    secureFree(allocator, plain);
                    return error.AuthFailed;
                };
                secureFree(allocator, a.value);
                a.value = plain;
                a.sealed = false;
            }
        }
    }
}

pub fn lock(io: std.Io, allocator: std.mem.Allocator, store: *Store, mk: keystore.MasterKey) !void {
    for (&store.slots) |*slot| {
        if (slot.*) |*e| {
            if (!e.obj.isToken()) continue;
            for (e.obj.attrs.items) |*a| {
                if (a.sealed or !e.obj.shouldSeal(a.type)) continue;
                const sealed = try allocator.alloc(u8, keystore.sealedLen(a.value.len));
                _ = keystore.seal(io, &mk, std.mem.asBytes(&a.type), a.value, sealed) catch {
                    secureFree(allocator, sealed);
                    return error.Seal;
                };
                secureFree(allocator, a.value);
                a.value = sealed;
                a.sealed = true;
            }
        }
    }
}

pub fn scrubUnsealed(store: *Store) void {
    for (&store.slots) |*slot| {
        if (slot.*) |*e| {
            if (!e.obj.isToken()) continue;
            for (e.obj.attrs.items) |*a| {
                if (a.sealed or !e.obj.shouldSeal(a.type)) continue;
                std.crypto.secureZero(u8, a.value);
                a.sealed = true;
            }
        }
    }
}

pub fn load(io: std.Io, allocator: std.mem.Allocator, store: *Store) void {
    var buf: [config.path_buf_len]u8 = undefined;
    const path = env.resolvePath(&buf, config.object_path_env, config.object_path_default) catch return;
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(config.object_read_limit)) catch return;
    defer allocator.free(bytes);
    parse(allocator, store, bytes) catch store.clear(allocator);
}

test "set replaces an existing attribute and reports size" {
    const a = std.testing.allocator;
    var obj: Object = .{};
    defer obj.deinit(a);

    try obj.set(a, ck.CKA_LABEL, "first");
    try obj.set(a, ck.CKA_LABEL, "second-value");
    try std.testing.expectEqual(@as(usize, 1), obj.attrs.items.len);
    try std.testing.expectEqualSlices(u8, "second-value", obj.get(ck.CKA_LABEL).?);
    try std.testing.expectEqual(@as(ck.CK_ULONG, "second-value".len), obj.sizeBytes());
}

test "set on an existing attribute clears a stale sealed flag" {
    const a = std.testing.allocator;
    var obj: Object = .{};
    defer obj.deinit(a);

    try obj.set(a, ck.CKA_VALUE, "ciphertext-placeholder");
    obj.findPtr(ck.CKA_VALUE).?.sealed = true;
    try obj.set(a, ck.CKA_VALUE, "fresh-plaintext");
    try std.testing.expect(!obj.findPtr(ck.CKA_VALUE).?.sealed);
    try std.testing.expectEqualSlices(u8, "fresh-plaintext", obj.get(ck.CKA_VALUE).?);
}

test "bool and class helpers read CK_BBOOL semantics" {
    const a = std.testing.allocator;
    var obj: Object = .{};
    defer obj.deinit(a);

    try std.testing.expect(!obj.isToken());
    try obj.set(a, ck.CKA_TOKEN, &[_]u8{ck.CK_TRUE});
    try obj.set(a, ck.CKA_PRIVATE, &[_]u8{ck.CK_FALSE});
    try std.testing.expect(obj.isToken());
    try std.testing.expect(!obj.isPrivate());
}

test "store hands out monotonic non-reused handles and destroys" {
    const a = std.testing.allocator;
    var store: Store = .{};
    defer store.deinit(a);

    var o1: Object = .{};
    try o1.set(a, ck.CKA_CLASS, &[_]u8{0});
    const h1 = store.insert(o1).?;

    var o2: Object = .{};
    try o2.set(a, ck.CKA_CLASS, &[_]u8{1});
    const h2 = store.insert(o2).?;

    try std.testing.expect(h1 != h2);
    try std.testing.expect(store.getPtr(h1) != null);
    try std.testing.expect(store.destroy(a, h1));
    try std.testing.expect(store.getPtr(h1) == null);
    try std.testing.expect(!store.destroy(a, h1));

    var o3: Object = .{};
    try o3.set(a, ck.CKA_CLASS, &[_]u8{2});
    const h3 = store.insert(o3).?;
    try std.testing.expect(h3 != h1 and h3 != h2);
    try std.testing.expectEqual(@as(usize, 2), store.count());
}

test "serialize then parse round-trips only token objects" {
    const a = std.testing.allocator;
    var store: Store = .{};
    defer store.deinit(a);

    var tok: Object = .{};
    try tok.set(a, ck.CKA_TOKEN, &[_]u8{ck.CK_TRUE});
    try tok.set(a, ck.CKA_CLASS, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 });
    try tok.set(a, ck.CKA_LABEL, "persisted");
    _ = store.insert(tok);

    var sess: Object = .{};
    try sess.set(a, ck.CKA_TOKEN, &[_]u8{ck.CK_FALSE});
    try sess.set(a, ck.CKA_LABEL, "ephemeral");
    _ = store.insert(sess);

    const data = try serialize(std.testing.io, a, &store, null);
    defer a.free(data);

    var restored: Store = .{};
    defer restored.deinit(a);
    try parse(a, &restored, data);

    try std.testing.expectEqual(@as(usize, 1), restored.count());
    var found_label: ?[]const u8 = null;
    for (&restored.slots) |*slot| {
        if (slot.*) |*e| found_label = e.obj.get(ck.CKA_LABEL);
    }
    try std.testing.expectEqualSlices(u8, "persisted", found_label.?);
}

test "serialize seals a sensitive value at rest and unlock recovers it" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const mk: keystore.MasterKey = @splat(0x5a);
    const wrong: keystore.MasterKey = @splat(0x17);
    const secret = "SUPER-SECRET-KEY-MATERIAL";

    var store: Store = .{};
    defer store.deinit(a);
    var key: Object = .{};
    try key.set(a, ck.CKA_TOKEN, &[_]u8{ck.CK_TRUE});
    try key.set(a, ck.CKA_CLASS, &[_]u8{ 4, 0, 0, 0, 0, 0, 0, 0 });
    try key.set(a, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE});
    try key.set(a, ck.CKA_VALUE, secret);
    _ = store.insert(key);

    const data = try serialize(io, a, &store, mk);
    defer a.free(data);
    try std.testing.expect(std.mem.indexOf(u8, data, secret) == null);

    var restored: Store = .{};
    defer restored.deinit(a);
    try parse(a, &restored, data);

    var sealed_value: ?[]const u8 = null;
    for (&restored.slots) |*slot| {
        if (slot.*) |*e| {
            if (e.obj.findPtr(ck.CKA_VALUE)) |attr| {
                try std.testing.expect(attr.sealed);
                sealed_value = attr.value;
            }
        }
    }
    try std.testing.expect(sealed_value != null);
    try std.testing.expect(std.mem.indexOf(u8, sealed_value.?, secret) == null);

    try std.testing.expectError(error.AuthFailed, unlock(a, &restored, wrong));
    try unlock(a, &restored, mk);
    for (&restored.slots) |*slot| {
        if (slot.*) |*e| {
            const v = e.obj.get(ck.CKA_VALUE).?;
            try std.testing.expectEqualSlices(u8, secret, v);
            try std.testing.expect(!e.obj.findPtr(ck.CKA_VALUE).?.sealed);
        }
    }
}

test "secureFree clears the secret from the value buffer" {
    var backing: [64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const a = fba.allocator();
    const v = try a.dupe(u8, "SUPER-SECRET-KEY");
    const region = backing[0..v.len];
    try std.testing.expect(std.mem.indexOf(u8, region, "SECRET") != null);
    secureFree(a, v);
    try std.testing.expect(std.mem.indexOf(u8, region, "SECRET") == null);
}

test "deinit clears a plaintext secret attribute from its buffer" {
    var backing: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    const a = fba.allocator();
    var obj: Object = .{};
    try obj.set(a, ck.CKA_VALUE, "AES-256-SECRET-KEY-BYTES");
    const stored = obj.findPtr(ck.CKA_VALUE).?.value;
    const region = stored[0..stored.len];
    try std.testing.expect(std.mem.indexOf(u8, region, "SECRET") != null);
    obj.deinit(a);
    try std.testing.expect(std.mem.indexOf(u8, region, "SECRET") == null);
}

test "parse rejects a bad magic without leaking" {
    const a = std.testing.allocator;
    var store: Store = .{};
    defer store.deinit(a);
    const junk = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    try std.testing.expectError(error.BadHeader, parse(a, &store, &junk));
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "parse fails safe on a truncated record and clear frees partial inserts" {
    const a = std.testing.allocator;
    var store: Store = .{};
    defer store.deinit(a);

    var good: Store = .{};
    defer good.deinit(a);
    var tok: Object = .{};
    try tok.set(a, ck.CKA_TOKEN, &[_]u8{ck.CK_TRUE});
    try tok.set(a, ck.CKA_LABEL, "x");
    _ = good.insert(tok);
    const data = try serialize(std.testing.io, a, &good, null);
    defer a.free(data);

    try std.testing.expectError(error.Truncated, parse(a, &store, data[0 .. data.len - 1]));
    store.clear(a);
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "scrubUnsealed fail-closes plaintext secrets after a failed re-seal" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const secret = "PLAINTEXT-KEY-MUST-NOT-SURVIVE-LOGOUT";

    var store: Store = .{};
    defer store.deinit(a);
    var key: Object = .{};
    try key.set(a, ck.CKA_TOKEN, &[_]u8{ck.CK_TRUE});
    try key.set(a, ck.CKA_SENSITIVE, &[_]u8{ck.CK_TRUE});
    try key.set(a, ck.CKA_VALUE, secret);
    _ = store.insert(key);

    const mk: keystore.MasterKey = @splat(0x42);
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, lock(io, failing.allocator(), &store, mk));

    const attr = store.slots[0].?.obj.findPtr(ck.CKA_VALUE).?;
    try std.testing.expect(!attr.sealed);
    try std.testing.expect(std.mem.indexOf(u8, attr.value, "SURVIVE") != null);

    scrubUnsealed(&store);

    try std.testing.expect(attr.sealed);
    try std.testing.expect(std.mem.indexOf(u8, attr.value, "SURVIVE") == null);
    for (attr.value) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
