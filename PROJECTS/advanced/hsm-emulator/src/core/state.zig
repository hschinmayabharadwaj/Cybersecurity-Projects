// ©AngelaMos | 2026
// state.zig

const std = @import("std");
const builtin = @import("builtin");
const ck = @import("../ck.zig");
const lock = @import("lock.zig");
const token = @import("token.zig");
const session = @import("session.zig");
const object_store = @import("object_store.zig");
const keystore = @import("../crypto/keystore.zig");

pub const Locking = enum { none, os };

pub const Instance = struct {
    debug_alloc: std.heap.DebugAllocator(.{}) = undefined,
    threaded: std.Io.Threaded = undefined,
    locking: Locking = .none,
    token: token.Token = .{},
    sessions: session.Table = .{},
    objects: object_store.Store = .{},
    logged_in: ?ck.CK_USER_TYPE = null,
    mk: ?keystore.MasterKey = null,

    pub fn allocator(self: *Instance) std.mem.Allocator {
        return if (builtin.mode == .Debug) self.debug_alloc.allocator() else std.heap.smp_allocator;
    }

    pub fn io(self: *Instance) std.Io {
        return self.threaded.io();
    }

    pub fn wipeMasterKey(self: *Instance) void {
        if (self.mk) |*mk| std.crypto.secureZero(u8, mk);
        self.mk = null;
    }

    pub fn relock(self: *Instance) void {
        if (self.mk) |*mk| object_store.lock(self.io(), self.allocator(), &self.objects, mk.*) catch {
            object_store.scrubUnsealed(&self.objects);
        };
        self.wipeMasterKey();
    }
};

pub var mutex: lock.Lock = .{};
var storage: Instance = undefined;
var present: bool = false;
var inflight: usize = 0;
var generation: u64 = 0;

pub fn acquire() ?*Instance {
    mutex.lock();
    if (!@atomicLoad(bool, &present, .acquire)) {
        mutex.unlock();
        return null;
    }
    return &storage;
}

pub fn isInitialized() bool {
    return @atomicLoad(bool, &present, .acquire);
}

pub fn initialize(locking: Locking) void {
    storage = .{
        .debug_alloc = .init,
        .threaded = .init(std.heap.smp_allocator, .{}),
        .locking = locking,
    };
    storage.token = token.load(storage.io(), storage.allocator());
    object_store.load(storage.io(), storage.allocator(), &storage.objects);
    @atomicStore(bool, &present, true, .release);
}

pub fn finalize() ck.CK_RV {
    mutex.lock();
    if (!@atomicLoad(bool, &present, .acquire)) {
        mutex.unlock();
        return ck.CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    @atomicStore(bool, &present, false, .release);
    mutex.unlock();

    while (true) {
        mutex.lock();
        const pending = inflight;
        mutex.unlock();
        if (pending == 0) break;
        std.Thread.yield() catch std.atomic.spinLoopHint();
    }

    mutex.lock();
    defer mutex.unlock();
    storage.sessions.wipeAll(storage.allocator());
    storage.wipeMasterKey();
    storage.objects.deinit(storage.allocator());
    storage.threaded.deinit();
    const leak = storage.debug_alloc.deinit();
    if (builtin.mode == .Debug and leak == .leak) @panic("hsm: allocator leak detected at C_Finalize");
    return ck.CKR_OK;
}

pub fn cryptoBegin() u64 {
    inflight += 1;
    return generation;
}

pub fn cryptoEnd() void {
    inflight -= 1;
}

pub fn cryptoAbort() void {
    mutex.lock();
    inflight -= 1;
    mutex.unlock();
}

pub fn bumpGeneration() void {
    generation += 1;
}

pub fn currentGeneration() u64 {
    return generation;
}

pub const InitOutcome = union(enum) {
    ok: Locking,
    err: ck.CK_RV,
};

pub fn parseInitArgs(p: ?*anyopaque) InitOutcome {
    if (p == null) return .{ .ok = .none };
    const args: *ck.CK_C_INITIALIZE_ARGS = @ptrCast(@alignCast(p.?));
    if (args.pReserved != null) return .{ .err = ck.CKR_ARGUMENTS_BAD };
    var cbs: u8 = 0;
    if (args.CreateMutex != null) cbs += 1;
    if (args.DestroyMutex != null) cbs += 1;
    if (args.LockMutex != null) cbs += 1;
    if (args.UnlockMutex != null) cbs += 1;
    if (cbs != 0 and cbs != 4) return .{ .err = ck.CKR_ARGUMENTS_BAD };
    const os_locking_ok = (args.flags & ck.CKF_OS_LOCKING_OK) != 0;
    if (os_locking_ok) return .{ .ok = .os };
    if (cbs == 4) return .{ .err = ck.CKR_CANT_LOCK };
    return .{ .ok = .none };
}
