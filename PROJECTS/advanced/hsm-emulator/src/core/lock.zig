// ©AngelaMos | 2026
// lock.zig

const std = @import("std");

const spin_limit: usize = 64;

pub const Lock = struct {
    state: std.atomic.Mutex = .unlocked,

    pub fn lock(self: *Lock) void {
        var spins: usize = 0;
        while (!self.state.tryLock()) {
            if (spins < spin_limit) {
                spins += 1;
                std.atomic.spinLoopHint();
            } else {
                spins = 0;
                std.Thread.yield() catch std.atomic.spinLoopHint();
            }
        }
    }

    pub fn tryLock(self: *Lock) bool {
        return self.state.tryLock();
    }

    pub fn unlock(self: *Lock) void {
        self.state.unlock();
    }
};
