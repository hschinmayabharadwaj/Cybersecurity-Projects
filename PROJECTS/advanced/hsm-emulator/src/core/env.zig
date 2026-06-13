// ©AngelaMos | 2026
// env.zig

const std = @import("std");

pub fn get(key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (std.c.environ[i]) |entry| : (i += 1) {
        const s = std.mem.sliceTo(entry, 0);
        if (s.len > key.len and s[key.len] == '=' and std.mem.eql(u8, s[0..key.len], key)) {
            return s[key.len + 1 ..];
        }
    }
    return null;
}

pub fn resolvePath(buf: []u8, env_key: []const u8, default_rel: []const u8) ![]const u8 {
    if (get(env_key)) |p| {
        if (p.len > 0) return p;
    }
    const home = get("HOME") orelse return error.NoHomeDir;
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ home, default_rel });
}
