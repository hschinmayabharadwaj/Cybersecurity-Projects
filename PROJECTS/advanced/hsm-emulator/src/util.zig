// ©AngelaMos | 2026
// util.zig

pub fn padded(comptime n: usize, comptime s: []const u8) [n]u8 {
    if (s.len > n) @compileError("padded: source string longer than field width");
    var out: [n]u8 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out[i] = if (i < s.len) s[i] else ' ';
    }
    return out;
}
