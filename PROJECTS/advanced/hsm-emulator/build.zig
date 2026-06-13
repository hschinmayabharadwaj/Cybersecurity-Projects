// ©AngelaMos | 2026
// build.zig

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const lib = b.addLibrary(.{
        .name = "hsm",
        .linkage = .dynamic,
        .version = .{ .major = 0, .minor = 1, .patch = 0 },
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .sanitize_c = .trap,
        }),
    });
    lib.root_module.linkSystemLibrary("crypto", .{});
    lib.setVersionScript(b.path("pkcs11.map"));
    b.installArtifact(lib);

    const ck_module = b.createModule(.{
        .root_source_file = b.path("src/ck.zig"),
        .target = target,
        .optimize = optimize,
    });

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("vendor/pkcs11/shim.h"),
        .target = target,
        .optimize = optimize,
    });
    translate_c.addIncludePath(b.path("vendor/pkcs11"));
    const p11c_module = translate_c.createModule();

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/abi_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ck", .module = ck_module },
                .{ .name = "p11c", .module = p11c_module },
            },
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run ABI and unit tests");
    test_step.dependOn(&run_tests.step);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test_all.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    unit_tests.root_module.linkSystemLibrary("crypto", .{});
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    const smoke = b.addExecutable(.{
        .name = "smoke",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/smoke.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "ck", .module = ck_module },
            },
        }),
    });
    const run_smoke = b.addRunArtifact(smoke);
    run_smoke.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_smoke.addArgs(args);
    const smoke_step = b.step("smoke", "Load the built .so via dlopen and exercise the Cryptoki ABI");
    smoke_step.dependOn(&run_smoke.step);
}
