const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zg = b.dependency("zg", .{ .target = target, .optimize = optimize });
    const normalize = zg.module("Normalize");

    const git2 = git2Module(b, target, optimize);

    const mod = b.addModule("radish", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zg_normalize", .module = normalize },
            .{ .name = "git2", .module = git2 },
        },
    });

    const exe = b.addExecutable(.{
        .name = "radish",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "radish", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}

/// Translate-c bindings for the system libgit2, linked as a `git2` module.
/// Paths come from the flake (LIBGIT2_INCLUDE / LIBGIT2_LIB).
fn git2Module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    // With Nix, the flake provides exact paths. Otherwise fall back to system
    // discovery: a header on the default include path and linkSystemLibrary.
    const include = b.graph.environ_map.get("LIBGIT2_INCLUDE");
    const header: std.Build.LazyPath = if (include) |inc|
        .{ .cwd_relative = b.pathJoin(&.{ inc, "git2.h" }) }
    else
        .{ .cwd_relative = "git2.h" };

    const tc = b.addTranslateC(.{
        .root_source_file = header,
        .target = target,
        .optimize = optimize,
    });
    if (include) |inc| tc.addIncludePath(.{ .cwd_relative = inc });

    const mod = tc.createModule();
    if (b.graph.environ_map.get("LIBGIT2_LIB")) |libdir| {
        mod.addLibraryPath(.{ .cwd_relative = libdir });
    }
    mod.linkSystemLibrary("git2", .{});
    mod.link_libc = true;
    return mod;
}
