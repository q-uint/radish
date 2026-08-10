const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zg = b.dependency("zg", .{ .target = target, .optimize = optimize });
    const normalize = zg.module("Normalize");

    const gitpack = gitpackModule(b, target, optimize);

    const mod = b.addModule("radish", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zg_normalize", .module = normalize },
            .{ .name = "gitpack", .module = gitpack },
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

/// The toolchain's own git implementation (compiler internal, std only),
/// imported from the pinned Zig's lib dir so it tracks the Zig we build with.
/// The path can move between versions; then this fails loudly.
fn gitpackModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Module {
    // zig_exe is <prefix>/bin/zig; the lib dir is <prefix>/lib.
    const bin_dir = std.fs.path.dirname(b.graph.zig_exe) orelse ".";
    const prefix = std.fs.path.dirname(bin_dir) orelse ".";
    const default = b.pathJoin(&.{ prefix, "lib", "compiler", "Maker", "Fetch", "git.zig" });
    // The pinned fork's copy, when the flake supplies one: stock git.zig has no
    // IndexPackOptions, so indexPack's checksums cannot be requested from it.
    const git_path = b.option([]const u8, "gitpack", "Path to git.zig") orelse
        b.graph.environ_map.get("RADISH_GITPACK") orelse default;
    return b.createModule(.{
        .root_source_file = .{ .cwd_relative = git_path },
        .target = target,
        .optimize = optimize,
    });
}
