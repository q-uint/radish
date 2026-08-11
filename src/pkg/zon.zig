//! Shared AST helpers for reading a build.zig.zon.
//!
//! Dependency names are arbitrary, so the typed `std.zon.parse` cannot be used:
//! it maps fields to struct names known at comptime and ZON has no dynamic-key
//! map type. Both the reader and the rewriter therefore walk the AST, the same
//! way Zig's own manifest parser does.

const std = @import("std");

pub const Ast = std.zig.Ast;
pub const Node = Ast.Node.Index;
pub const StructInit = Ast.full.StructInit;

/// Room for the two nodes `fullStructInit` may need to borrow.
pub const Buf = [2]Node;

pub const Error = error{BadManifest};

pub fn parse(gpa: std.mem.Allocator, source: [:0]const u8) !Ast {
    var ast = try Ast.parse(gpa, source, .{ .mode = .zon });
    errdefer ast.deinit(gpa);
    if (ast.errors.len > 0) return error.BadManifest;
    return ast;
}

/// The manifest's top-level struct.
pub fn root(ast: Ast, buf: *Buf) !StructInit {
    return ast.fullStructInit(buf, ast.nodeData(.root).node) orelse error.BadManifest;
}

/// The `.dependencies` struct, or null when the manifest has none.
pub fn dependencies(ast: Ast, root_init: StructInit, buf: *Buf) !?StructInit {
    const node = findField(ast, root_init, "dependencies") orelse return null;
    return ast.fullStructInit(buf, node) orelse error.BadManifest;
}

/// The node a named field is initialized to, or null when absent.
pub fn findField(ast: Ast, init: StructInit, want: []const u8) ?Node {
    for (init.ast.fields) |field| {
        if (std.mem.eql(u8, nameOf(ast, field), want)) return field;
    }
    return null;
}

/// The `.name` a field node is bound to, without the leading dot. The name
/// token sits two before the value: `.name` `=` `value`.
pub fn nameOf(ast: Ast, node: Node) []const u8 {
    return ast.tokenSlice(ast.firstToken(node) - 2);
}

/// The value of a string-literal node, with quotes stripped. Borrows `ast`.
pub fn stringValue(ast: Ast, node: Node) ![]const u8 {
    const raw = ast.tokenSlice(ast.nodeMainToken(node));
    if (raw.len < 2 or raw[0] != '"') return error.BadManifest;
    return raw[1 .. raw.len - 1];
}

/// One past the last byte of a token.
pub fn tokenEnd(ast: Ast, tok: Ast.TokenIndex) usize {
    return ast.tokenStart(tok) + ast.tokenSlice(tok).len;
}
