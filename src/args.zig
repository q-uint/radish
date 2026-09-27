//! Command-line parsing and help, both read off one struct per command.
//!
//! Fields are positionals in declaration order, and a default makes one
//! optional. A field named `flags` is not a positional: its own fields are the
//! `--spelled` options, each a `Flag` carrying its own help text.
const std = @import("std");

pub const Error = error{
    MissingArgument,
    UnexpectedArgument,
    UnknownFlag,
    BadValue,
};

/// Which argument an `Error` was about. Borrows comptime names and argv.
pub const Diagnostic = struct {
    what: []const u8 = "",
    got: []const u8 = "",

    /// The human sentence for `err`, with no trailing newline.
    pub fn report(self: Diagnostic, err: Error, w: *std.Io.Writer) !void {
        const is_flag = std.mem.startsWith(u8, self.what, FLAG_PREFIX);
        switch (err) {
            error.MissingArgument => if (is_flag) {
                try w.print("{s} needs a value", .{self.what});
            } else {
                try w.print("missing <{s}>", .{self.what});
            },
            error.BadValue => try w.print("'{s}' is not a valid {s}{s}{s}", .{
                self.got,
                if (is_flag) "" else "<",
                self.what,
                if (is_flag) " value" else ">",
            }),
            error.UnknownFlag => try w.print("unknown flag {s}", .{self.what}),
            error.UnexpectedArgument => try w.print("unexpected argument '{s}'", .{self.got}),
        }
    }
};

/// The field whose own fields are the options, rather than a positional.
const FLAGS = "flags";
const FLAG_PREFIX = "--";
/// Where descriptions start, and the longest one that still fits beside them
/// on a 100-column line.
const DESCRIPTION_COLUMN = 52;
const MAX_HELP = 48;

/// One argument and the text describing it, which `--help` prints and the
/// overview leaves out. An empty `text` means the name already says it.
pub fn Arg(comptime T: type, comptime text: []const u8) type {
    return struct {
        pub const Value = T;
        pub const help = text;
        value: T,
    };
}

/// A `--spelled` option, which is an `Arg` that lives inside `flags`.
pub const Flag = Arg;

/// Whether `T` is an `Arg`, which is the only thing a command may declare.
fn isArg(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => @hasDecl(T, "Value") and @hasDecl(T, "help"),
        else => false,
    };
}

fn isFlags(comptime name: []const u8) bool {
    return std.mem.eql(u8, name, FLAGS);
}

/// `require_verified` as it is written on the command line.
fn kebab(comptime name: []const u8) []const u8 {
    comptime var out: [name.len]u8 = undefined;
    inline for (name, 0..) |c, i| out[i] = if (c == '_') '-' else c;
    const frozen = out;
    return &frozen;
}

fn spelling(comptime name: []const u8) []const u8 {
    return FLAG_PREFIX ++ kebab(name);
}

/// What a flag's value looks like in the help. The field type is the only
/// thing known about it, so the placeholder says its shape, not its meaning.
fn placeholder(comptime T: type) []const u8 {
    const V = switch (@typeInfo(T)) {
        .optional => |o| o.child,
        else => T,
    };
    if (V == []const u8) return "text";
    return switch (@typeInfo(V)) {
        .int => "n",
        else => "value",
    };
}

/// How a default is written in the help, or "" when showing it would not help:
/// a bool is implied by its own absence, and a null means unset.
fn defaultText(comptime T: type, comptime value: T) []const u8 {
    if (T == []const u8) return value;
    return switch (@typeInfo(T)) {
        .bool => "",
        .optional => if (value) |v| defaultText(@typeInfo(T).optional.child, v) else "",
        .int => std.fmt.comptimePrint("{d}", .{value}),
        else => "",
    };
}

/// `=200`, or nothing when there is no default worth naming.
fn suffix(comptime text: []const u8) []const u8 {
    return if (text.len == 0) "" else "=" ++ text;
}

fn digits(comptime n: usize) []const u8 {
    return std.fmt.comptimePrint("{d}", .{n});
}

fn parseValue(comptime T: type, text: []const u8) Error!T {
    if (T == []const u8) return text;
    return switch (@typeInfo(T)) {
        .int => std.fmt.parseInt(T, text, 10) catch error.BadValue,
        .optional => |o| try parseValue(o.child, text),
        // A type that reads itself is checked here, so a malformed node id is
        // a usage error rather than a failure deep inside the command.
        .@"struct" => if (@hasDecl(T, "parse"))
            T.parse(text) catch error.BadValue
        else
            @compileError(@typeName(T) ++ " needs a `parse` to be an argument"),
        else => @compileError("unsupported argument type " ++ @typeName(T)),
    };
}

/// Optionals must come last, or an argument count cannot say which positional
/// was omitted and a required field would be left undefined. Descriptions are
/// capped so the help stays a table rather than a paragraph.
fn check(comptime Cmd: type) void {
    const info = @typeInfo(Cmd).@"struct";
    comptime var optional_seen: ?[]const u8 = null;
    inline for (info.field_names, info.field_types, info.field_attrs) |name, T, attrs| {
        if (comptime isFlags(name)) continue;
        if (!isArg(T)) {
            @compileError("field '" ++ name ++ "' must be an Arg(T, help), found " ++ @typeName(T));
        }
        if (attrs.default_value_ptr != null) {
            optional_seen = name;
        } else if (optional_seen) |prev| {
            @compileError("positional '" ++ name ++ "' is required but follows optional '" ++ prev ++ "'");
        }
    }

    if (@hasDecl(Cmd, "about") and Cmd.about.len > MAX_HELP) {
        @compileError("`about` is " ++ digits(Cmd.about.len) ++ " chars, over the " ++ digits(MAX_HELP) ++ " allowed: " ++ Cmd.about);
    }
    if (!@hasField(Cmd, FLAGS)) return;
    inline for (@typeInfo(@FieldType(Cmd, FLAGS)).@"struct".field_types) |F| {
        if (F.help.len > MAX_HELP) {
            @compileError("flag help is " ++ digits(F.help.len) ++ " chars, over the " ++ digits(MAX_HELP) ++ " allowed: " ++ F.help);
        }
    }
}

/// Fills `Cmd` from `argv`, which must already have the command name removed.
/// On error `diag` names the argument at fault.
pub fn parse(comptime Cmd: type, argv: []const []const u8, diag: *Diagnostic) Error!Cmd {
    comptime check(Cmd);
    const info = @typeInfo(Cmd).@"struct";
    var out: Cmd = undefined;

    comptime var required: usize = 0;
    inline for (info.field_names, info.field_types, info.field_attrs) |name, T, attrs| {
        if (attrs.defaultValue(T)) |d| {
            @field(out, name) = d;
        } else if (comptime !isFlags(name)) {
            required += 1;
        }
    }

    var pos: usize = 0;
    var i: usize = 0;
    while (i < argv.len) : (i += 1) {
        if (std.mem.startsWith(u8, argv[i], FLAG_PREFIX)) {
            i += try setFlag(Cmd, &out, argv[i], argv[i + 1 ..], diag);
            continue;
        }
        try setPositional(Cmd, &out, pos, argv[i], diag);
        pos += 1;
    }
    if (pos < required) {
        diag.* = .{ .what = positionalName(Cmd, pos) };
        return error.MissingArgument;
    }
    return out;
}

/// The `n`th positional's name, as the help spells it. Only ever asked for a
/// missing required one, and `check` puts those first, so `n` always exists.
fn positionalName(comptime Cmd: type, n: usize) []const u8 {
    comptime var index: usize = 0;
    inline for (@typeInfo(Cmd).@"struct".field_names) |name| {
        if (comptime !isFlags(name)) {
            if (index == n) return comptime kebab(name);
            index += 1;
        }
    }
    unreachable;
}

/// Assigns the `n`th positional. Past the last one it is an error, so a typo
/// is refused rather than dropped.
fn setPositional(comptime Cmd: type, out: *Cmd, n: usize, arg: []const u8, diag: *Diagnostic) Error!void {
    const info = @typeInfo(Cmd).@"struct";
    comptime var index: usize = 0;
    inline for (info.field_names, info.field_types) |name, T| {
        if (comptime !isFlags(name)) {
            if (index == n) {
                @field(out, name).value = parseValue(T.Value, arg) catch |e| {
                    diag.* = .{ .what = comptime kebab(name), .got = arg };
                    return e;
                };
                return;
            }
            index += 1;
        }
    }
    diag.* = .{ .got = arg };
    return error.UnexpectedArgument;
}

/// Assigns `--name`, and its value when the flag is not a bool. Returns how
/// many further argv entries it consumed.
fn setFlag(
    comptime Cmd: type,
    out: *Cmd,
    arg: []const u8,
    rest: []const []const u8,
    diag: *Diagnostic,
) Error!usize {
    if (@hasField(Cmd, FLAGS)) {
        const info = @typeInfo(@FieldType(Cmd, FLAGS)).@"struct";
        inline for (info.field_names, info.field_types) |name, F| {
            if (std.mem.eql(u8, arg, comptime spelling(name))) {
                if (F.Value == bool) {
                    @field(@field(out, FLAGS), name).value = true;
                    return 0;
                }
                if (rest.len == 0) {
                    diag.* = .{ .what = arg };
                    return error.MissingArgument;
                }
                @field(@field(out, FLAGS), name).value = parseValue(F.Value, rest[0]) catch |e| {
                    diag.* = .{ .what = arg, .got = rest[0] };
                    return e;
                };
                return 1;
            }
        }
    }
    diag.* = .{ .what = arg };
    return error.UnknownFlag;
}

/// One line: the command, its arguments, and what it does. This is the
/// overview, so nothing per-argument appears here.
pub fn usage(comptime Cmd: type, name: []const u8, w: *std.Io.Writer) !void {
    var buf: [DESCRIPTION_COLUMN * 2]u8 = undefined;
    var left = std.Io.Writer.fixed(&buf);
    try signature(Cmd, name, &left);
    try pad(w, left.buffered());
    if (@hasDecl(Cmd, "about")) try w.writeAll(Cmd.about);
    try w.writeByte('\n');
}

/// `  radish clone <host> <port> [dir=out]`, with no description.
fn signature(comptime Cmd: type, name: []const u8, w: *std.Io.Writer) !void {
    const info = @typeInfo(Cmd).@"struct";
    try w.print("  {s}", .{name});
    inline for (info.field_names, info.field_types, info.field_attrs) |f, T, attrs| {
        if (comptime !isFlags(f)) {
            if (comptime attrs.defaultValue(T)) |d| {
                try w.print(" [{s}{s}]", .{ comptime kebab(f), comptime suffix(defaultText(T.Value, d.value)) });
            } else {
                try w.print(" <{s}>", .{comptime kebab(f)});
            }
        }
    }
}

/// What `--help` prints: the command, then a line for every argument and flag
/// that carries text of its own.
pub fn help(comptime Cmd: type, name: []const u8, w: *std.Io.Writer) !void {
    if (@hasDecl(Cmd, "about")) try w.print("{s} - {s}\n\n", .{ name, Cmd.about });

    var buf: [DESCRIPTION_COLUMN * 2]u8 = undefined;
    var left = std.Io.Writer.fixed(&buf);
    try signature(Cmd, name, &left);
    try w.print("{s}\n", .{left.buffered()});

    const info = @typeInfo(Cmd).@"struct";
    inline for (info.field_names, info.field_types) |f, T| {
        if (comptime !isFlags(f) and T.help.len > 0) {
            try detail(w, "<" ++ comptime kebab(f) ++ ">", T.help);
        }
    }
    if (!@hasField(Cmd, FLAGS)) return;

    const flags = @typeInfo(@FieldType(Cmd, FLAGS)).@"struct";
    inline for (flags.field_names, flags.field_types, flags.field_attrs) |f, F, attrs| {
        const shown = comptime if (attrs.defaultValue(F)) |d| defaultText(F.Value, d.value) else "";
        const value = if (F.Value == bool) "" else " <" ++ comptime placeholder(F.Value) ++ suffix(shown) ++ ">";
        try detail(w, comptime spelling(f) ++ value, F.help);
    }
}

fn detail(w: *std.Io.Writer, comptime left: []const u8, text: []const u8) !void {
    var buf: [DESCRIPTION_COLUMN * 2]u8 = undefined;
    var line = std.Io.Writer.fixed(&buf);
    try line.print("    {s}", .{left});
    try pad(w, line.buffered());
    try w.print("{s}\n", .{text});
}

/// Writes `text`, then spaces up to the description column. A line already
/// past it gets two spaces, so a long name pushes its description rather than
/// running into it.
fn pad(w: *std.Io.Writer, text: []const u8) !void {
    try w.writeAll(text);
    if (text.len + 2 > DESCRIPTION_COLUMN) return w.writeAll("  ");
    try w.splatByteAll(' ', DESCRIPTION_COLUMN - text.len);
}

const testing = std.testing;

const Clone = struct {
    pub const about = "clone a repo into <dir>";

    host: Arg([]const u8, ""),
    port: Arg(u16, ""),
    rid: Arg([]const u8, "repository id, rad:z..."),
    dir: Arg([]const u8, "") = .{ .value = "out" },

    flags: struct {
        require_verified: Flag(bool, "exit non-zero on an unverified remote") = .{ .value = false },
        frames: Flag(usize, "gossip frames to observe") = .{ .value = 200 },
    } = .{},
};

test "positionals fill in declaration order, and a default stays unset" {
    var d: Diagnostic = .{};
    const got = try parse(Clone, &.{ "seed.example", "8776", "rad:z4VSy" }, &d);
    try testing.expectEqualStrings("seed.example", got.host.value);
    try testing.expectEqual(@as(u16, 8776), got.port.value);
    try testing.expectEqualStrings("rad:z4VSy", got.rid.value);
    try testing.expectEqualStrings("out", got.dir.value);
    try testing.expect(!got.flags.require_verified.value);
    try testing.expectEqual(@as(usize, 200), got.flags.frames.value);
}

test "an optional positional is taken when given" {
    var d: Diagnostic = .{};
    const got = try parse(Clone, &.{ "h", "1", "rid", "mydir" }, &d);
    try testing.expectEqualStrings("mydir", got.dir.value);
}

// A flag is named rather than placed, so its position must not matter.
test "a bool flag is set by presence, wherever it appears" {
    var d: Diagnostic = .{};
    const before = try parse(Clone, &.{ "--require-verified", "h", "1", "rid" }, &d);
    try testing.expect(before.flags.require_verified.value);
    const after = try parse(Clone, &.{ "h", "1", "rid", "--require-verified" }, &d);
    try testing.expect(after.flags.require_verified.value);
}

test "a valued flag consumes the argument after it" {
    var d: Diagnostic = .{};
    const got = try parse(Clone, &.{ "h", "1", "rid", "--frames", "50" }, &d);
    try testing.expectEqual(@as(usize, 50), got.flags.frames.value);
    try testing.expectEqualStrings("rid", got.rid.value);
}

/// The message `argv` produces, for asserting on what a user actually sees.
fn failure(argv: []const []const u8, buf: []u8) ![]const u8 {
    var d: Diagnostic = .{};
    const err = if (parse(Clone, argv, &d)) |_| return error.ParseSucceeded else |e| e;
    var w = std.Io.Writer.fixed(buf);
    try d.report(err, &w);
    return w.buffered();
}

// An error names the argument at fault: the enum alone leaves a user guessing
// which of five positionals was wrong.
test "each failure says which argument it was about" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("missing <rid>", try failure(&.{ "h", "1" }, &buf));
    try testing.expectEqualStrings("missing <port>", try failure(&.{"h"}, &buf));
    try testing.expectEqualStrings("unknown flag --nope", try failure(&.{ "h", "1", "r", "--nope" }, &buf));
    try testing.expectEqualStrings("--frames needs a value", try failure(&.{ "h", "1", "r", "--frames" }, &buf));
    try testing.expectEqualStrings(
        "'notanumber' is not a valid <port>",
        try failure(&.{ "h", "notanumber", "r" }, &buf),
    );
    try testing.expectEqualStrings(
        "'x' is not a valid --frames value",
        try failure(&.{ "h", "1", "r", "--frames", "x" }, &buf),
    );
    try testing.expectEqualStrings(
        "unexpected argument 'x'",
        try failure(&.{ "h", "1", "r", "d", "x" }, &buf),
    );
}

/// Everything `render` wrote, minus the trailing newline.
fn rendered(comptime f: anytype, buf: []u8) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try f(Clone, "radish clone", &w);
    return std.mem.trimEnd(u8, w.buffered(), "\n");
}

// The overview is one line per command: a default is shown where it helps, and
// nothing per-argument appears, or twenty commands would not fit on a screen.
test "usage is a single line, with defaults but no descriptions" {
    var buf: [512]u8 = undefined;
    const out = try rendered(usage, &buf);

    try testing.expect(std.mem.indexOfScalar(u8, out, '\n') == null);
    try testing.expect(std.mem.startsWith(u8, out, "  radish clone <host> <port> <rid> [dir=out]"));
    try testing.expect(std.mem.endsWith(u8, out, Clone.about));
    try testing.expect(std.mem.indexOf(u8, out, "--require-verified") == null);
    try testing.expect(std.mem.indexOf(u8, out, @FieldType(Clone, "rid").help) == null);
}

// The detail view is where per-argument text lives. An argument whose name
// already says it carries none, and prints no line at all.
test "help describes the arguments that carry text, and no others" {
    var buf: [1024]u8 = undefined;
    const out = try rendered(help, &buf);

    try testing.expect(std.mem.startsWith(u8, out, "radish clone - " ++ Clone.about));
    try testing.expect(std.mem.indexOf(u8, out, "<rid>") != null);
    try testing.expect(std.mem.indexOf(u8, out, @FieldType(Clone, "rid").help) != null);
    try testing.expect(std.mem.indexOf(u8, out, "--frames <n=200>") != null);
    // `host` and `port` describe themselves, so they get no detail line.
    try testing.expect(std.mem.indexOf(u8, out, "    <host>") == null);
    try testing.expect(std.mem.indexOf(u8, out, "    <port>") == null);
}

// Descriptions line up whatever the command is called, so the help reads as a
// table rather than as ragged sentences.
test "every description starts at the same column" {
    var buf: [1024]u8 = undefined;
    const out = try rendered(help, &buf);

    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "    ")) continue;
        const text = std.mem.lastIndexOf(u8, line, "  ").? + 2;
        try testing.expectEqual(@as(usize, DESCRIPTION_COLUMN), text);
    }
}
