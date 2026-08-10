//! Turning a `host:port` into a connected TCP stream.
//!
//! `IpAddress.resolve` handles only literals (v4, v6, and v6 scopes), so a
//! hostname has to go through `HostName.lookup`, which is DNS. Radicle node
//! addresses are routinely hostnames, so every dial path needs this.
const std = @import("std");

pub const Error = error{NoAddressReturned};

/// Resolves `host` - an IPv4/IPv6 literal or a DNS name - to an address.
/// Literals are tried first so no lookup happens when one is given.
pub fn resolve(io: std.Io, host: []const u8, port: u16) !std.Io.net.IpAddress {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| return addr else |_| {}

    const name = try std.Io.net.HostName.init(host);
    var buf: [16]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&buf);
    try name.lookup(io, &queue, .{ .port = port });

    // lookup pushes any number of addresses plus exactly one canonical name,
    // then closes the queue; getOne reports Closed once it is drained.
    while (queue.getOne(io)) |result| switch (result) {
        .address => |addr| return addr,
        .canonical_name => {},
    } else |_| {}
    return error.NoAddressReturned;
}

/// Resolves `host` and opens a TCP connection to it.
pub fn connect(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    var addr = try resolve(io, host, port);
    return addr.connect(io, .{ .mode = .stream });
}

const testing = std.testing;

test "resolves IPv4 literals without a lookup" {
    const addr = try resolve(testing.io, "127.0.0.1", 8776);
    try testing.expectEqual(@as(u16, 8776), addr.getPort());
    var buf: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{f}", .{addr});
    try testing.expect(std.mem.startsWith(u8, text, "127.0.0.1"));
}

test "resolves IPv6 literals" {
    const addr = try resolve(testing.io, "::1", 8776);
    try testing.expectEqual(@as(u16, 8776), addr.getPort());
}

test "rejects a name that is not a valid hostname" {
    try testing.expectError(error.InvalidHostName, resolve(testing.io, "not a host", 8776));
}
