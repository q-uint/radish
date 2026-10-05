//! Test vectors for the iroh records.
//!
//! The record here was published to n0's staging pkarr relay and read back, so
//! it is one an implementation that is not ours accepted, signed and stored.
//! Everything else in `iroh/` checks its own work.
const std = @import("std");

/// Vectors read better as hex.
pub fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// The key that signs the published record. Public on purpose and worthless by
/// design: it identifies nothing, it is never a radicle node identity, and
/// anyone reading this can overwrite the record it publishes, which costs
/// nothing because the record points at documentation space.
///
/// Distinct from `quic/testdata.zig`'s seeds so a key can never be attributed
/// to the wrong thing.
pub const fixture_seed = "7070707070707070707070707070707070707070707070707070707070707070";

/// The one address the record carries: RFC 5737 TEST-NET-1, which routes
/// nowhere, so the record cannot point at anything real.
pub const fixture_addr = "addr=192.0.2.1:4433";

/// The relay it was published to. n0 documents this one as the less reliable
/// instance, which is what a test record belongs on.
pub const staging_relay = "https://staging-dns.iroh.link/pkarr";

/// The record as the relay served it back on 2026-09-28, reassembled with the
/// public key a relay leaves out because it is in the URL: 32 key, 64
/// signature, 8 timestamp, 102 of DNS packet.
///
/// The relay verified this before storing it and put it in the mainline DHT,
/// so an implementation that is not ours accepted our key encoding, our
/// bencode, our signature and our DNS packet. Everything downstream of that
/// can be checked offline, which is why this is here rather than in a test
/// that needs a network.
pub const fixture_record =
    "19204c8c3ba85ba059cd18ac9017bd02a18da5d10c68fb779a34be43ef067791" ++
    "c98c0ba0d5982e2e984ea416dca5f8305b8ca51bff9f829cb7558d1a5c0a3cad" ++
    "577bded1d3303ff8a8f0faf383866230a1ccae8b9af4b6e5bbf815a306267c0e" ++
    "00065c87315b1a5b" ++
    "000080000000000100000000055f69726f6834" ++
    "64726f72336462356962703479737170646e736a79663737796b6f61356a7174" ++
    "627477787337683467313972383561677136656f" ++
    "00001000010000001e001413616464723d3139322e302e322e313a34343333";

/// Microseconds since the epoch, which is 2026-09-28T08:52:58Z.
pub const fixture_timestamp: u64 = 1790585578658395;
