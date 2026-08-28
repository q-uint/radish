//! The TLS 1.3 key schedule (RFC 8446 s7.1).
//!
//! QUIC drives this with handshake messages carried in CRYPTO frames instead
//! of TLS records, but the schedule itself is unchanged. Each traffic secret
//! it produces feeds `crypto.keysFromSecret` to become packet protection keys.
const std = @import("std");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const expandLabel = std.crypto.tls.hkdfExpandLabel;

pub const secret_len = Hkdf.prk_length;
pub const Secret = [secret_len]u8;
pub const Transcript = [Sha256.digest_length]u8;

const zeros: Secret = @splat(0);

/// Transcript hash of no messages, used where the schedule takes no context.
pub fn emptyTranscript() Transcript {
    return std.crypto.tls.emptyHash(Sha256);
}

/// Derive-Secret: HKDF-Expand-Label with a transcript hash as the context.
/// Source: RFC 8446 s7.1.
pub fn deriveSecret(secret: Secret, comptime label: []const u8, transcript: Transcript) Secret {
    return expandLabel(Hkdf, secret, label, &transcript, secret_len);
}

/// Root of the schedule. Without a pre-shared key both inputs are zero.
pub fn earlySecret() Secret {
    return Hkdf.extract(&zeros, &zeros);
}

/// Mixes the (EC)DHE shared secret in. `shared` is the raw x25519 output.
pub fn handshakeSecret(early: Secret, shared: []const u8) Secret {
    return Hkdf.extract(&deriveSecret(early, "derived", emptyTranscript()), shared);
}

/// The last extract, taking no new keying material.
pub fn masterSecret(handshake: Secret) Secret {
    return Hkdf.extract(&deriveSecret(handshake, "derived", emptyTranscript()), &zeros);
}

/// Both directions' handshake traffic secrets. `transcript` covers
/// ClientHello through ServerHello.
pub fn handshakeTraffic(handshake: Secret, transcript: Transcript) Directions {
    return .{
        .client = deriveSecret(handshake, "c hs traffic", transcript),
        .server = deriveSecret(handshake, "s hs traffic", transcript),
    };
}

/// Both directions' application traffic secrets. `transcript` covers
/// ClientHello through the server's Finished.
pub fn applicationTraffic(master: Secret, transcript: Transcript) Directions {
    return .{
        .client = deriveSecret(master, "c ap traffic", transcript),
        .server = deriveSecret(master, "s ap traffic", transcript),
    };
}

pub const Directions = struct {
    client: Secret,
    server: Secret,
};

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// The key that authenticates a Finished, from one direction's traffic secret.
/// Source: RFC 8446 s4.4.4.
pub fn finishedKey(secret: Secret) Secret {
    return expandLabel(Hkdf, secret, "finished", "", secret_len);
}

/// verify_data: an HMAC over the transcript as it stood *before* the Finished
/// being checked.
/// Source: RFC 8446 s4.4.4.
pub fn verifyData(secret: Secret, transcript: Transcript) [Hmac.mac_length]u8 {
    return std.crypto.tls.hmac(Hmac, &transcript, finishedKey(secret));
}

const X25519 = std.crypto.dh.X25519;

pub const PublicKey = [X25519.public_length]u8;
pub const SecretKey = [X25519.secret_length]u8;

/// The (EC)DHE input to `handshakeSecret`: raw X25519, no hashing.
/// Source: RFC 8446 s7.4.2.
pub fn x25519(secret: SecretKey, peer_public: PublicKey) !Secret {
    return X25519.scalarmult(secret, peer_public);
}

const testing = std.testing;
const testdata = @import("testdata.zig");
const messages = @import("handshake.zig");
const hex = testdata.hex;

// RFC 8448 s3 walks a full handshake and prints every intermediate secret.
test "RFC 8448 key schedule" {
    const early = earlySecret();
    try testing.expectEqualSlices(
        u8,
        &hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
        &early,
    );

    const shared = try x25519(
        hex("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005"),
        hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f"),
    );
    try testing.expectEqualSlices(
        u8,
        &hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"),
        &shared,
    );

    const handshake = handshakeSecret(early, &shared);
    try testing.expectEqualSlices(
        u8,
        &hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"),
        &handshake,
    );

    // Hashed from the trace's own Hello messages rather than pasted in, so a
    // change to either side has to stay consistent with the other.
    var ch: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ch, testdata.rfc8448_client_hello_hex);
    var sh: [90]u8 = undefined;
    _ = try std.fmt.hexToBytes(&sh, testdata.rfc8448_server_hello_hex);
    var t: messages.Transcript = .{};
    t.update(&ch);
    t.update(&sh);

    const hs = handshakeTraffic(handshake, t.hash());
    try testing.expectEqualSlices(u8, &hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &hs.client);
    try testing.expectEqualSlices(u8, &hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &hs.server);

    const master = masterSecret(handshake);
    try testing.expectEqualSlices(
        u8,
        &hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"),
        &master,
    );

    const finished_transcript = hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    const ap = applicationTraffic(master, finished_transcript);
    try testing.expectEqualSlices(u8, &hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), &ap.client);
    try testing.expectEqualSlices(u8, &hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), &ap.server);
}
