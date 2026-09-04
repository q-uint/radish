//! Noise_XL_Edwards25519_ChaChaPoly_SHA256 handshake, as used by radicle-node.
//! (radicle names the pattern NOISE_XK, but cyphernet's Display yields "XL";
//! see PROTOCOL_NAME below.) Verified byte-for-byte against a live node.
//!
//! This matches cyphernet's `noise-framework` (Cyphernet-DAO/rust-cyphernet)
//! with radicle's `p2p-ed25519` feature, which diverges from the vanilla Noise
//! spec in ways that must be replicated:
//!   - the DH is over EDWARDS25519, not X25519: keys are raw Ed25519 public
//!     keys (compressed Edwards points) and the shared secret is
//!     `ge_scalarmult(clamp(SHA512(seed)[0..32]), peer_point)` (radicle-crypto
//!     SecretKey::ecdh).
//!   - nonce counter is LITTLE-endian in the 12-byte ChaCha nonce.
//!   - an empty payload encrypts to empty (no Poly1305 tag).
//!   - the protocol name (39 bytes > 32) seeds `h` via SHA-256.
//! Source: radicle-node/src/wire.rs (NOISE_XK), radicle-crypto/src/lib.rs
//! (ecdh), cyphernet noise/src/{state,cipher,hkdf}.rs, cyphergraphy ed25519.rs.
const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const ChaChaPoly = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ed25519 = std.crypto.sign.Ed25519;

const HASHLEN = 32;
const KEYLEN = 32;
const TAGLEN = ChaChaPoly.tag_length; // 16

// cyphernet's HandshakePattern Displays as {initiator}{responder}. Radicle's
// NOISE_XK = InitiatorPattern::Xmitted ("X") + OneWayPattern::Known ("L"), so
// the protocol name string is "XL", not "XK" - despite the `NOISE_XK` name.
pub const PROTOCOL_NAME = "Noise_XL_Edwards25519_ChaChaPoly_SHA256";

const CipherState = struct {
    k: [KEYLEN]u8 = @splat(0),
    n: u64 = 0,

    fn hasKey(self: CipherState) bool {
        return !std.mem.allEqual(u8, &self.k, 0);
    }

    // 12-byte nonce = 4 zero bytes ++ counter as little-endian u64.
    fn nonce(self: CipherState) [12]u8 {
        var out: [12]u8 = @splat(0);
        std.mem.writeInt(u64, out[4..12], self.n, .little);
        return out;
    }

    // Empty plaintext -> empty output (no tag). cyphernet still advances the
    // nonce on an empty payload when the key is set (encrypt_with_ad: n += 1).
    fn encrypt(self: *CipherState, out: []u8, ad: []const u8, pt: []const u8) usize {
        if (pt.len == 0) {
            self.n += 1;
            return 0;
        }
        var tag: [TAGLEN]u8 = undefined;
        ChaChaPoly.encrypt(out[0..pt.len], &tag, pt, ad, self.nonce(), self.k);
        @memcpy(out[pt.len..][0..TAGLEN], &tag);
        self.n += 1;
        return pt.len + TAGLEN;
    }

    // Empty ciphertext -> empty plaintext; nonce still advances (see encrypt).
    fn decrypt(self: *CipherState, out: []u8, ad: []const u8, ct: []const u8) ![]u8 {
        if (ct.len == 0) {
            self.n += 1;
            return out[0..0];
        }
        const body = ct[0 .. ct.len - TAGLEN];
        const tag: [TAGLEN]u8 = ct[ct.len - TAGLEN ..][0..TAGLEN].*;
        try ChaChaPoly.decrypt(out[0..body.len], body, tag, ad, self.nonce(), self.k);
        self.n += 1;
        return out[0..body.len];
    }
};

pub const SymmetricState = struct {
    h: [HASHLEN]u8,
    ck: [HASHLEN]u8,
    cipher: CipherState = .{},

    pub fn init() SymmetricState {
        // Protocol name is 39 bytes (> 32), so h = SHA256(name).
        var h: [HASHLEN]u8 = undefined;
        Sha256.hash(PROTOCOL_NAME, &h, .{});
        var self: SymmetricState = .{ .h = h, .ck = h };
        self.mixHash(&.{}); // empty prologue (cyphernet initialize: mix_hash(prologue))
        return self;
    }

    pub fn mixHash(self: *SymmetricState, data: []const u8) void {
        var d = Sha256.init(.{});
        d.update(&self.h);
        d.update(data);
        d.final(&self.h);
    }

    pub fn mixKey(self: *SymmetricState, ikm: []const u8) void {
        const out = hkdf2(self.ck, ikm);
        self.ck = out[0];
        self.cipher = .{ .k = out[1], .n = 0 };
    }

    // Returns the ciphertext length written to `out`.
    pub fn encryptAndHash(self: *SymmetricState, out: []u8, pt: []const u8) usize {
        // With no key set, ciphertext == plaintext (unencrypted).
        if (!self.cipher.hasKey()) {
            @memcpy(out[0..pt.len], pt);
            self.mixHash(pt);
            return pt.len;
        }
        const n = self.cipher.encrypt(out, &self.h, pt);
        self.mixHash(out[0..n]);
        return n;
    }

    pub fn decryptAndHash(self: *SymmetricState, out: []u8, ct: []const u8) ![]u8 {
        if (!self.cipher.hasKey()) {
            @memcpy(out[0..ct.len], ct);
            self.mixHash(ct);
            return out[0..ct.len];
        }
        const pt = try self.cipher.decrypt(out, &self.h, ct);
        self.mixHash(ct);
        return pt;
    }
};

// hkdf_2: temp = HMAC(ck, ikm); o1 = HMAC(temp, 0x01); o2 = HMAC(temp, o1 ++ 0x02).
fn hkdf2(ck: [HASHLEN]u8, ikm: []const u8) [2][HASHLEN]u8 {
    var temp: [HASHLEN]u8 = undefined;
    HmacSha256.create(&temp, ikm, &ck);

    var o1: [HASHLEN]u8 = undefined;
    HmacSha256.create(&o1, &[_]u8{0x01}, &temp);

    var o2: [HASHLEN]u8 = undefined;
    var m = HmacSha256.init(&temp);
    m.update(&o1);
    m.update(&[_]u8{0x02});
    m.final(&o2);

    return .{ o1, o2 };
}

/// Two transport cipher states produced by the handshake `split`.
pub const Transport = struct {
    send: CipherState,
    recv: CipherState,

    /// Encrypts a transport message. Returns bytes written to `out`.
    pub fn encrypt(self: *Transport, out: []u8, pt: []const u8) usize {
        return self.send.encrypt(out, &.{}, pt);
    }

    /// Decrypts a transport message in place-ish into `out`.
    pub fn decrypt(self: *Transport, out: []u8, ct: []const u8) ![]u8 {
        return self.recv.decrypt(out, &.{}, ct);
    }
};

/// Noise_XK message sizes on the wire. A reader has to know these up front:
/// the messages are not length-prefixed, so reading the wrong count blocks
/// forever waiting for bytes the peer will never send.
pub const MSG1_LEN = 32; // e, es: ephemeral key + empty payload
pub const MSG2_LEN = 32; // e, ee: ephemeral key + empty payload
pub const MSG3_LEN = 48; // s, se: static key (32) + tag (16) + empty payload

/// An Ed25519 key pair for the Edwards25519 DH. `secret_key` is the 32-byte
/// seed; `public_key` is the compressed Edwards point (the NID bytes).
pub const KeyPair = struct {
    secret_key: [32]u8,
    public_key: [32]u8,

    pub fn generateDeterministic(seed: [32]u8) !KeyPair {
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        return .{ .secret_key = seed, .public_key = kp.public_key.toBytes() };
    }
};

/// Initiator half of the handshake. The responder's static public key
/// (`rs`, the node's raw Ed25519 NID) must be known in advance.
pub const Initiator = struct {
    sym: SymmetricState,
    s: KeyPair, // our static key
    e: KeyPair, // our ephemeral key
    rs: [32]u8, // responder static (known)
    re: [32]u8 = @splat(0), // responder ephemeral (learned in msg 2)

    pub fn init(static: KeyPair, ephemeral: KeyPair, rs: [32]u8) Initiator {
        var sym = SymmetricState.init();
        sym.mixHash(&rs); // XK pre-message: responder's static is known.
        return .{ .sym = sym, .s = static, .e = ephemeral, .rs = rs };
    }

    /// Writes message 1 (`e, es`) into `out`; returns its length.
    pub fn writeMsg1(self: *Initiator, out: []u8) usize {
        @memcpy(out[0..32], &self.e.public_key);
        self.sym.mixHash(&self.e.public_key);
        self.sym.mixKey(&dh(self.e.secret_key, self.rs));
        const n = self.sym.encryptAndHash(out[32..], &.{});
        return 32 + n;
    }

    /// Reads message 2 (`e, ee`).
    pub fn readMsg2(self: *Initiator, msg: []const u8) !void {
        if (msg.len < 32) return error.ShortMessage;
        self.re = msg[0..32].*;
        self.sym.mixHash(&self.re);
        self.sym.mixKey(&dh(self.e.secret_key, self.re));
        var scratch: [0]u8 = undefined;
        _ = try self.sym.decryptAndHash(&scratch, msg[32..]);
    }

    /// Writes message 3 (`s, se`) into `out`; returns its length. After this,
    /// call `split`.
    pub fn writeMsg3(self: *Initiator, out: []u8) usize {
        const n1 = self.sym.encryptAndHash(out, &self.s.public_key);
        self.sym.mixKey(&dh(self.s.secret_key, self.re));
        const n2 = self.sym.encryptAndHash(out[n1..], &.{});
        return n1 + n2;
    }

    /// Derives the transport cipher states.
    ///
    /// cyphernet assigns sending=c1, receiving=c2 for BOTH roles (no standard
    /// initiator/responder swap). So to interoperate we must send with the key
    /// the responder receives on (c2) and receive on the key it sends with (c1).
    pub fn split(self: *Initiator) Transport {
        const out = hkdf2(self.sym.ck, &.{});
        return .{
            .send = .{ .k = out[1], .n = 0 },
            .recv = .{ .k = out[0], .n = 0 },
        };
    }
};

/// Responder half, used to test our initiator in-process (the real peer is a
/// radicle-node). The responder's static key is its identity.
pub const Responder = struct {
    sym: SymmetricState,
    s: KeyPair,
    e: KeyPair,
    re: [32]u8 = @splat(0),

    pub fn init(static: KeyPair, ephemeral: KeyPair) Responder {
        var sym = SymmetricState.init();
        sym.mixHash(&static.public_key);
        return .{ .sym = sym, .s = static, .e = ephemeral };
    }

    pub fn readMsg1(self: *Responder, msg: []const u8) !void {
        if (msg.len < 32) return error.ShortMessage;
        self.re = msg[0..32].*;
        self.sym.mixHash(&self.re);
        self.sym.mixKey(&dh(self.s.secret_key, self.re));
        var scratch: [0]u8 = undefined;
        _ = try self.sym.decryptAndHash(&scratch, msg[32..]);
    }

    pub fn writeMsg2(self: *Responder, out: []u8) usize {
        @memcpy(out[0..32], &self.e.public_key);
        self.sym.mixHash(&self.e.public_key);
        self.sym.mixKey(&dh(self.e.secret_key, self.re));
        const n = self.sym.encryptAndHash(out[32..], &.{});
        return 32 + n;
    }

    pub fn readMsg3(self: *Responder, msg: []const u8) ![32]u8 {
        var rs_buf: [32]u8 = undefined;
        const rs = try self.sym.decryptAndHash(&rs_buf, msg[0 .. 32 + TAGLEN]);
        self.sym.mixKey(&dh(self.e.secret_key, rs[0..32].*));
        var scratch: [0]u8 = undefined;
        _ = try self.sym.decryptAndHash(&scratch, msg[32 + TAGLEN ..]);
        return rs_buf;
    }

    /// Mirror of Initiator.split: responder receives with the first key.
    // Matches cyphernet: responder sends with c1, receives with c2.
    pub fn split(self: *Responder) Transport {
        const out = hkdf2(self.sym.ck, &.{});
        return .{
            .send = .{ .k = out[0], .n = 0 },
            .recv = .{ .k = out[1], .n = 0 },
        };
    }
};

// Edwards25519 ECDH (radicle-crypto SecretKey::ecdh):
//   scalar = clamp(SHA512(seed)[0..32]);  shared = (scalar * peer_point).compress()
fn dh(seed: [32]u8, public: [32]u8) [32]u8 {
    var az: [Sha512.digest_length]u8 = undefined;
    Sha512.hash(&seed, &az, .{});
    var scalar = az[0..32].*;
    Edwards25519.scalar.clamp(&scalar);

    const point = Edwards25519.fromBytes(public) catch @panic("invalid edwards point");
    const shared = point.mul(scalar) catch @panic("edwards mul failed");
    return shared.toBytes();
}

const testing = std.testing;

test "dh is symmetric (radicle-crypto ecdh property)" {
    // dh(a_seed, B_pub) == dh(b_seed, A_pub), the invariant XK relies on.
    const a = try KeyPair.generateDeterministic(@splat(11));
    const b = try KeyPair.generateDeterministic(@splat(22));
    const ab = dh(a.secret_key, b.public_key);
    const ba = dh(b.secret_key, a.public_key);
    try testing.expectEqualSlices(u8, &ab, &ba);
}

test "XK handshake: initiator and responder agree, transport works" {
    const i_s = try KeyPair.generateDeterministic(@splat(1));
    const i_e = try KeyPair.generateDeterministic(@splat(2));
    const r_s = try KeyPair.generateDeterministic(@splat(3));
    const r_e = try KeyPair.generateDeterministic(@splat(4));

    var ini = Initiator.init(i_s, i_e, r_s.public_key);
    var res = Responder.init(r_s, r_e);

    var buf: [128]u8 = undefined;

    const n1 = ini.writeMsg1(&buf);
    try testing.expectEqual(MSG1_LEN, n1); // e + empty payload
    try res.readMsg1(buf[0..n1]);

    const n2 = res.writeMsg2(&buf);
    try testing.expectEqual(MSG2_LEN, n2);
    try ini.readMsg2(buf[0..n2]);

    const n3 = ini.writeMsg3(&buf);
    try testing.expectEqual(MSG3_LEN, n3); // s(32+16 tag) + empty payload
    const recovered_is = try res.readMsg3(buf[0..n3]);
    try testing.expectEqualSlices(u8, &i_s.public_key, &recovered_is);

    // Handshake hashes must match.
    try testing.expectEqualSlices(u8, &ini.sym.h, &res.sym.h);

    var it = ini.split();
    var rt = res.split();

    // Initiator -> responder.
    var ct: [64]u8 = undefined;
    const cn = it.encrypt(&ct, "ping");
    var pt: [64]u8 = undefined;
    try testing.expectEqualStrings("ping", try rt.decrypt(&pt, ct[0..cn]));

    // Responder -> initiator.
    const cn2 = rt.encrypt(&ct, "pong");
    try testing.expectEqualStrings("pong", try it.decrypt(&pt, ct[0..cn2]));
}

test "hkdf2 matches HMAC chain" {
    const ck: [32]u8 = @splat(0xab);
    const out = hkdf2(ck, "input");
    // o1 = HMAC(HMAC(ck,ikm), 0x01); recompute independently.
    var temp: [32]u8 = undefined;
    HmacSha256.create(&temp, "input", &ck);
    var o1: [32]u8 = undefined;
    HmacSha256.create(&o1, &[_]u8{1}, &temp);
    try testing.expectEqualSlices(u8, &o1, &out[0]);
}

test "encryptAndHash round trips, and an empty payload encrypts to empty" {
    var a = SymmetricState.init();
    a.mixKey("shared-secret-material");
    var b = a; // same state -> same key/nonce

    var buf: [64]u8 = undefined;
    const n = a.encryptAndHash(&buf, "hello");
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("hello", try b.decryptAndHash(&out, buf[0..n]));

    var c = SymmetricState.init();
    c.mixKey("k");
    try testing.expectEqual(@as(usize, 0), c.encryptAndHash(&buf, ""));
}
