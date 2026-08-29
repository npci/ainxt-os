// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! HS256 JWT minting for the console's gateway role.
//!
//! The console is the authenticating gateway (DOCKING.md): it decides who the caller is and proves
//! it to AiNxt OS with a signed token. The browser never sees the secret and never asserts identity,
//! which is the whole reason the console exists rather than pointing a web page at `:8080` directly.
//!
//! Claim names are fixed by `ainxt_server::JwtSsoAuth`: `sub` (required), `role`, `caps`,
//! `clearance`, `department`, `exp`. Anything else is ignored by the verifier.

use sha2::{Digest, Sha256};

const BLOCK: usize = 64; // SHA-256 block size, for HMAC padding (RFC 2104).

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-SHA256 (RFC 2104). Matches `ainxt_server::hmac_sha256`, which is what verifies the result.
fn hmac_sha256(secret: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key = [0u8; BLOCK];
    if secret.len() > BLOCK {
        key[..32].copy_from_slice(&sha256(secret));
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// base64url, no padding — the JWT encoding (RFC 7515 §2).
fn b64url(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

/// The local operator identity the console asserts on the caller's behalf.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub user: String,
    pub role: String,
    pub department: String,
    pub caps: Vec<String>,
    pub clearance: String,
}

impl Default for Identity {
    fn default() -> Self {
        // Deliberately a plain engineer, not an admin: the console's default identity should be
        // able to hold a conversation and nothing more. Escalating is an explicit choice in Settings.
        Identity {
            user: "console-operator".into(),
            role: "engineer".into(),
            department: "engineering".into(),
            caps: vec!["chat.send".into()],
            clearance: "public".into(),
        }
    }
}

/// Mint a short-lived token for `identity`. `ttl_secs` is deliberately small — the console mints one
/// per request, so a leaked token is worthless almost immediately.
pub fn mint(secret: &[u8], identity: &Identity, now_unix: u64, ttl_secs: u64) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "sub": identity.user,
        "role": identity.role,
        "department": identity.department,
        "caps": identity.caps,
        "clearance": identity.clearance,
        "iat": now_unix,
        "exp": now_unix + ttl_secs,
    });
    let payload = b64url(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");
    let sig = b64url(&hmac_sha256(secret, signing_input.as_bytes()));
    format!("{signing_input}.{sig}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 2 — the standard HMAC-SHA256 vector. If this passes, the daemon's
    /// `ct_eq` comparison against its own `hmac_sha256` will agree with ours.
    #[test]
    fn hmac_matches_rfc4231_vector() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231 case 3 uses a key longer than one block, which exercises the key-hashing branch.
    #[test]
    fn hmac_handles_key_longer_than_block() {
        let mac = hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            mac.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn b64url_is_unpadded_and_url_safe() {
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(&[251, 255]), "-_8"); // '+' and '/' must become '-' and '_'
        assert!(!b64url(b"any").contains('='));
    }

    #[test]
    fn minted_token_has_three_parts_and_carries_the_identity() {
        let id = Identity::default();
        let t = mint(b"secret", &id, 1_000, 60);
        assert_eq!(t.split('.').count(), 3);
        let payload = t.split('.').nth(1).expect("payload");
        // Decode enough to prove the claims the verifier reads are present and correct.
        let json = String::from_utf8(b64url_decode_for_test(payload)).expect("utf8");
        let v: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(v["sub"], "console-operator");
        assert_eq!(v["role"], "engineer");
        assert_eq!(v["clearance"], "public");
        assert_eq!(v["exp"], 1_060);
        assert_eq!(v["caps"][0], "chat.send");
    }

    /// The default identity must NOT be admin — an admin console default would hand every local
    /// process a full-capability principal through the chat window.
    #[test]
    fn default_identity_is_not_admin() {
        assert_ne!(Identity::default().role, "admin");
        assert_eq!(Identity::default().caps, vec!["chat.send".to_string()]);
    }

    fn b64url_decode_for_test(s: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let idx = |c: u8| T.iter().position(|&t| t == c).expect("b64 char") as u32;
        let b = s.as_bytes();
        let mut out = Vec::new();
        for chunk in b.chunks(4) {
            let mut n = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                n |= idx(c) << (18 - 6 * i);
            }
            out.push((n >> 16) as u8);
            if chunk.len() > 2 {
                out.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(n as u8);
            }
        }
        out
    }
}
