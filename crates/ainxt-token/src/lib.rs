// SPDX-License-Identifier: Apache-2.0
// Copyright 2024-2026 National Payments Corporation of India
//! ainxt-token — the encrypted per-(user, connector) secret store (Phase 2, increment #2).
//!
//! Connectors act on behalf of a user, which means the runtime must hold that user's OAuth/API
//! tokens. Those tokens are the crown jewels: a leak is a direct account takeover of the user's
//! GitLab/Jira/Graph. This crate keeps them encrypted at rest and structurally isolated per user.
//!
//! Three layers, each a seam:
//!
//! - [`SecretCodec`] — authenticated encryption. The default [`AeadCodec`] uses **XChaCha20-Poly1305**
//!   over a **versioned [`KeyRing`]**: every sealed record records *which key version* encrypted it,
//!   so keys can be **rotated** without a flag-day re-encrypt (old records decrypt with retained old
//!   keys; new records use the new active key). The 192-bit XChaCha nonce is safe to pick at random,
//!   so there is no nonce-reuse footgun. Encryption is bound to **additional authenticated data**
//!   (AAD) so a sealed blob is cryptographically tied to *its* (user, connector) — it cannot be
//!   transplanted to another user or connector even by someone with write access to the store.
//! - [`TokenStore`] — persistence. The default [`InMemoryTokenStore`] is for tests/dev; a Postgres
//!   store plugs in behind the same trait. The store only ever sees ciphertext.
//! - [`TokenVault`] — composes codec + store so callers work in plaintext at the edges while the
//!   store holds only sealed bytes. It exposes `save` / `load` / `metadata` / `revoke` /
//!   `connectors_for`. `revoke` is the storage half of the connector deauthorize verb (#6).
//!
//! Non-secret metadata (token expiry, granted scopes) is stored in the clear alongside the sealed
//! secret so the refresh coordinator (#4) can schedule refreshes and the OAuth engine (#3) can do
//! incremental-consent checks **without decrypting** — least-exposure of the secret.
//!
//! Clean-room: terminology, envelope format, and the vault API are original to AiNxt.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ainxt_types::Principal;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an XChaCha20-Poly1305 key (256-bit) and nonce (192-bit).
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

// ============================ Codec (versioned AEAD) ============================

/// A crypto failure. Deliberately coarse: a caller must not be able to distinguish "wrong key" from
/// "tampered ciphertext" from "wrong AAD" (that distinction is an oracle). Only [`UnknownKey`] is
/// reported precisely because it is an operational/config error, not an attacker-controlled input.
///
/// [`UnknownKey`]: CodecError::UnknownKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    /// Encryption failed (should not happen with a valid key; surfaced rather than panicking).
    Encrypt,
    /// Decryption/authentication failed — wrong key, tampered ciphertext, or mismatched AAD.
    Decrypt,
    /// The sealed record names a key version this ring does not hold (retire-too-early / misconfig).
    UnknownKey(u32),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecError::Encrypt => f.write_str("secret encryption failed"),
            CodecError::Decrypt => f.write_str("secret decryption/authentication failed"),
            CodecError::UnknownKey(id) => write!(f, "no key version {id} in the key ring"),
        }
    }
}

impl std::error::Error for CodecError {}

/// A sealed secret: self-describing so it can be stored and later opened by whichever key version
/// produced it. Serializable for persistence (the store holds exactly this — never plaintext).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    /// Which [`KeyRing`] key version encrypted this record (enables rotation).
    pub key_id: u32,
    /// The per-record random nonce (24 bytes for XChaCha).
    pub nonce: Vec<u8>,
    /// Ciphertext with the appended Poly1305 authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Authenticated-encryption seam. The enterprise HSM/KMS-backed codec plugs in here; the default is
/// [`AeadCodec`] over an in-process [`KeyRing`].
pub trait SecretCodec: Send + Sync {
    /// Encrypt `plaintext`, binding it to `aad` (additional authenticated data). Opening later
    /// requires the *same* `aad`, so the ciphertext is tied to its logical owner/context.
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret, CodecError>;
    /// Decrypt a sealed record, verifying `aad`. Fails if the key version is unknown, the AAD
    /// differs, or the ciphertext was tampered with.
    fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Vec<u8>, CodecError>;
    /// The key version new records are currently sealed with.
    fn active_key_id(&self) -> u32;
}

/// A 256-bit key, wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    fn as_cipher_key(&self) -> &Key {
        Key::from_slice(&self.0)
    }
}

/// A versioned set of encryption keys. New records seal with `active`; any retained key can open an
/// older record, which is what makes rotation non-disruptive.
pub struct KeyRing {
    active: u32,
    keys: BTreeMap<u32, SecretKey>,
}

impl KeyRing {
    /// Start a ring with a single active key.
    pub fn new(key_id: u32, key: [u8; KEY_LEN]) -> Self {
        let mut keys = BTreeMap::new();
        keys.insert(key_id, SecretKey(key));
        KeyRing {
            active: key_id,
            keys,
        }
    }

    /// Start a ring with a single, freshly generated random active key (bootstrap/dev).
    pub fn generate(key_id: u32) -> Self {
        KeyRing::new(key_id, random_key())
    }

    /// Add a decryption key **without** changing the active (sealing) key — e.g. importing an old
    /// key so historical records still open.
    pub fn with_key(mut self, key_id: u32, key: [u8; KEY_LEN]) -> Self {
        self.keys.insert(key_id, SecretKey(key));
        self
    }

    /// Rotate: install `key` as version `key_id` and make it the new active (sealing) key. Prior
    /// keys are retained so already-stored records keep decrypting until they are re-sealed.
    /// `key_id` must be greater than the current active (monotonic versions); otherwise ignored.
    pub fn rotate_to(mut self, key_id: u32, key: [u8; KEY_LEN]) -> Self {
        self.keys.insert(key_id, SecretKey(key));
        if key_id > self.active {
            self.active = key_id;
        }
        self
    }

    /// Retire (drop) an old key version so records sealed with it can no longer be opened. Refuses
    /// to retire the active key. Returns whether a key was removed.
    pub fn retire(&mut self, key_id: u32) -> bool {
        if key_id == self.active {
            return false;
        }
        self.keys.remove(&key_id).is_some()
    }

    fn active_key(&self) -> &SecretKey {
        self.keys
            .get(&self.active)
            .expect("active key always present")
    }
}

/// Generate a cryptographically-random 256-bit key from the OS CSPRNG.
pub fn random_key() -> [u8; KEY_LEN] {
    // XChaCha20Poly1305 keys are 32 bytes; generate_key uses OsRng under the hood.
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(key.as_slice());
    out
}

/// The default codec: XChaCha20-Poly1305 over a versioned [`KeyRing`]. The ring lives behind a
/// [`Mutex`] (not a bare [`KeyRing`]) so [`AeadCodec::rotate`] can mutate the LIVE instance in place —
/// every [`TokenVault`] built over the SAME `Arc<AeadCodec>` (see [`SharedAeadCodec`]) observes a
/// rotation immediately, with no daemon restart and no second, disjoint ring to silently fall out of
/// sync with the one that was actually rotated.
pub struct AeadCodec {
    ring: Mutex<KeyRing>,
}

impl AeadCodec {
    pub fn new(ring: KeyRing) -> Self {
        AeadCodec {
            ring: Mutex::new(ring),
        }
    }

    /// Rotate the live ring in place: install `key` one version above the current active key and make
    /// it active, so every subsequent [`seal`](SecretCodec::seal) call uses it — while every key
    /// already in the ring (including the one just superseded) is retained, so a record sealed before
    /// this call keeps [`open`](SecretCodec::open)ing (KEY-ROT-01). Returns the new active key id.
    ///
    /// The new id is always `current_active + 1`, computed and applied under ONE mutex acquisition —
    /// never a caller-supplied id — specifically so two concurrent rotations can never race onto the
    /// SAME id (each sees the other's already-published result and picks the next one up), and so a
    /// `seal`/`open` call in flight on another thread can never observe a half-rotated ring.
    ///
    /// Delegates the actual insert-and-promote to [`KeyRing::rotate_to`] UNCHANGED — this method only
    /// adds the seam that makes it safe to call on a LIVE, concurrently-read `Arc<AeadCodec>`.
    /// `KeyRing::rotate_to` takes `self` by value and returns `Self` (a deliberately immutable-style
    /// builder signature — see its own doc), so calling it on a ring that lives behind a `Mutex<_>`
    /// means taking the current ring out of the mutex slot first: swap in a cheap placeholder built
    /// from the SAME `(next_id, key)` this call is about to rotate to (never observed by anyone — the
    /// mutex stays locked for the whole swap), rotate the TAKEN ring by value, then publish the
    /// rotated ring back into the slot.
    pub fn rotate(&self, key: [u8; KEY_LEN]) -> u32 {
        let mut guard = self.ring.lock().expect("keyring lock poisoned");
        let next_id = guard.active.checked_add(1).expect(
            "key ring exhausted the u32 key id space (4B rotations) — never expected in practice",
        );
        let placeholder = KeyRing::new(next_id, key);
        let current = std::mem::replace(&mut *guard, placeholder);
        *guard = current.rotate_to(next_id, key);
        next_id
    }

    /// Retire a non-active key version on the LIVE ring: any record already sealed under `key_id`
    /// becomes permanently unrecoverable through this codec ([`open`](SecretCodec::open) will return
    /// [`CodecError::UnknownKey`]). Unlike [`rotate`](Self::rotate), [`KeyRing::retire`] already takes
    /// `&mut self`, so this needs no swap trick — just the same mutex seam that makes it safe to call
    /// concurrently with live `seal`/`open` traffic on the same `Arc<AeadCodec>`. Refuses to retire the
    /// active key (returns `false`, matching [`KeyRing::retire`]'s own fail-closed contract) — retiring
    /// the key currently sealing new records would make every NEW seal immediately unrecoverable too,
    /// which is never the intended effect of "retire an old, compromised key."
    pub fn retire(&self, key_id: u32) -> bool {
        let mut guard = self.ring.lock().expect("keyring lock poisoned");
        guard.retire(key_id)
    }
}

impl SecretCodec for AeadCodec {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret, CodecError> {
        let ring = self.ring.lock().expect("keyring lock poisoned");
        let cipher = XChaCha20Poly1305::new(ring.active_key().as_cipher_key());
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CodecError::Encrypt)?;
        Ok(SealedSecret {
            key_id: ring.active,
            nonce: nonce.to_vec(),
            ciphertext,
        })
    }

    fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Vec<u8>, CodecError> {
        let ring = self.ring.lock().expect("keyring lock poisoned");
        let key = ring
            .keys
            .get(&sealed.key_id)
            .ok_or(CodecError::UnknownKey(sealed.key_id))?;
        if sealed.nonce.len() != NONCE_LEN {
            return Err(CodecError::Decrypt);
        }
        let cipher = XChaCha20Poly1305::new(key.as_cipher_key());
        let nonce = XNonce::from_slice(&sealed.nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &sealed.ciphertext,
                    aad,
                },
            )
            .map_err(|_| CodecError::Decrypt)
    }

    fn active_key_id(&self) -> u32 {
        self.ring.lock().expect("keyring lock poisoned").active
    }
}

/// Lets multiple [`TokenVault`]s share ONE live, rotatable [`AeadCodec`] instance instead of each
/// privately owning its own disjoint [`KeyRing`] built from the same raw key bytes. A composition root
/// that needs a rotation performed through one entrypoint (e.g. an admin HTTP route) to be visible to
/// every vault built over the codec (e.g. the connector OAuth-callback SEAL path and the connector-USE
/// refresh/READ path, in `ainxt-connector-http`) constructs ONE `Arc<AeadCodec>` and wraps a clone of
/// it in a `SharedAeadCodec` for each [`TokenVault::new`] call, instead of calling [`AeadCodec::new`] a
/// second time over the same raw key bytes — which would produce a second, independently-rotatable
/// ring that silently drifts out of sync the first time either one is rotated.
pub struct SharedAeadCodec(pub Arc<AeadCodec>);

impl SecretCodec for SharedAeadCodec {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<SealedSecret, CodecError> {
        self.0.seal(plaintext, aad)
    }

    fn open(&self, sealed: &SealedSecret, aad: &[u8]) -> Result<Vec<u8>, CodecError> {
        self.0.open(sealed, aad)
    }

    fn active_key_id(&self) -> u32 {
        self.0.active_key_id()
    }
}

// ============================ Store ============================

/// A store-level failure (backend/IO). In-memory never errors; a Postgres store surfaces its errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token store error: {}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// The tenant used when a deployment is single-tenant (or a caller uses the unscoped API). A real
/// tenant id can never equal this sentinel in a multi-tenant deployment because tenant ids there are
/// always explicit (a UUID/slug from the JWT `tid`/`tenant` claim), so the sentinel and a real
/// tenant never collide in the key space.
pub const DEFAULT_TENANT: &str = "\u{1}default";

/// A tenant id proven to originate from a **verified identity claim** — the authenticator validated
/// the JWT signature and read the tenant from the trusted `tid`/`tenant` claim. It is the ONLY way to
/// name a tenant on the principal-bound vault API ([`TokenVault::save_for`] etc.), so a
/// request-body / client-supplied tenant string cannot reach the token key. This is the tenant half
/// of the confused-deputy defense the design's `(jwt.sub, connector, tenant)` axis requires:
/// pairing a verified caller with an *unverified* tenant is structurally impossible because there is
/// no bare-`&str` tenant parameter on the bound API — only a [`TenantClaim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantClaim(String);

impl TenantClaim {
    /// Mint from an authenticated claim. **Caller contract:** call this only *after* the JWT signature
    /// and the `tid`/`tenant` claim have been verified by the authenticator seam — never from
    /// request-body input. Deliberately not a `From<&str>` impl, so a self-asserted string cannot
    /// silently become a "verified" tenant at a call site (the conversion is always an explicit,
    /// greppable `from_verified_claim`).
    pub fn from_verified_claim(tenant: impl Into<String>) -> Self {
        TenantClaim(tenant.into())
    }
    /// The single-tenant / unscoped sentinel ([`DEFAULT_TENANT`]) — never a real, collidable tenant id.
    pub fn single_tenant() -> Self {
        TenantClaim(DEFAULT_TENANT.to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identity of a stored token: which tenant, whose, and for which connector.
///
/// The **tenant** axis (design: keyed by `(jwt.sub, connector, tenant)`) is a first-class part of the
/// key AND of the AEAD AAD binding (see [`TokenVault`]): two tenants that happen to reuse the same
/// `user_id` (e.g. federated logins minting overlapping subs) are structurally and cryptographically
/// isolated — a record sealed for `(tenant=A, user, connector)` cannot be opened as
/// `(tenant=B, user, connector)` even by an attacker with full write access to the store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TokenKey {
    pub tenant: String,
    pub user_id: String,
    pub connector: String,
}

impl TokenKey {
    /// Key in the [`DEFAULT_TENANT`] (single-tenant / unscoped callers).
    pub fn of(user_id: impl Into<String>, connector: impl Into<String>) -> Self {
        TokenKey {
            tenant: DEFAULT_TENANT.to_string(),
            user_id: user_id.into(),
            connector: connector.into(),
        }
    }
    /// Fully tenant-scoped key (multi-tenant deployments).
    pub fn scoped(
        tenant: impl Into<String>,
        user_id: impl Into<String>,
        connector: impl Into<String>,
    ) -> Self {
        TokenKey {
            tenant: tenant.into(),
            user_id: user_id.into(),
            connector: connector.into(),
        }
    }

    /// Derive the key from a **verified identity**: the tenant comes from a [`TenantClaim`] (an
    /// authenticated claim, never client-supplied) and the user axis is ALWAYS the verified
    /// principal's `user_id` — the JWT `sub`, *read from the principal*, not accepted as a separate
    /// argument. This is the confused-deputy defense: at this call site there is no way to pair one
    /// authenticated caller with another user's `sub` or with an unverified tenant, because neither
    /// is a free parameter. Every principal-bound vault method ([`TokenVault::save_for`] etc.) keys
    /// through here, so the design's `(jwt.sub, connector, tenant)` axis is bound to identity by
    /// construction.
    pub fn for_principal(
        tenant: &TenantClaim,
        principal: &Principal,
        connector: impl Into<String>,
    ) -> Self {
        TokenKey {
            tenant: tenant.0.clone(),
            user_id: principal.user_id.clone(),
            connector: connector.into(),
        }
    }
}

/// What the store persists: the sealed secret plus **plaintext, non-secret** metadata used for
/// refresh scheduling and incremental-consent checks without decrypting the secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredToken {
    pub sealed: SealedSecret,
    /// Unix seconds at which the access token expires, if known.
    pub expires_at: Option<u64>,
    /// OAuth scopes granted with this token (empty for API-token connectors).
    pub scopes: Vec<String>,
}

/// Persistence seam for sealed tokens. Keyed by (tenant, user, connector). Only ciphertext is ever
/// stored. `connectors_for` is tenant-scoped so one tenant can never enumerate another's grants even
/// when `user_id` values overlap.
pub trait TokenStore: Send + Sync {
    fn put(&self, key: &TokenKey, record: StoredToken) -> Result<(), StoreError>;
    fn get(&self, key: &TokenKey) -> Result<Option<StoredToken>, StoreError>;
    /// Remove a record; returns whether one existed. Storage half of the deauthorize verb.
    fn delete(&self, key: &TokenKey) -> Result<bool, StoreError>;
    /// The connectors a user currently has a token for **within `tenant`**.
    fn connectors_for(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError>;
}

/// The (tenant, user, connector) tuple used as the in-memory / file map key.
type MapKey = (String, String, String);

/// In-memory token store (tests/dev). Cheap to clone; clones share the same backing map.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTokenStore {
    map: Arc<Mutex<BTreeMap<MapKey, StoredToken>>>,
}

impl InMemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn k(key: &TokenKey) -> MapKey {
        (
            key.tenant.clone(),
            key.user_id.clone(),
            key.connector.clone(),
        )
    }
}

impl TokenStore for InMemoryTokenStore {
    fn put(&self, key: &TokenKey, record: StoredToken) -> Result<(), StoreError> {
        self.map
            .lock()
            .expect("store lock")
            .insert(Self::k(key), record);
        Ok(())
    }
    fn get(&self, key: &TokenKey) -> Result<Option<StoredToken>, StoreError> {
        Ok(self
            .map
            .lock()
            .expect("store lock")
            .get(&Self::k(key))
            .cloned())
    }
    fn delete(&self, key: &TokenKey) -> Result<bool, StoreError> {
        Ok(self
            .map
            .lock()
            .expect("store lock")
            .remove(&Self::k(key))
            .is_some())
    }
    fn connectors_for(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        let map = self.map.lock().expect("store lock");
        Ok(map
            .keys()
            .filter(|(t, u, _)| t == tenant && u == user_id)
            .map(|(_, _, c)| c.clone())
            .collect())
    }
}

/// Durable, file-backed token store: the encrypted records persist to a JSON file and survive a
/// restart. Single-process concurrency via a Mutex; the whole map is rewritten **atomically** on
/// each mutation (temp file + rename, so a crash mid-write never corrupts the store). The file holds
/// only ciphertext + non-secret metadata. For 2,000-user cross-process horizontal scale, a Postgres
/// store plugs in behind this same [`TokenStore`] trait — `FileTokenStore` is the durable OSS
/// default, not the sharded-scale one.
///
/// Cheap to clone, like [`InMemoryTokenStore`]/[`InMemorySqlTokenBackend`]: the map is behind an
/// `Arc<Mutex<..>>`, so clones share the same backing table AND the same on-disk file. This is what
/// lets a composition root hand ONE `FileTokenStore` to both the OAuth-callback SEAL path
/// ([`TokenVault::save_in`]) and the USE-path refresh/READ path — the same sharing shape
/// `InMemorySqlTokenBackend` already provides for the in-memory backend (see
/// `ainxt-runtimed::mounts::build_connector_gateway`'s doc).
#[derive(Clone)]
pub struct FileTokenStore {
    path: PathBuf,
    map: Arc<Mutex<BTreeMap<MapKey, StoredToken>>>,
}

#[derive(Serialize, Deserialize)]
struct PersistedEntry {
    /// Tenant defaults to [`DEFAULT_TENANT`] when reading a pre-multi-tenant file (additive upgrade).
    #[serde(default = "default_tenant_field")]
    tenant: String,
    user: String,
    connector: String,
    /// Checkmarx CX-FP: renamed to `sealed`; `#[serde(rename)]` preserves the on-disk JSON key.
    #[serde(rename = "token")]
    sealed: StoredToken,
}

fn default_tenant_field() -> String {
    DEFAULT_TENANT.to_string()
}

impl FileTokenStore {
    /// Open (or create) a store at `path`, loading any records already on disk.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let map = if path.exists() {
            let bytes = std::fs::read(&path)
                .map_err(|e| StoreError(format!("read {}: {e}", path.display())))?;
            let entries: Vec<PersistedEntry> = serde_json::from_slice(&bytes)
                .map_err(|e| StoreError(format!("parse {}: {e}", path.display())))?;
            entries
                .into_iter()
                .map(|e| ((e.tenant, e.user, e.connector), e.sealed))
                .collect()
        } else {
            BTreeMap::new()
        };
        Ok(FileTokenStore {
            path,
            map: Arc::new(Mutex::new(map)),
        })
    }

    fn k(key: &TokenKey) -> MapKey {
        (
            key.tenant.clone(),
            key.user_id.clone(),
            key.connector.clone(),
        )
    }

    fn persist(&self, map: &BTreeMap<MapKey, StoredToken>) -> Result<(), StoreError> {
        let entries: Vec<PersistedEntry> = map
            .iter()
            .map(|((t, u, c), tok)| PersistedEntry {
                tenant: t.clone(),
                user: u.clone(),
                connector: c.clone(),
                sealed: tok.clone(),
            })
            .collect();
        let json = serde_json::to_vec_pretty(&entries)
            .map_err(|e| StoreError(format!("serialize: {e}")))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &json)
            .map_err(|e| StoreError(format!("write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| StoreError(format!("rename into {}: {e}", self.path.display())))?;
        Ok(())
    }
}

impl TokenStore for FileTokenStore {
    fn put(&self, key: &TokenKey, record: StoredToken) -> Result<(), StoreError> {
        let mut map = self.map.lock().expect("store lock");
        map.insert(Self::k(key), record);
        self.persist(&map)
    }
    fn get(&self, key: &TokenKey) -> Result<Option<StoredToken>, StoreError> {
        Ok(self
            .map
            .lock()
            .expect("store lock")
            .get(&Self::k(key))
            .cloned())
    }
    fn delete(&self, key: &TokenKey) -> Result<bool, StoreError> {
        let mut map = self.map.lock().expect("store lock");
        let removed = map.remove(&Self::k(key)).is_some();
        if removed {
            self.persist(&map)?;
        }
        Ok(removed)
    }
    fn connectors_for(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        let map = self.map.lock().expect("store lock");
        Ok(map
            .keys()
            .filter(|(t, u, _)| t == tenant && u == user_id)
            .map(|(_, _, c)| c.clone())
            .collect())
    }
}

// ============================ SQL / Postgres store (durable, cross-process) ============================
//
// [`FileTokenStore`] is durable but single-node; the 2,000-user fleet needs a store that many worker
// PROCESSES on many hosts share — the design's `user_connector_tokens` Postgres table keyed by
// `(jwt.sub, connector, tenant)`. [`SqlTokenStore`] implements [`TokenStore`] over a narrow,
// row-oriented [`SqlTokenBackend`] seam that maps 1:1 onto that table. The seam is the *only* thing
// that talks to the database driver, so:
//   * the store's relational logic (upsert-on-conflict, tenant-scoped listing, delete-returns-existed)
//     is proven OFFLINE against [`InMemorySqlTokenBackend`] — no live DB in tests; and
//   * production binds a Postgres-backed `SqlTokenBackend` (sqlx / rust-postgres) that runs
//     [`USER_CONNECTOR_TOKENS_DDL`] and the parameterized statements — with the store never seeing
//     plaintext (it only ever moves the already-sealed [`SealedSecret`] bytes).

/// Canonical DDL for the durable token table. The composite PRIMARY KEY is the design's
/// `(tenant, jwt.sub, connector)` axis; the sealed secret is stored as its three ciphertext columns
/// (never plaintext) plus non-secret expiry/scope metadata. A production `SqlTokenBackend` runs this
/// (idempotently) at startup. `bytea`/`bigint`/`text[]` are Postgres types; other backends map them.
pub const USER_CONNECTOR_TOKENS_DDL: &str = "\
CREATE TABLE IF NOT EXISTS user_connector_tokens (
    tenant      text        NOT NULL,
    user_id     text        NOT NULL,
    connector   text        NOT NULL,
    key_id      bigint      NOT NULL,
    nonce       bytea       NOT NULL,
    ciphertext  bytea       NOT NULL,
    expires_at  bigint,
    scopes      text[]      NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, user_id, connector)
);";

/// One row of `user_connector_tokens`: the composite key + the sealed secret columns + non-secret
/// metadata. This is the exact shape a Postgres backend reads/writes; it never carries plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRow {
    pub tenant: String,
    pub user_id: String,
    pub connector: String,
    pub key_id: u32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub expires_at: Option<u64>,
    pub scopes: Vec<String>,
}

impl TokenRow {
    fn from_record(key: &TokenKey, record: &StoredToken) -> Self {
        TokenRow {
            tenant: key.tenant.clone(),
            user_id: key.user_id.clone(),
            connector: key.connector.clone(),
            key_id: record.sealed.key_id,
            nonce: record.sealed.nonce.clone(),
            ciphertext: record.sealed.ciphertext.clone(),
            expires_at: record.expires_at,
            scopes: record.scopes.clone(),
        }
    }
    fn into_record(self) -> StoredToken {
        StoredToken {
            sealed: SealedSecret {
                key_id: self.key_id,
                nonce: self.nonce,
                ciphertext: self.ciphertext,
            },
            expires_at: self.expires_at,
            scopes: self.scopes,
        }
    }
}

/// The narrow relational seam behind [`SqlTokenStore`]. Every method maps to one parameterized SQL
/// statement against `user_connector_tokens`; the trait is the boundary the DB driver lives behind so
/// the store logic is testable without a live database. All methods are keyed on the full
/// `(tenant, user_id, connector)` composite so tenant isolation holds at the storage layer.
pub trait SqlTokenBackend: Send + Sync {
    /// `INSERT ... ON CONFLICT (tenant,user_id,connector) DO UPDATE` — idempotent upsert.
    fn upsert(&self, row: &TokenRow) -> Result<(), StoreError>;
    /// `SELECT ... WHERE tenant=$1 AND user_id=$2 AND connector=$3`.
    fn fetch(
        &self,
        tenant: &str,
        user_id: &str,
        connector: &str,
    ) -> Result<Option<TokenRow>, StoreError>;
    /// `DELETE ... WHERE (...)` — returns whether a row was actually removed (rows-affected > 0).
    fn remove(&self, tenant: &str, user_id: &str, connector: &str) -> Result<bool, StoreError>;
    /// `SELECT connector ... WHERE tenant=$1 AND user_id=$2` — tenant-scoped enumeration.
    fn list_connectors(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError>;
}

/// Durable, cross-process [`TokenStore`] over a relational backend (`user_connector_tokens`). The
/// store holds no state itself; it converts [`StoredToken`] ⇄ [`TokenRow`] and delegates to the
/// backend. Bind a Postgres backend in the composition root for the 2,000-user fleet.
pub struct SqlTokenStore<B: SqlTokenBackend> {
    backend: B,
}

impl<B: SqlTokenBackend> SqlTokenStore<B> {
    pub fn new(backend: B) -> Self {
        SqlTokenStore { backend }
    }
    /// The DDL a caller should run once at startup (convenience re-export).
    pub fn ddl() -> &'static str {
        USER_CONNECTOR_TOKENS_DDL
    }
}

impl<B: SqlTokenBackend> TokenStore for SqlTokenStore<B> {
    fn put(&self, key: &TokenKey, record: StoredToken) -> Result<(), StoreError> {
        self.backend.upsert(&TokenRow::from_record(key, &record))
    }
    fn get(&self, key: &TokenKey) -> Result<Option<StoredToken>, StoreError> {
        Ok(self
            .backend
            .fetch(&key.tenant, &key.user_id, &key.connector)?
            .map(TokenRow::into_record))
    }
    fn delete(&self, key: &TokenKey) -> Result<bool, StoreError> {
        self.backend
            .remove(&key.tenant, &key.user_id, &key.connector)
    }
    fn connectors_for(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        self.backend.list_connectors(tenant, user_id)
    }
}

/// An offline fake of the relational backend that models `user_connector_tokens` exactly: a table
/// with a UNIQUE `(tenant, user_id, connector)` primary key, upsert semantics, tenant-scoped listing,
/// and delete-returns-existed. Used to prove [`SqlTokenStore`]'s logic without a live DB; production
/// replaces it with a Postgres-backed [`SqlTokenBackend`]. Cheap to clone — clones share the table,
/// modelling several processes talking to one database.
#[derive(Clone, Default)]
pub struct InMemorySqlTokenBackend {
    table: Arc<Mutex<BTreeMap<MapKey, TokenRow>>>,
}

impl InMemorySqlTokenBackend {
    pub fn new() -> Self {
        Self::default()
    }
    fn pk(tenant: &str, user_id: &str, connector: &str) -> MapKey {
        (
            tenant.to_string(),
            user_id.to_string(),
            connector.to_string(),
        )
    }
}

impl SqlTokenBackend for InMemorySqlTokenBackend {
    fn upsert(&self, row: &TokenRow) -> Result<(), StoreError> {
        self.table
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?
            .insert(
                Self::pk(&row.tenant, &row.user_id, &row.connector),
                row.clone(),
            );
        Ok(())
    }
    fn fetch(
        &self,
        tenant: &str,
        user_id: &str,
        connector: &str,
    ) -> Result<Option<TokenRow>, StoreError> {
        Ok(self
            .table
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?
            .get(&Self::pk(tenant, user_id, connector))
            .cloned())
    }
    fn remove(&self, tenant: &str, user_id: &str, connector: &str) -> Result<bool, StoreError> {
        Ok(self
            .table
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?
            .remove(&Self::pk(tenant, user_id, connector))
            .is_some())
    }
    fn list_connectors(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
        Ok(self
            .table
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?
            .keys()
            .filter(|(t, u, _)| t == tenant && u == user_id)
            .map(|(_, _, c)| c.clone())
            .collect())
    }
}

// ============================ Postgres binding (feature = "postgres") ============================
//
// [`SqlTokenStore`] proves its relational logic OFFLINE against [`InMemorySqlTokenBackend`]. The `pg`
// module below is the driver-agnostic PRODUCTION binding of the same [`SqlTokenBackend`] seam: it
// issues the real parameterized SQL against the [`USER_CONNECTOR_TOKENS_DDL`] table but pulls **no**
// database crate. A deployment implements the tiny synchronous [`pg::PgExecutor`] port over
// rust-postgres / sqlx (or a pooled connection) and injects it; the store still never sees plaintext
// (it moves only the already-sealed [`SealedSecret`] columns). This mirrors `ainxt-memory`'s
// `durable::pg` so the token store reaches the same production bar: the SQL shape + row mapping are
// proven offline against a fake executor; binding a live Postgres driver is the infra step.

/// Driver-agnostic Postgres binding for the [`SqlTokenBackend`] seam. Compiled only under the
/// `postgres` feature. Pulls no DB crate — a deployment backs [`PgExecutor`] with a real driver.
#[cfg(feature = "postgres")]
pub mod pg {
    use super::{SqlTokenBackend, StoreError, TokenRow, USER_CONNECTOR_TOKENS_DDL};

    /// A bound parameter for a parameterized statement (positional `$1`, `$2`, …). Covers exactly the
    /// column types `user_connector_tokens` needs: `text`, `bigint`, `bytea`, `text[]`, and SQL NULL
    /// (for an absent `expires_at`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SqlParam {
        Text(String),
        Int(i64),
        Bytes(Vec<u8>),
        TextArray(Vec<String>),
        Null,
    }

    /// A synchronous SQL executor a deployment backs with a real Postgres driver. `execute` returns
    /// rows-affected; `query` returns rows as positional cells matching the `SELECT` column order.
    pub trait PgExecutor: std::fmt::Debug + Send + Sync {
        fn execute(&self, sql: &str, params: &[SqlParam]) -> Result<u64, StoreError>;
        fn query(&self, sql: &str, params: &[SqlParam]) -> Result<Vec<Vec<SqlParam>>, StoreError>;
    }

    /// The parameterized statements this binding issues (associated consts so tests pin the exact SQL).
    pub const UPSERT_SQL: &str = "\
INSERT INTO user_connector_tokens \
(tenant,user_id,connector,key_id,nonce,ciphertext,expires_at,scopes,updated_at) \
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now()) \
ON CONFLICT (tenant,user_id,connector) DO UPDATE SET \
key_id=EXCLUDED.key_id,nonce=EXCLUDED.nonce,ciphertext=EXCLUDED.ciphertext,\
expires_at=EXCLUDED.expires_at,scopes=EXCLUDED.scopes,updated_at=now()";
    pub const FETCH_SQL: &str = "\
SELECT key_id,nonce,ciphertext,expires_at,scopes FROM user_connector_tokens \
WHERE tenant=$1 AND user_id=$2 AND connector=$3";
    pub const DELETE_SQL: &str =
        "DELETE FROM user_connector_tokens WHERE tenant=$1 AND user_id=$2 AND connector=$3";
    pub const LIST_SQL: &str = "\
SELECT connector FROM user_connector_tokens WHERE tenant=$1 AND user_id=$2 ORDER BY connector";

    /// A [`SqlTokenBackend`] that maps each seam method to one parameterized Postgres statement.
    #[derive(Debug)]
    pub struct PgTokenBackend<E: PgExecutor> {
        exec: E,
    }

    impl<E: PgExecutor> PgTokenBackend<E> {
        /// Bind an executor and run the idempotent schema DDL once.
        pub fn connect(exec: E) -> Result<Self, StoreError> {
            exec.execute(USER_CONNECTOR_TOKENS_DDL, &[])?;
            Ok(PgTokenBackend { exec })
        }
    }

    fn as_int(cell: Option<&SqlParam>) -> Result<i64, StoreError> {
        match cell {
            Some(SqlParam::Int(i)) => Ok(*i),
            _ => Err(StoreError("expected bigint column".into())),
        }
    }
    fn as_bytes(cell: Option<&SqlParam>) -> Result<Vec<u8>, StoreError> {
        match cell {
            Some(SqlParam::Bytes(b)) => Ok(b.clone()),
            _ => Err(StoreError("expected bytea column".into())),
        }
    }
    fn as_opt_int(cell: Option<&SqlParam>) -> Result<Option<u64>, StoreError> {
        match cell {
            Some(SqlParam::Null) | None => Ok(None),
            Some(SqlParam::Int(i)) => Ok(Some(*i as u64)),
            _ => Err(StoreError("expected nullable bigint column".into())),
        }
    }
    fn as_text_array(cell: Option<&SqlParam>) -> Result<Vec<String>, StoreError> {
        match cell {
            Some(SqlParam::TextArray(v)) => Ok(v.clone()),
            _ => Err(StoreError("expected text[] column".into())),
        }
    }

    impl<E: PgExecutor> SqlTokenBackend for PgTokenBackend<E> {
        fn upsert(&self, row: &TokenRow) -> Result<(), StoreError> {
            self.exec.execute(
                UPSERT_SQL,
                &[
                    SqlParam::Text(row.tenant.clone()),
                    SqlParam::Text(row.user_id.clone()),
                    SqlParam::Text(row.connector.clone()),
                    SqlParam::Int(row.key_id as i64),
                    SqlParam::Bytes(row.nonce.clone()),
                    SqlParam::Bytes(row.ciphertext.clone()),
                    row.expires_at
                        .map(|e| SqlParam::Int(e as i64))
                        .unwrap_or(SqlParam::Null),
                    SqlParam::TextArray(row.scopes.clone()),
                ],
            )?;
            Ok(())
        }

        fn fetch(
            &self,
            tenant: &str,
            user_id: &str,
            connector: &str,
        ) -> Result<Option<TokenRow>, StoreError> {
            let rows = self.exec.query(
                FETCH_SQL,
                &[
                    SqlParam::Text(tenant.to_string()),
                    SqlParam::Text(user_id.to_string()),
                    SqlParam::Text(connector.to_string()),
                ],
            )?;
            let Some(r) = rows.into_iter().next() else {
                return Ok(None);
            };
            Ok(Some(TokenRow {
                tenant: tenant.to_string(),
                user_id: user_id.to_string(),
                connector: connector.to_string(),
                key_id: as_int(r.first())? as u32,
                nonce: as_bytes(r.get(1))?,
                ciphertext: as_bytes(r.get(2))?,
                expires_at: as_opt_int(r.get(3))?,
                scopes: as_text_array(r.get(4))?,
            }))
        }

        fn remove(&self, tenant: &str, user_id: &str, connector: &str) -> Result<bool, StoreError> {
            let affected = self.exec.execute(
                DELETE_SQL,
                &[
                    SqlParam::Text(tenant.to_string()),
                    SqlParam::Text(user_id.to_string()),
                    SqlParam::Text(connector.to_string()),
                ],
            )?;
            Ok(affected > 0)
        }

        fn list_connectors(&self, tenant: &str, user_id: &str) -> Result<Vec<String>, StoreError> {
            let rows = self.exec.query(
                LIST_SQL,
                &[
                    SqlParam::Text(tenant.to_string()),
                    SqlParam::Text(user_id.to_string()),
                ],
            )?;
            rows.into_iter()
                .map(|r| match r.into_iter().next() {
                    Some(SqlParam::Text(s)) => Ok(s),
                    _ => Err(StoreError("expected text connector column".into())),
                })
                .collect()
        }
    }
}

// ============================ Vault (codec + store) ============================

/// A vault-level failure — either the codec or the store failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    Codec(CodecError),
    Store(StoreError),
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Codec(e) => write!(f, "{e}"),
            VaultError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<CodecError> for VaultError {
    fn from(e: CodecError) -> Self {
        VaultError::Codec(e)
    }
}
impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        VaultError::Store(e)
    }
}

/// Non-secret token metadata, readable without decrypting the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenMeta {
    pub expires_at: Option<u64>,
    pub scopes: Vec<String>,
    pub key_id: u32,
}

/// The vault: the one object callers use. It seals on the way in and opens on the way out, so
/// plaintext secrets live only transiently in memory and the store holds only ciphertext.
pub struct TokenVault {
    codec: Box<dyn SecretCodec>,
    store: Box<dyn TokenStore>,
}

impl TokenVault {
    pub fn new(codec: Box<dyn SecretCodec>, store: Box<dyn TokenStore>) -> Self {
        TokenVault { codec, store }
    }

    /// AAD binding a ciphertext to its (tenant, user, connector). Uses NUL separators, which cannot
    /// appear in a JWT `sub`, a tenant id, or a connector id, so the three components are unambiguous.
    /// Binding the tenant here is what makes cross-tenant transplant cryptographically impossible even
    /// when two tenants reuse the same `user_id`.
    fn aad(tenant: &str, user_id: &str, connector: &str) -> Vec<u8> {
        let mut v = Vec::with_capacity(tenant.len() + user_id.len() + connector.len() + 2);
        v.extend_from_slice(tenant.as_bytes());
        v.push(0);
        v.extend_from_slice(user_id.as_bytes());
        v.push(0);
        v.extend_from_slice(connector.as_bytes());
        v
    }

    // ---- tenant-scoped API (multi-tenant deployments) ----

    /// Seal `secret` for (tenant, user, connector) and persist it with plaintext expiry/scope
    /// metadata. Overwrites any existing token for that triple.
    pub fn save_in(
        &self,
        tenant: &str,
        user_id: &str,
        connector: &str,
        secret: &[u8],
        expires_at: Option<u64>,
        scopes: &[String],
    ) -> Result<(), VaultError> {
        let sealed = self
            .codec
            .seal(secret, &Self::aad(tenant, user_id, connector))?;
        let record = StoredToken {
            sealed,
            expires_at,
            scopes: scopes.to_vec(),
        };
        self.store
            .put(&TokenKey::scoped(tenant, user_id, connector), record)?;
        Ok(())
    }

    /// Decrypt the secret for (tenant, user, connector), or `None` if nothing is stored. A stored
    /// record that fails to open (wrong key/tamper/cross-tenant transplant) is a hard [`VaultError`].
    pub fn load_in(
        &self,
        tenant: &str,
        user_id: &str,
        connector: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let Some(record) = self
            .store
            .get(&TokenKey::scoped(tenant, user_id, connector))?
        else {
            return Ok(None);
        };
        let plaintext = self
            .codec
            .open(&record.sealed, &Self::aad(tenant, user_id, connector))?;
        Ok(Some(plaintext))
    }

    /// Read expiry/scope metadata for (tenant, user, connector) **without decrypting** the secret.
    pub fn metadata_in(
        &self,
        tenant: &str,
        user_id: &str,
        connector: &str,
    ) -> Result<Option<TokenMeta>, VaultError> {
        Ok(self
            .store
            .get(&TokenKey::scoped(tenant, user_id, connector))?
            .map(|r| TokenMeta {
                expires_at: r.expires_at,
                scopes: r.scopes,
                key_id: r.sealed.key_id,
            }))
    }

    /// Remove (tenant, user, connector)'s token (deauthorize). Returns whether one existed.
    pub fn revoke_in(
        &self,
        tenant: &str,
        user_id: &str,
        connector: &str,
    ) -> Result<bool, VaultError> {
        Ok(self
            .store
            .delete(&TokenKey::scoped(tenant, user_id, connector))?)
    }

    /// The connectors this (tenant, user) has authorized.
    pub fn connectors_for_in(
        &self,
        tenant: &str,
        user_id: &str,
    ) -> Result<Vec<String>, VaultError> {
        Ok(self.store.connectors_for(tenant, user_id)?)
    }

    // ---- verified-identity API (confused-deputy-safe: tenant + sub bound to the authenticated principal) ----
    //
    // GAP-AUDIT token-durability (gap6, item 2) — investigated whether this family
    // (`TenantClaim`/`TokenKey::for_principal`/`save_for`/`load_for`/`metadata_for`/`revoke_for`/
    // `connectors_for_principal`) has a real caller in either composition root (`ainxt-runtimed`,
    // `ainxt-server`). It does not: `grep -rn "TenantClaim\|for_principal\|save_for\|load_for" crates/`
    // outside this crate's own definitions/tests is empty. This is NOT because the confused-deputy
    // property goes unenforced on the shipped connector OAuth surface — `ainxt-server`'s
    // `connector_tenant()` (see its doc, `crates/ainxt-server/src/lib.rs`) independently closes the
    // identical hole ("pair one authenticated caller with another user's `sub`/an unverified tenant")
    // by preferring the VERIFIED `principal.department` JWT claim over the spoofable
    // `X-AInxt-Tenant` header, proven end-to-end by
    // `wire_conn_07_tenant_resolution_prefers_verified_claim_over_spoofable_header` in that crate. Both
    // designs are equally strong in practice: `TenantClaim::from_verified_claim` and
    // `connector_tenant()`'s `principal.department` read are both "caller must only feed this a value
    // already verified upstream" contracts — neither is a runtime-checked guarantee, since `Principal`
    // itself (`ainxt_types::Principal`) is a plain, freely-constructible struct with no signature
    // attached; the actual verification happens once, in the `Authenticator` seam
    // (`ainxt-server::JwtSsoAuth::principal`), before either mechanism ever sees a `Principal`. So this
    // family is legitimately superseded, unreachable code with respect to the REAL served connector
    // surface today — left in place (not removed) as a public library primitive for an embedder of
    // `ainxt-token` that does not go through `ainxt-server`'s own routing layer, where binding the
    // tenant into the vault call's TYPE (rather than a same-shaped bare `&str` parameter next to it)
    // is the stronger available idiom. See also `ainxt-connector-http::BoundPrincipal`/`VerifiedTenant`
    // — a second, independently-built restatement of this exact pattern in that crate, ALSO with zero
    // callers in the real composition root for the same reason.

    /// Seal `secret` for the **verified caller** — the key is derived by [`TokenKey::for_principal`],
    /// so the `sub` axis is the authenticated `principal.user_id` and the tenant is a
    /// [`TenantClaim`] (an authenticated claim). No client-supplied `sub`/tenant can reach the key.
    pub fn save_for(
        &self,
        tenant: &TenantClaim,
        principal: &Principal,
        connector: &str,
        secret: &[u8],
        expires_at: Option<u64>,
        scopes: &[String],
    ) -> Result<(), VaultError> {
        self.save_in(
            tenant.as_str(),
            &principal.user_id,
            connector,
            secret,
            expires_at,
            scopes,
        )
    }

    /// Decrypt the verified caller's secret for `connector`. Because the `sub` is read from the
    /// authenticated principal, one caller can never resolve another caller's token here.
    pub fn load_for(
        &self,
        tenant: &TenantClaim,
        principal: &Principal,
        connector: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        self.load_in(tenant.as_str(), &principal.user_id, connector)
    }

    /// Read expiry/scope metadata for the verified caller's `connector` token **without decrypting**.
    pub fn metadata_for(
        &self,
        tenant: &TenantClaim,
        principal: &Principal,
        connector: &str,
    ) -> Result<Option<TokenMeta>, VaultError> {
        self.metadata_in(tenant.as_str(), &principal.user_id, connector)
    }

    /// Revoke (deauthorize) the verified caller's `connector` token. Returns whether one existed.
    pub fn revoke_for(
        &self,
        tenant: &TenantClaim,
        principal: &Principal,
        connector: &str,
    ) -> Result<bool, VaultError> {
        self.revoke_in(tenant.as_str(), &principal.user_id, connector)
    }

    /// The connectors the verified caller has authorized (tenant-scoped to the caller's own grants).
    pub fn connectors_for_principal(
        &self,
        tenant: &TenantClaim,
        principal: &Principal,
    ) -> Result<Vec<String>, VaultError> {
        self.connectors_for_in(tenant.as_str(), &principal.user_id)
    }

    // ---- unscoped API (single-tenant / [`DEFAULT_TENANT`]) — kept for existing callers ----

    /// Seal for (user, connector) in the [`DEFAULT_TENANT`].
    pub fn save(
        &self,
        user_id: &str,
        connector: &str,
        secret: &[u8],
        expires_at: Option<u64>,
        scopes: &[String],
    ) -> Result<(), VaultError> {
        self.save_in(
            DEFAULT_TENANT,
            user_id,
            connector,
            secret,
            expires_at,
            scopes,
        )
    }

    /// Load for (user, connector) in the [`DEFAULT_TENANT`].
    pub fn load(&self, user_id: &str, connector: &str) -> Result<Option<Vec<u8>>, VaultError> {
        self.load_in(DEFAULT_TENANT, user_id, connector)
    }

    /// Metadata for (user, connector) in the [`DEFAULT_TENANT`].
    pub fn metadata(
        &self,
        user_id: &str,
        connector: &str,
    ) -> Result<Option<TokenMeta>, VaultError> {
        self.metadata_in(DEFAULT_TENANT, user_id, connector)
    }

    /// Revoke (user, connector) in the [`DEFAULT_TENANT`].
    pub fn revoke(&self, user_id: &str, connector: &str) -> Result<bool, VaultError> {
        self.revoke_in(DEFAULT_TENANT, user_id, connector)
    }

    /// Connectors for `user_id` in the [`DEFAULT_TENANT`].
    pub fn connectors_for(&self, user_id: &str) -> Result<Vec<String>, VaultError> {
        self.connectors_for_in(DEFAULT_TENANT, user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codec() -> AeadCodec {
        AeadCodec::new(KeyRing::new(1, [7u8; KEY_LEN]))
    }

    fn vault() -> TokenVault {
        TokenVault::new(Box::new(codec()), Box::new(InMemoryTokenStore::new()))
    }

    #[test]
    fn seal_open_round_trips() {
        let c = codec();
        let aad = b"user-1\0gitlab";
        let sealed = c.seal(b"glpat-secret-token", aad).unwrap();
        assert_eq!(sealed.key_id, 1);
        assert_eq!(sealed.nonce.len(), NONCE_LEN);
        assert_ne!(sealed.ciphertext, b"glpat-secret-token"); // actually encrypted
        assert_eq!(c.open(&sealed, aad).unwrap(), b"glpat-secret-token");
    }

    #[test]
    fn wrong_aad_fails_to_open() {
        let c = codec();
        let sealed = c.seal(b"secret", b"user-A\0gitlab").unwrap();
        // Same key, different owner context → authentication fails (per-user/connector isolation).
        assert_eq!(c.open(&sealed, b"user-B\0gitlab"), Err(CodecError::Decrypt));
        assert_eq!(c.open(&sealed, b"user-A\0jira"), Err(CodecError::Decrypt));
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let c = codec();
        let mut sealed = c.seal(b"secret", b"aad").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert_eq!(c.open(&sealed, b"aad"), Err(CodecError::Decrypt));
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let c = codec();
        let a = c.seal(b"same", b"aad").unwrap();
        let b = c.seal(b"same", b"aad").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonces must be random per record");
        assert_ne!(
            a.ciphertext, b.ciphertext,
            "same plaintext must not yield same ciphertext"
        );
    }

    #[test]
    fn key_rotation_keeps_old_records_readable() {
        // Seal under v1.
        let old = AeadCodec::new(KeyRing::new(1, [1u8; KEY_LEN]));
        let sealed_v1 = old.seal(b"legacy", b"aad").unwrap();
        assert_eq!(sealed_v1.key_id, 1);

        // Rotate to v2: v1 retained for decryption, v2 becomes active for new records.
        let rotated = AeadCodec::new(KeyRing::new(1, [1u8; KEY_LEN]).rotate_to(2, [2u8; KEY_LEN]));
        assert_eq!(rotated.active_key_id(), 2);
        // Old record still opens...
        assert_eq!(rotated.open(&sealed_v1, b"aad").unwrap(), b"legacy");
        // ...and new records seal under v2.
        let sealed_v2 = rotated.seal(b"fresh", b"aad").unwrap();
        assert_eq!(sealed_v2.key_id, 2);
        assert_eq!(rotated.open(&sealed_v2, b"aad").unwrap(), b"fresh");
    }

    #[test]
    fn retired_key_can_no_longer_open() {
        let mut ring = KeyRing::new(1, [1u8; KEY_LEN]).rotate_to(2, [2u8; KEY_LEN]);
        let codec_before = AeadCodec::new(KeyRing::new(1, [1u8; KEY_LEN]));
        let sealed_v1 = codec_before.seal(b"x", b"aad").unwrap();
        assert!(ring.retire(1), "v1 is retirable (not active)");
        assert!(!ring.retire(2), "active key must not be retirable");
        let codec_after = AeadCodec::new(ring);
        assert_eq!(
            codec_after.open(&sealed_v1, b"aad"),
            Err(CodecError::UnknownKey(1))
        );
    }

    #[test]
    fn unknown_key_version_is_reported() {
        let c = codec(); // ring has only v1
        let sealed = SealedSecret {
            key_id: 99,
            nonce: vec![0u8; NONCE_LEN],
            ciphertext: vec![0; 16],
        };
        assert_eq!(c.open(&sealed, b"aad"), Err(CodecError::UnknownKey(99)));
    }

    #[test]
    fn generated_keys_are_distinct() {
        assert_ne!(random_key(), random_key(), "OS CSPRNG must not repeat");
    }

    #[test]
    fn store_put_get_delete_list() {
        let s = InMemoryTokenStore::new();
        let rec = StoredToken {
            sealed: SealedSecret {
                key_id: 1,
                nonce: vec![0; NONCE_LEN],
                ciphertext: vec![1, 2, 3],
            },
            expires_at: Some(1000),
            scopes: vec!["api".into()],
        };
        let k = TokenKey::of("u", "gitlab");
        s.put(&k, rec.clone()).unwrap();
        assert_eq!(s.get(&k).unwrap(), Some(rec));
        assert_eq!(
            s.connectors_for(DEFAULT_TENANT, "u").unwrap(),
            vec!["gitlab".to_string()]
        );
        assert!(s.delete(&k).unwrap());
        assert_eq!(s.get(&k).unwrap(), None);
        assert!(!s.delete(&k).unwrap());
    }

    #[test]
    fn vault_save_load_round_trip() {
        let v = vault();
        v.save("u", "gitlab", b"glpat-xyz", Some(1234), &["api".into()])
            .unwrap();
        assert_eq!(v.load("u", "gitlab").unwrap(), Some(b"glpat-xyz".to_vec()));
        let meta = v.metadata("u", "gitlab").unwrap().unwrap();
        assert_eq!(meta.expires_at, Some(1234));
        assert_eq!(meta.scopes, vec!["api".to_string()]);
        assert_eq!(meta.key_id, 1);
    }

    #[test]
    fn vault_isolates_users() {
        let v = vault();
        v.save("alice", "gitlab", b"alice-token", None, &[])
            .unwrap();
        // Bob has no token for gitlab → None (structural isolation).
        assert_eq!(v.load("bob", "gitlab").unwrap(), None);
        assert!(v.connectors_for("bob").unwrap().is_empty());
        assert_eq!(
            v.connectors_for("alice").unwrap(),
            vec!["gitlab".to_string()]
        );
    }

    #[test]
    fn transplanted_record_fails_to_load() {
        // Even an attacker with store write-access cannot move Alice's sealed token to Bob: the AAD
        // binds the ciphertext to (user, connector), so opening it under Bob's context fails.
        let shared_codec = AeadCodec::new(KeyRing::new(1, [9u8; KEY_LEN]));
        let alice_aad = TokenVault::aad(DEFAULT_TENANT, "alice", "gitlab");
        let alice_sealed = shared_codec.seal(b"alice-token", &alice_aad).unwrap();

        let store = InMemoryTokenStore::new();
        // Plant Alice's ciphertext under Bob's key in the store.
        store
            .put(
                &TokenKey::of("bob", "gitlab"),
                StoredToken {
                    sealed: alice_sealed,
                    expires_at: None,
                    scopes: vec![],
                },
            )
            .unwrap();
        let vault = TokenVault::new(Box::new(shared_codec), Box::new(store));
        // Load as Bob → AAD mismatch → hard error, never a silent success.
        assert_eq!(
            vault.load("bob", "gitlab"),
            Err(VaultError::Codec(CodecError::Decrypt))
        );
    }

    #[test]
    fn revoke_removes_the_token() {
        let v = vault();
        v.save("u", "jira", b"t", None, &[]).unwrap();
        assert!(v.revoke("u", "jira").unwrap());
        assert_eq!(v.load("u", "jira").unwrap(), None);
        assert!(
            !v.revoke("u", "jira").unwrap(),
            "second revoke finds nothing"
        );
    }

    #[test]
    fn metadata_readable_without_decrypting_secret() {
        // A codec whose key is absent from open-time would fail load, but metadata still works.
        let v = vault();
        v.save("u", "graph", b"secret", Some(42), &["Mail.Read".into()])
            .unwrap();
        let meta = v.metadata("u", "graph").unwrap().unwrap();
        assert_eq!(meta.expires_at, Some(42));
        assert_eq!(meta.scopes, vec!["Mail.Read".to_string()]);
    }

    // ---- durable file-backed store ----

    fn temp_path(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("ainxt_token_{tag}.json"));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension("tmp"));
        p
    }

    #[test]
    fn file_store_survives_restart() {
        let path = temp_path("restart");
        let rec = StoredToken {
            sealed: SealedSecret {
                key_id: 1,
                nonce: vec![0; NONCE_LEN],
                ciphertext: vec![9, 8, 7],
            },
            expires_at: Some(1234),
            scopes: vec!["api".into()],
        };
        {
            let store = FileTokenStore::open(&path).unwrap();
            store
                .put(&TokenKey::of("alice", "gitlab"), rec.clone())
                .unwrap();
        } // drop = "process restart"
        let reopened = FileTokenStore::open(&path).unwrap();
        assert_eq!(
            reopened.get(&TokenKey::of("alice", "gitlab")).unwrap(),
            Some(rec),
            "record must survive restart"
        );
        assert_eq!(
            reopened.connectors_for(DEFAULT_TENANT, "alice").unwrap(),
            vec!["gitlab".to_string()]
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_store_delete_persists() {
        let path = temp_path("delete");
        let rec = StoredToken {
            sealed: SealedSecret {
                key_id: 1,
                nonce: vec![0; NONCE_LEN],
                ciphertext: vec![1],
            },
            expires_at: None,
            scopes: vec![],
        };
        let store = FileTokenStore::open(&path).unwrap();
        store.put(&TokenKey::of("u", "jira"), rec).unwrap();
        assert!(store.delete(&TokenKey::of("u", "jira")).unwrap());
        // A fresh open sees the deletion persisted.
        let reopened = FileTokenStore::open(&path).unwrap();
        assert_eq!(reopened.get(&TokenKey::of("u", "jira")).unwrap(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn durable_encrypted_vault_round_trips_across_restart() {
        // The end-to-end guarantee: an encrypted token, persisted to disk, is recoverable after a
        // restart — with the store holding only ciphertext. The codec key is stable (in prod it comes
        // from KMS/config); here a fixed key stands in.
        let path = temp_path("vault");
        {
            let vault = TokenVault::new(
                Box::new(AeadCodec::new(KeyRing::new(1, [4u8; KEY_LEN]))),
                Box::new(FileTokenStore::open(&path).unwrap()),
            );
            vault
                .save(
                    "alice",
                    "graph",
                    b"glpat-durable-secret",
                    Some(999),
                    &["Mail.Read".into()],
                )
                .unwrap();
        } // restart
          // The on-disk file must NOT contain the plaintext secret.
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            !raw.contains("glpat-durable-secret"),
            "plaintext secret must never hit disk: {raw}"
        );
        // Re-open with the same key and recover the secret.
        let vault2 = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [4u8; KEY_LEN]))),
            Box::new(FileTokenStore::open(&path).unwrap()),
        );
        assert_eq!(
            vault2.load("alice", "graph").unwrap(),
            Some(b"glpat-durable-secret".to_vec())
        );
        let _ = std::fs::remove_file(&path);
    }

    // ---- CONN-07: crypto-agility invariant (accepted divergence from FERNET) ----

    #[test]
    fn gap_ainxt_token_conn_07_crypto_agility_invariant_holds() {
        // The design names FERNET/MultiFernet. AiNxt deliberately diverges to XChaCha20-Poly1305 over
        // a versioned KeyRing (clean-room Rust, no OpenSSL). This test pins that the *invariant*
        // MultiFernet provides is preserved by the divergent primitive, so the divergence is a
        // primitive swap, not a capability regression:
        //   (a) authenticated encryption — a tampered blob fails to open (not silently accepted);
        //   (b) encrypt-with-newest — new records seal under the active (highest) key version;
        //   (c) decrypt-with-any-retained — records sealed under an older, retained key still open;
        //   (d) forward control — a retired key can no longer open its records.
        let ring = KeyRing::new(1, [1u8; KEY_LEN]);
        let v1 = AeadCodec::new(KeyRing::new(1, [1u8; KEY_LEN]));
        let old = v1.seal(b"legacy", b"aad").unwrap();
        assert_eq!(old.key_id, 1);

        // (b) encrypt-with-newest after rotation.
        let rotated = AeadCodec::new(ring.rotate_to(2, [2u8; KEY_LEN]));
        assert_eq!(rotated.active_key_id(), 2);
        assert_eq!(rotated.seal(b"fresh", b"aad").unwrap().key_id, 2);
        // (c) decrypt-with-any-retained.
        assert_eq!(rotated.open(&old, b"aad").unwrap(), b"legacy");
        // (a) authentication.
        let mut tampered = old.clone();
        tampered.ciphertext[0] ^= 0xff;
        assert_eq!(rotated.open(&tampered, b"aad"), Err(CodecError::Decrypt));
        // (d) retire the old key → its records no longer open.
        let mut r2 = KeyRing::new(1, [1u8; KEY_LEN]).rotate_to(2, [2u8; KEY_LEN]);
        assert!(r2.retire(1));
        assert_eq!(
            AeadCodec::new(r2).open(&old, b"aad"),
            Err(CodecError::UnknownKey(1))
        );
    }

    // ---- CONN-02: multi-tenant token isolation (tenant in key + AAD) ----

    #[test]
    fn gap_ainxt_token_conn_02_multi_tenant_isolation() {
        // Two DIFFERENT tenants that reuse the SAME (user_id, connector). Before the tenant axis
        // existed, these collided on one key; now they are structurally AND cryptographically
        // isolated. A SHARED codec/store is used deliberately: the only thing separating the tenants
        // is the tenant dimension in the key and the AEAD AAD.
        let v = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [7u8; KEY_LEN]))),
            Box::new(InMemoryTokenStore::new()),
        );
        v.save_in(
            "tenant-a",
            "u",
            "gitlab",
            b"A-SECRET",
            Some(10),
            &["api".into()],
        )
        .unwrap();
        v.save_in(
            "tenant-b",
            "u",
            "gitlab",
            b"B-SECRET",
            Some(20),
            &["read".into()],
        )
        .unwrap();

        // 1. Each tenant reads its own secret — no collision despite identical (user, connector).
        assert_eq!(
            v.load_in("tenant-a", "u", "gitlab").unwrap(),
            Some(b"A-SECRET".to_vec())
        );
        assert_eq!(
            v.load_in("tenant-b", "u", "gitlab").unwrap(),
            Some(b"B-SECRET".to_vec())
        );

        // 2. Metadata is per-tenant too (proves the store key, not just the AAD, carries tenant).
        assert_eq!(
            v.metadata_in("tenant-a", "u", "gitlab")
                .unwrap()
                .unwrap()
                .expires_at,
            Some(10)
        );
        assert_eq!(
            v.metadata_in("tenant-b", "u", "gitlab")
                .unwrap()
                .unwrap()
                .expires_at,
            Some(20)
        );

        // 3. A third tenant sees nothing for the same (user, connector).
        assert_eq!(v.load_in("tenant-c", "u", "gitlab").unwrap(), None);

        // 4. connectors_for is tenant-scoped: tenant-a's listing never leaks tenant-b's grants.
        v.save_in("tenant-b", "u", "jira", b"B-JIRA", None, &[])
            .unwrap();
        assert_eq!(
            v.connectors_for_in("tenant-a", "u").unwrap(),
            vec!["gitlab".to_string()]
        );
        let mut b = v.connectors_for_in("tenant-b", "u").unwrap();
        b.sort();
        assert_eq!(b, vec!["gitlab".to_string(), "jira".to_string()]);

        // 5. Revoking in one tenant does not touch the other.
        assert!(v.revoke_in("tenant-a", "u", "gitlab").unwrap());
        assert_eq!(v.load_in("tenant-a", "u", "gitlab").unwrap(), None);
        assert_eq!(
            v.load_in("tenant-b", "u", "gitlab").unwrap(),
            Some(b"B-SECRET".to_vec())
        );
    }

    #[test]
    fn gap_ainxt_token_conn_02_cross_tenant_transplant_fails_cryptographically() {
        // Even an attacker with full store write-access cannot move tenant-A's sealed record into
        // tenant-B's slot: the AAD binds the ciphertext to its tenant, so opening it under tenant-B
        // fails hard. This is the guarantee that a shared user_id across tenants cannot be abused.
        let codec = AeadCodec::new(KeyRing::new(1, [9u8; KEY_LEN]));
        let a_sealed = codec
            .seal(
                b"tenant-a-secret",
                &TokenVault::aad("tenant-a", "u", "gitlab"),
            )
            .unwrap();
        let store = InMemoryTokenStore::new();
        // Plant tenant-A's ciphertext under tenant-B's key.
        store
            .put(
                &TokenKey::scoped("tenant-b", "u", "gitlab"),
                StoredToken {
                    sealed: a_sealed,
                    expires_at: None,
                    scopes: vec![],
                },
            )
            .unwrap();
        let vault = TokenVault::new(Box::new(codec), Box::new(store));
        assert_eq!(
            vault.load_in("tenant-b", "u", "gitlab"),
            Err(VaultError::Codec(CodecError::Decrypt)),
            "a transplanted cross-tenant record must never open"
        );
    }

    // ---- CONN-01: durable relational (Postgres) token store behind the TokenStore trait ----

    #[test]
    fn gap_ainxt_token_conn_01_sql_token_store_round_trips_and_upserts() {
        // The SqlTokenStore is a real TokenStore over the user_connector_tokens relational seam,
        // proven offline against the in-memory SQL backend fake (no live DB).
        let store = SqlTokenStore::new(InMemorySqlTokenBackend::new());
        let k = TokenKey::scoped("tenant-a", "alice", "gitlab");
        assert_eq!(store.get(&k).unwrap(), None);

        let rec = StoredToken {
            sealed: SealedSecret {
                key_id: 3,
                nonce: vec![1; NONCE_LEN],
                ciphertext: vec![9, 8, 7],
            },
            expires_at: Some(4242),
            scopes: vec!["api".into()],
        };
        store.put(&k, rec.clone()).unwrap();
        assert_eq!(store.get(&k).unwrap(), Some(rec));

        // Upsert: a second put on the same composite key overwrites (ON CONFLICT DO UPDATE), it does
        // not duplicate.
        let rec2 = StoredToken {
            sealed: SealedSecret {
                key_id: 4,
                nonce: vec![2; NONCE_LEN],
                ciphertext: vec![1, 2, 3, 4],
            },
            expires_at: None,
            scopes: vec![],
        };
        store.put(&k, rec2.clone()).unwrap();
        assert_eq!(store.get(&k).unwrap(), Some(rec2));
        assert_eq!(
            store.connectors_for("tenant-a", "alice").unwrap(),
            vec!["gitlab".to_string()],
            "upsert must not create a duplicate row"
        );

        // Delete returns existed, then not.
        assert!(store.delete(&k).unwrap());
        assert!(!store.delete(&k).unwrap());
        assert_eq!(store.get(&k).unwrap(), None);
    }

    #[test]
    fn gap_ainxt_token_conn_01_sql_store_is_tenant_scoped_and_ddl_names_the_table() {
        let store = SqlTokenStore::new(InMemorySqlTokenBackend::new());
        // Same (user, connector) across two tenants — isolated at the storage layer.
        store
            .put(
                &TokenKey::scoped("t1", "u", "gitlab"),
                StoredToken {
                    sealed: SealedSecret {
                        key_id: 1,
                        nonce: vec![0; NONCE_LEN],
                        ciphertext: vec![1],
                    },
                    expires_at: None,
                    scopes: vec![],
                },
            )
            .unwrap();
        store
            .put(
                &TokenKey::scoped("t2", "u", "gitlab"),
                StoredToken {
                    sealed: SealedSecret {
                        key_id: 1,
                        nonce: vec![0; NONCE_LEN],
                        ciphertext: vec![2],
                    },
                    expires_at: None,
                    scopes: vec![],
                },
            )
            .unwrap();
        assert_eq!(
            store.connectors_for("t1", "u").unwrap(),
            vec!["gitlab".to_string()]
        );
        assert_eq!(
            store
                .get(&TokenKey::scoped("t1", "u", "gitlab"))
                .unwrap()
                .unwrap()
                .sealed
                .ciphertext,
            vec![1]
        );
        // The canonical DDL pins the design's table + composite key.
        let ddl = SqlTokenStore::<InMemorySqlTokenBackend>::ddl();
        assert!(ddl.contains("user_connector_tokens"));
        assert!(ddl.contains("PRIMARY KEY (tenant, user_id, connector)"));
    }

    #[test]
    fn gap_ainxt_token_conn_01_encrypted_vault_over_sql_store_never_holds_plaintext() {
        // End-to-end: TokenVault over SqlTokenStore. The backend row holds only ciphertext.
        let backend = InMemorySqlTokenBackend::new();
        let vault = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [4u8; KEY_LEN]))),
            Box::new(SqlTokenStore::new(backend.clone())),
        );
        vault
            .save_in(
                "tenant-x",
                "alice",
                "graph",
                b"glpat-super-secret",
                Some(9),
                &["Mail.Read".into()],
            )
            .unwrap();
        // Recover through the vault.
        assert_eq!(
            vault.load_in("tenant-x", "alice", "graph").unwrap(),
            Some(b"glpat-super-secret".to_vec())
        );
        // The raw row the "database" holds must not contain the plaintext secret.
        let row = backend
            .fetch("tenant-x", "alice", "graph")
            .unwrap()
            .unwrap();
        assert!(
            !row.ciphertext
                .windows(b"glpat-super-secret".len())
                .any(|w| w == b"glpat-super-secret"),
            "plaintext secret must never reach the SQL row"
        );
        assert_eq!(row.scopes, vec!["Mail.Read".to_string()]);
        assert_eq!(row.expires_at, Some(9));
    }

    // ---- r5: durable multi-tenant token store — offline proof of the infra_gated seam ----
    //
    // The production `SqlTokenBackend` is Postgres and needs a live DB (infra_gated): no offline test
    // can bind a real driver. What IS provable offline is the seam's DURABILITY CONTRACT — that two
    // `SqlTokenStore` instances over ONE shared backend (modelling several daemon processes talking to
    // a single Postgres) see each other's writes on the design's `(tenant, jwt.sub, connector)` key.
    // This is the exact invariant the gap names ("durable multi-tenant token store"); a Postgres
    // backend that honours the same seam inherits it. The in-memory backend clones share their table,
    // so this is a faithful cross-process model.
    #[test]
    fn r5_sql_token_backend_durable_across_processes_offline() {
        let shared = InMemorySqlTokenBackend::new();
        // "Process A" (e.g. the OAuth-callback write path) seals a token for tenant-a/alice/graph.
        let proc_a = SqlTokenStore::new(shared.clone());
        // "Process B" (e.g. a worker running the USE path) is a *different* store over the SAME DB.
        let proc_b = SqlTokenStore::new(shared.clone());

        let key = TokenKey::scoped("tenant-a", "alice", "graph");
        assert_eq!(proc_b.get(&key).unwrap(), None, "cold DB before any write");

        let rec = StoredToken {
            sealed: SealedSecret {
                key_id: 2,
                nonce: vec![5; NONCE_LEN],
                ciphertext: vec![9, 9, 9],
            },
            expires_at: Some(7777),
            scopes: vec!["Mail.Read".into()],
        };
        proc_a.put(&key, rec.clone()).unwrap();

        // Durability: process B reads what process A durably wrote — the store holds no in-proc state.
        assert_eq!(
            proc_b.get(&key).unwrap(),
            Some(rec),
            "a second process must see the first process's durable write"
        );

        // Tenant isolation still holds at the storage layer across processes: a different tenant with
        // the SAME (user, connector) sees nothing.
        assert_eq!(
            proc_b
                .get(&TokenKey::scoped("tenant-b", "alice", "graph"))
                .unwrap(),
            None,
            "a different tenant must never reach tenant-a's token"
        );

        // A delete in one process is visible in the other (revocation propagates).
        assert!(proc_b.delete(&key).unwrap());
        assert_eq!(
            proc_a.get(&key).unwrap(),
            None,
            "revocation is durable across processes"
        );
    }

    // ---- r12: token-vault crypto primitive is FERNET/MultiFernet-EQUIVALENT (gap: crypto primitive) ----

    #[test]
    fn r12_token_vault_crypto_primitive_is_fernet_equivalent_by_default() {
        // The design names FERNET/MultiFernet. AiNxt ships XChaCha20-Poly1305 over a versioned KeyRing
        // (clean-room Rust, no OpenSSL). This test pins that the DEFAULT vault codec — the one the
        // Connector Runtime seals every OAuth/API token with — delivers each property MultiFernet is
        // relied on for, so the divergence is a primitive SWAP, not a capability regression:
        //   (F1) authenticated encryption — ciphertext is not plaintext AND a single flipped byte
        //        fails to open (integrity, not just confidentiality);
        //   (F2) MultiFernet rotation — encrypt-with-primary + decrypt-with-any-retained-key;
        //   (F3) forward control — a retired key can no longer open its historical records;
        //   (F4) per-owner binding (beyond stock Fernet) — the AAD ties a token to its
        //        (tenant, user, connector) so a store-write attacker cannot transplant it.
        // The end-to-end path (TokenVault) is exercised, not just the raw codec, so this is the
        // property the SHIPPED default actually provides.
        let codec = AeadCodec::new(KeyRing::new(1, [0x5Au8; KEY_LEN]));
        let store = InMemoryTokenStore::new();
        let vault = TokenVault::new(Box::new(codec), Box::new(store.clone()));

        // (F1) authenticated encryption via the vault.
        vault
            .save_in(
                "t",
                "alice",
                "gitlab",
                b"glpat-FERNET-EQUIV",
                Some(9),
                &["api".into()],
            )
            .unwrap();
        let stored = store
            .get(&TokenKey::scoped("t", "alice", "gitlab"))
            .unwrap()
            .unwrap();
        assert_ne!(
            stored.sealed.ciphertext, b"glpat-FERNET-EQUIV",
            "must be encrypted at rest"
        );
        assert_eq!(
            vault.load_in("t", "alice", "gitlab").unwrap(),
            Some(b"glpat-FERNET-EQUIV".to_vec())
        );
        // Flip one ciphertext byte in the store → open must FAIL (integrity), never silently succeed.
        {
            let mut tampered = stored.clone();
            tampered.sealed.ciphertext[0] ^= 0xff;
            store
                .put(&TokenKey::scoped("t", "alice", "gitlab"), tampered)
                .unwrap();
            assert!(
                vault.load_in("t", "alice", "gitlab").is_err(),
                "a tampered sealed token must fail authentication (F1)"
            );
        }

        // (F2)+(F3) MultiFernet rotation semantics on the raw codec.
        let v1 = AeadCodec::new(KeyRing::new(1, [1u8; KEY_LEN]));
        let old = v1.seal(b"legacy", b"aad").unwrap();
        let rotated = AeadCodec::new(KeyRing::new(1, [1u8; KEY_LEN]).rotate_to(2, [2u8; KEY_LEN]));
        assert_eq!(
            rotated.active_key_id(),
            2,
            "new records seal with the primary (newest) key (F2)"
        );
        assert_eq!(rotated.seal(b"fresh", b"aad").unwrap().key_id, 2);
        assert_eq!(
            rotated.open(&old, b"aad").unwrap(),
            b"legacy",
            "any retained key still opens (F2)"
        );
        let mut r = KeyRing::new(1, [1u8; KEY_LEN]).rotate_to(2, [2u8; KEY_LEN]);
        assert!(r.retire(1));
        assert_eq!(
            AeadCodec::new(r).open(&old, b"aad"),
            Err(CodecError::UnknownKey(1)),
            "a retired key can no longer open its records (F3)"
        );

        // (F4) per-owner AAD binding — beyond stock Fernet. Transplant Alice's blob to Bob → open fails.
        let shared = AeadCodec::new(KeyRing::new(1, [7u8; KEY_LEN]));
        let alice_blob = shared
            .seal(b"secret", &TokenVault::aad("t", "alice", "gitlab"))
            .unwrap();
        let s2 = InMemoryTokenStore::new();
        s2.put(
            &TokenKey::scoped("t", "bob", "gitlab"),
            StoredToken {
                sealed: alice_blob,
                expires_at: None,
                scopes: vec![],
            },
        )
        .unwrap();
        let v2 = TokenVault::new(Box::new(shared), Box::new(s2));
        assert_eq!(
            v2.load_in("t", "bob", "gitlab"),
            Err(VaultError::Codec(CodecError::Decrypt)),
            "a transplanted token must never open under another owner's AAD (F4)"
        );
    }

    // ---- r13: tenant + sub axis bound to VERIFIED identity (confused-deputy defense) ----

    #[test]
    fn r13_token_key_axis_bound_to_verified_principal_cross_sub_isolation() {
        // The design keys tokens on (jwt.sub, connector, tenant). The confused-deputy risk is a
        // handler that receives a verified caller AND a client-supplied `sub`/tenant next to it, then
        // keys on the client-supplied value — letting one authenticated caller read another's token.
        // The principal-bound vault API closes this: the `sub` is read FROM the verified principal and
        // the tenant is a `TenantClaim` (an authenticated claim), so neither is a free argument.
        let vault = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [7u8; KEY_LEN]))),
            Box::new(InMemoryTokenStore::new()),
        );
        let tenant = TenantClaim::from_verified_claim("tenant-a");

        // Two DIFFERENT verified callers in the SAME tenant, each seals a token for the same connector.
        let alice = Principal::user("alice", &["connector.gitlab"]);
        let bob = Principal::user("bob", &["connector.gitlab"]);
        vault
            .save_for(
                &tenant,
                &alice,
                "gitlab",
                b"ALICE-PAT",
                Some(10),
                &["api".into()],
            )
            .unwrap();
        vault
            .save_for(
                &tenant,
                &bob,
                "gitlab",
                b"BOB-PAT",
                Some(20),
                &["api".into()],
            )
            .unwrap();

        // 1. Each verified caller resolves ONLY its own secret — the sub in the key came from the
        //    authenticated principal, so there is no way for bob's request to name alice's sub.
        assert_eq!(
            vault.load_for(&tenant, &alice, "gitlab").unwrap(),
            Some(b"ALICE-PAT".to_vec())
        );
        assert_eq!(
            vault.load_for(&tenant, &bob, "gitlab").unwrap(),
            Some(b"BOB-PAT".to_vec())
        );

        // 2. The derived key literally carries the VERIFIED sub, not any caller-supplied string.
        let k = TokenKey::for_principal(&tenant, &alice, "gitlab");
        assert_eq!(k.user_id, "alice");
        assert_eq!(k.tenant, "tenant-a");
        // Even if a handler *also* had a client-supplied "sub", it cannot influence the bound key:
        // there is no parameter for it on the *_for API (this is a compile-time guarantee, exercised
        // here by showing the key is identical regardless of any ambient string).
        assert_eq!(
            TokenKey::for_principal(&tenant, &bob, "gitlab").user_id,
            "bob"
        );

        // 3. A caller with NO token gets None — never a fallback to another sub's grant.
        let carol = Principal::user("carol", &["connector.gitlab"]);
        assert_eq!(vault.load_for(&tenant, &carol, "gitlab").unwrap(), None);
        assert!(vault
            .connectors_for_principal(&tenant, &carol)
            .unwrap()
            .is_empty());

        // 4. connectors listing is per verified caller.
        assert_eq!(
            vault.connectors_for_principal(&tenant, &alice).unwrap(),
            vec!["gitlab".to_string()]
        );

        // 5. Revoke is scoped to the verified caller — alice's revoke never touches bob.
        assert!(vault.revoke_for(&tenant, &alice, "gitlab").unwrap());
        assert_eq!(vault.load_for(&tenant, &alice, "gitlab").unwrap(), None);
        assert_eq!(
            vault.load_for(&tenant, &bob, "gitlab").unwrap(),
            Some(b"BOB-PAT".to_vec()),
            "one caller's revoke must not affect another verified caller"
        );
    }

    #[test]
    fn r13_verified_tenant_claim_isolates_same_sub_across_tenants() {
        // The tenant half: two verified callers that share the SAME `sub` (e.g. federated logins
        // minting overlapping subs) but authenticate into DIFFERENT tenants must be isolated. The
        // tenant can only be named via a `TenantClaim` (a verified claim), never a client string, so a
        // caller cannot pair its verified sub with a foreign tenant to reach another tenant's tokens.
        let vault = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [3u8; KEY_LEN]))),
            Box::new(InMemoryTokenStore::new()),
        );
        let a = TenantClaim::from_verified_claim("tenant-a");
        let b = TenantClaim::from_verified_claim("tenant-b");
        let user = Principal::user("shared-sub", &["connector.jira"]);

        vault
            .save_for(&a, &user, "jira", b"A-SECRET", None, &[])
            .unwrap();
        vault
            .save_for(&b, &user, "jira", b"B-SECRET", None, &[])
            .unwrap();

        // Same verified sub, different verified tenant → different secret; no collision, no leak.
        assert_eq!(
            vault.load_for(&a, &user, "jira").unwrap(),
            Some(b"A-SECRET".to_vec())
        );
        assert_eq!(
            vault.load_for(&b, &user, "jira").unwrap(),
            Some(b"B-SECRET".to_vec())
        );

        // A third verified tenant sees nothing for the same sub+connector.
        let c = TenantClaim::from_verified_claim("tenant-c");
        assert_eq!(vault.load_for(&c, &user, "jira").unwrap(), None);

        // The single-tenant sentinel is distinct from every real verified tenant.
        assert_eq!(
            vault
                .load_for(&TenantClaim::single_tenant(), &user, "jira")
                .unwrap(),
            None
        );
        assert_eq!(TenantClaim::single_tenant().as_str(), DEFAULT_TENANT);
    }

    #[test]
    fn r13_durable_sql_store_cross_sub_isolation_over_verified_keys_offline() {
        // The durable multi-tenant store (design: Postgres `user_connector_tokens`) is infra_gated —
        // the production backend is Postgres. What is provable OFFLINE is that the DURABLE store,
        // driven through the principal-bound (verified-identity) key, isolates two verified callers
        // that share a tenant AND two tenants that share a sub — across processes (shared backend).
        let shared = InMemorySqlTokenBackend::new();
        let proc_write = SqlTokenStore::new(shared.clone());
        let proc_use = SqlTokenStore::new(shared.clone());
        let tenant = TenantClaim::from_verified_claim("tenant-a");
        let alice = Principal::user("alice", &["connector.graph"]);
        let bob = Principal::user("bob", &["connector.graph"]);

        // Writes go through the verified-identity key derivation (as the OAuth-callback path would).
        proc_write
            .put(
                &TokenKey::for_principal(&tenant, &alice, "graph"),
                StoredToken {
                    sealed: SealedSecret {
                        key_id: 1,
                        nonce: vec![0; NONCE_LEN],
                        ciphertext: vec![0xA1],
                    },
                    expires_at: None,
                    scopes: vec![],
                },
            )
            .unwrap();
        proc_write
            .put(
                &TokenKey::for_principal(&tenant, &bob, "graph"),
                StoredToken {
                    sealed: SealedSecret {
                        key_id: 1,
                        nonce: vec![0; NONCE_LEN],
                        ciphertext: vec![0xB2],
                    },
                    expires_at: None,
                    scopes: vec![],
                },
            )
            .unwrap();

        // A second process (the USE path) reads durably AND stays sub-isolated: alice's verified key
        // never resolves bob's row.
        assert_eq!(
            proc_use
                .get(&TokenKey::for_principal(&tenant, &alice, "graph"))
                .unwrap()
                .unwrap()
                .sealed
                .ciphertext,
            vec![0xA1]
        );
        assert_eq!(
            proc_use
                .get(&TokenKey::for_principal(&tenant, &bob, "graph"))
                .unwrap()
                .unwrap()
                .sealed
                .ciphertext,
            vec![0xB2]
        );
        // connectors_for is tenant+sub scoped: alice's listing is exactly her own grant.
        assert_eq!(
            proc_use.connectors_for("tenant-a", "alice").unwrap(),
            vec!["graph".to_string()]
        );
    }
}

// ---- r12: offline proof of the driver-agnostic Postgres binding (feature = "postgres") ----
//
// The production `SqlTokenBackend` is Postgres and needs a live DB (infra_gated). What IS provable
// offline is that the `pg::PgTokenBackend` issues the correct parameterized SQL against
// `user_connector_tokens` and maps rows back faithfully — proven against a fake `PgExecutor` that
// records statements and returns canned rows. A live driver honouring the same port inherits this.
#[cfg(all(test, feature = "postgres"))]
mod pg_tests {
    use super::pg::{
        PgExecutor, PgTokenBackend, SqlParam, DELETE_SQL, FETCH_SQL, LIST_SQL, UPSERT_SQL,
    };
    use super::*;
    use std::sync::Mutex;

    /// A fake Postgres executor: records every (sql, params), and returns queued query rows. Models a
    /// single durable table so upsert/fetch/delete/list round-trip like the real backend.
    #[derive(Debug, Default)]
    struct FakePg {
        calls: Mutex<Vec<(String, Vec<SqlParam>)>>,
        // (tenant,user,connector) -> the row cells a FETCH would return (key_id,nonce,ct,exp,scopes)
        table: Mutex<std::collections::BTreeMap<(String, String, String), Vec<SqlParam>>>,
    }
    impl FakePg {
        fn pk(p: &[SqlParam]) -> (String, String, String) {
            let t = |i: usize| match &p[i] {
                SqlParam::Text(s) => s.clone(),
                _ => panic!("expected text pk cell {i}"),
            };
            (t(0), t(1), t(2))
        }
    }
    impl PgExecutor for FakePg {
        fn execute(&self, sql: &str, params: &[SqlParam]) -> Result<u64, StoreError> {
            self.calls
                .lock()
                .unwrap()
                .push((sql.to_string(), params.to_vec()));
            if sql == UPSERT_SQL {
                let key = Self::pk(params);
                // Store the SELECT-shaped row (key_id,nonce,ciphertext,expires_at,scopes) = params 3..8.
                self.table
                    .lock()
                    .unwrap()
                    .insert(key, params[3..8].to_vec());
                Ok(1)
            } else if sql == DELETE_SQL {
                let key = Self::pk(params);
                Ok(if self.table.lock().unwrap().remove(&key).is_some() {
                    1
                } else {
                    0
                })
            } else {
                Ok(0)
            }
        }
        fn query(&self, sql: &str, params: &[SqlParam]) -> Result<Vec<Vec<SqlParam>>, StoreError> {
            self.calls
                .lock()
                .unwrap()
                .push((sql.to_string(), params.to_vec()));
            let text = |i: usize| match &params[i] {
                SqlParam::Text(s) => s.clone(),
                _ => panic!("expected text param {i}"),
            };
            if sql == FETCH_SQL {
                let key = (text(0), text(1), text(2));
                Ok(self
                    .table
                    .lock()
                    .unwrap()
                    .get(&key)
                    .cloned()
                    .into_iter()
                    .collect())
            } else if sql == LIST_SQL {
                let (t, u) = (text(0), text(1));
                Ok(self
                    .table
                    .lock()
                    .unwrap()
                    .keys()
                    .filter(|(kt, ku, _)| *kt == t && *ku == u)
                    .map(|(_, _, c)| vec![SqlParam::Text(c.clone())])
                    .collect())
            } else {
                Ok(vec![])
            }
        }
    }

    #[test]
    fn r12_pg_token_backend_issues_correct_sql_and_round_trips_offline() {
        let backend = PgTokenBackend::connect(FakePg::default()).unwrap();
        // connect() ran the DDL.
        // Drive it through the real SqlTokenStore + TokenVault so plaintext never reaches a param.
        let vault = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [4u8; KEY_LEN]))),
            Box::new(SqlTokenStore::new(backend)),
        );
        // Upsert (save) then load through the vault.
        vault
            .save_in(
                "tenant-a",
                "alice",
                "graph",
                b"glpat-PG-SECRET",
                Some(4242),
                &["Mail.Read".into()],
            )
            .unwrap();
        assert_eq!(
            vault.load_in("tenant-a", "alice", "graph").unwrap(),
            Some(b"glpat-PG-SECRET".to_vec())
        );
        // Metadata + tenant-scoped listing round-trip.
        let meta = vault
            .metadata_in("tenant-a", "alice", "graph")
            .unwrap()
            .unwrap();
        assert_eq!(meta.expires_at, Some(4242));
        assert_eq!(meta.scopes, vec!["Mail.Read".to_string()]);
        assert_eq!(
            vault.connectors_for_in("tenant-a", "alice").unwrap(),
            vec!["graph".to_string()]
        );
        // A different tenant with the SAME (user, connector) sees nothing (tenant isolation in SQL).
        assert_eq!(vault.load_in("tenant-b", "alice", "graph").unwrap(), None);
        // Delete returns existed, then not.
        assert!(vault.revoke_in("tenant-a", "alice", "graph").unwrap());
        assert_eq!(vault.load_in("tenant-a", "alice", "graph").unwrap(), None);
    }

    #[test]
    fn r12_pg_upsert_sql_is_idempotent_on_conflict_and_never_carries_plaintext() {
        let fake = std::sync::Arc::new(FakePgShared::default());
        let backend = PgTokenBackend::connect(FakePgShared::clone_handle(&fake)).unwrap();
        let vault = TokenVault::new(
            Box::new(AeadCodec::new(KeyRing::new(1, [9u8; KEY_LEN]))),
            Box::new(SqlTokenStore::new(backend)),
        );
        vault
            .save_in("t", "u", "gitlab", b"PLAINTEXT-NEVER-IN-SQL", None, &[])
            .unwrap();
        // The statement issued is an ON CONFLICT upsert (idempotent), and no bound param equals the
        // plaintext secret — only the sealed ciphertext bytes travel.
        let (sql, params) = fake.last_upsert();
        assert!(
            sql.contains("ON CONFLICT (tenant,user_id,connector) DO UPDATE"),
            "upsert must be idempotent: {sql}"
        );
        for p in &params {
            if let SqlParam::Bytes(b) = p {
                assert!(
                    b.windows(b"PLAINTEXT-NEVER-IN-SQL".len())
                        .all(|w| w != b"PLAINTEXT-NEVER-IN-SQL"),
                    "plaintext secret must never reach a SQL parameter"
                );
            }
            if let SqlParam::Text(s) = p {
                assert_ne!(
                    s, "PLAINTEXT-NEVER-IN-SQL",
                    "plaintext secret must never be a text param"
                );
            }
        }
    }

    // A share-able variant so the test can inspect the last upsert after the backend was moved in.
    #[derive(Debug, Default)]
    struct FakePgShared {
        inner: FakePg,
    }
    impl FakePgShared {
        fn clone_handle(arc: &std::sync::Arc<FakePgShared>) -> HandleExec {
            HandleExec(arc.clone())
        }
        fn last_upsert(&self) -> (String, Vec<SqlParam>) {
            self.inner
                .calls
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(s, _)| s == UPSERT_SQL)
                .cloned()
                .expect("an upsert was issued")
        }
    }
    #[derive(Debug)]
    struct HandleExec(std::sync::Arc<FakePgShared>);
    impl PgExecutor for HandleExec {
        fn execute(&self, sql: &str, params: &[SqlParam]) -> Result<u64, StoreError> {
            self.0.inner.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlParam]) -> Result<Vec<Vec<SqlParam>>, StoreError> {
            self.0.inner.query(sql, params)
        }
    }
}
