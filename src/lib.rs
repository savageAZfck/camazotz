//! camazotz — certified erasure with crypto-shredding.
//!
//! Named for Camazotz, the Maya death-bat of the Popol Vuh — the god of
//! endings. This crate makes deletion *provable*: a subject's data is
//! purged from free-text stores, their consent grants are revoked on
//! record, the per-subject data-encryption key is destroyed, and the
//! resulting certificate carries `decrypt_verified: true` only when a
//! post-destruction decrypt attempt **provably fails**.
//!
//! The load-bearing design detail: keys and destroyed-subject tombstones
//! live in a key vault *outside* the data roots. A filesystem snapshot
//! or state rollback can resurrect ciphertext — it cannot resurrect the
//! key, and it cannot erase the tombstone. [`Erasure::replay_forgotten`]
//! re-applies incidental purges for every tombstoned subject after a
//! rollback, so an erasure survives state reversion.
//!
//! ```no_run
//! use camazotz::{Erasure, PurgeTarget, Vault};
//! use std::path::PathBuf;
//!
//! let vault = Vault::new(PathBuf::from("/var/lib/app/keys")).unwrap();
//! let mut erasure = Erasure::new(vault, PathBuf::from("/var/lib/app/erasure"));
//! erasure.purge_lines(PathBuf::from("/var/lib/app/notes.txt"));
//! let cert = erasure.forget("alice").unwrap();
//! assert!(cert.dek_destroyed);
//! ```

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

pub mod consent;

/// SHA-256 reference for a subject — the only form of their name that
/// ever touches the audit chain.
pub fn subject_ref(subject: &str) -> String {
    hex::encode(Sha256::digest(subject.as_bytes()))
}

/// A sealed blob: XChaCha20-Poly1305 under a per-subject DEK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBox {
    pub nonce: String,
    pub blob: String,
}

/// Per-subject key vault. Keys and destroyed-subject tombstones live in
/// `dir` — keep it outside any snapshot/rollback root so a revert can
/// restore ciphertext but never the key.
pub struct Vault {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl Vault {
    pub fn new(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(dir.join("keys"))?;
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        // Filename is the hash of the key id — the id itself never leaks
        // into a directory listing.
        self.dir
            .join("keys")
            .join(format!("{}.key", hex::encode(Sha256::digest(key_id.as_bytes()))))
    }

    /// Seal `plaintext` under the DEK for `key_id` (created on first use).
    pub fn seal(&self, plaintext: &[u8], key_id: &str) -> io::Result<SealedBox> {
        let _g = self.lock.lock().expect("vault lock");
        let key = self.load_or_create_key(key_id)?;
        let cipher = XChaCha20Poly1305::new((&key).into());
        let mut nonce_bytes = [0u8; 24];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let blob = cipher
            .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "seal failed"))?;
        Ok(SealedBox {
            nonce: hex::encode(nonce_bytes),
            blob: hex::encode(blob),
        })
    }

    /// Open a sealed box. `None` when the key is absent or decrypt fails —
    /// the same result either way, which is what makes decrypt-failure a
    /// meaningful post-destruction proof.
    pub fn open(&self, sealed: &SealedBox, key_id: &str) -> Option<Vec<u8>> {
        let key = self.load_key(key_id)?;
        let nonce = hex::decode(&sealed.nonce).ok()?;
        let blob = hex::decode(&sealed.blob).ok()?;
        XChaCha20Poly1305::new((&key).into())
            .decrypt(XNonce::from_slice(&nonce), blob.as_ref())
            .ok()
    }

    /// Destroy the DEK for `key_id`. Returns whether a key existed.
    /// This is the crypto-shred: every blob sealed under the key becomes
    /// unrecoverable, everywhere the ciphertext survives — including
    /// inside backups and state snapshots.
    pub fn destroy_key(&self, key_id: &str) -> bool {
        let _g = self.lock.lock().expect("vault lock");
        let path = self.key_path(key_id);
        if path.exists() {
            fs::remove_file(path).is_ok()
        } else {
            false
        }
    }

    /// Record a destroyed subject's tombstone (survives rollback;
    /// [`Erasure::replay_forgotten`] consumes it).
    pub fn record_destroyed(&self, subject_ref: &str, name: &str) -> io::Result<()> {
        let line = json!({
            "ts": consent::now(),
            "subject_ref": subject_ref,
            "name": name,
        });
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("destroyed.jsonl"))?;
        use std::io::Write;
        f.write_all(line.to_string().as_bytes())?;
        f.write_all(b"\n")
    }

    /// Names of every destroyed subject (for purge replay).
    pub fn replay_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if let Ok(text) = fs::read_to_string(self.dir.join("destroyed.jsonl")) {
            for line in text.lines() {
                if let Ok(v) = serde_json::from_str::<Value>(line) {
                    if let Some(n) = v["name"].as_str() {
                        names.push(n.to_string());
                    }
                }
            }
        }
        names
    }

    fn load_key(&self, key_id: &str) -> Option<[u8; 32]> {
        let bytes = fs::read(self.key_path(key_id)).ok()?;
        <[u8; 32]>::try_from(bytes.as_slice()).ok()
    }

    fn load_or_create_key(&self, key_id: &str) -> io::Result<[u8; 32]> {
        if let Some(k) = self.load_key(key_id) {
            return Ok(k);
        }
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        let path = self.key_path(key_id);
        fs::write(&path, key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(key)
    }
}

/// A mutation applied to free-text stores during erasure.
#[derive(Debug, Clone)]
pub enum PurgeTarget {
    /// Drop every line containing the subject (case-insensitive).
    FilterLines(PathBuf),
    /// Replace every occurrence with `[forgotten]` in place.
    Redact(PathBuf),
    /// Delete files in this directory whose filename contains the subject.
    DeleteMatching(PathBuf),
}

/// What the erasure did, summarized on the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub kind: String,
    pub version: u32,
    pub issued_at: u64,
    /// SHA-256 of the subject — never the name.
    pub subject_ref: String,
    pub method: String,
    pub dek_destroyed: bool,
    /// `true` only when a post-destruction decrypt attempt provably
    /// failed — the certificate *verifies* irrecoverability.
    pub decrypt_verified: bool,
    /// What was purged, as `kind:count` entries.
    pub purged: Vec<String>,
    pub detail: BTreeMap<String, Value>,
    pub signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
}

impl Certificate {
    /// Verify the Ed25519 signature over the certificate body.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let Some(sig_hex) = &self.signature else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else {
            return false;
        };
        let sig = Signature::from_bytes(&arr);
        key.verify_strict(&self.signing_body(), &sig).is_ok()
    }

    /// Canonical signing body: sorted-key JSON of everything but the
    /// signature fields.
    pub fn signing_body(&self) -> Vec<u8> {
        let mut v = serde_json::to_value(self).unwrap_or_default();
        if let Some(m) = v.as_object_mut() {
            m.remove("signature");
            m.remove("signature_scheme");
            m.remove("signed");
        }
        serde_json::to_vec(&v).unwrap_or_default()
    }
}

/// The erasure organ. Register purge targets, then [`forget`](Self::forget).
pub struct Erasure {
    pub vault: Vault,
    cert_dir: PathBuf,
    targets: Vec<PurgeTarget>,
    consent: Option<consent::Registry>,
    signer: Option<SigningKey>,
    /// Optional audit sink — receives `(event_type, payload)` for every
    /// certified erasure so the caller can anchor it in an audit chain.
    audit: Option<Box<dyn Fn(&str, Value) + Send + Sync>>,
}

impl Erasure {
    pub fn new(vault: Vault, cert_dir: PathBuf) -> Self {
        Self {
            vault,
            cert_dir,
            targets: Vec::new(),
            consent: None,
            signer: None,
            audit: None,
        }
    }

    pub fn purge_lines(&mut self, path: PathBuf) {
        self.targets.push(PurgeTarget::FilterLines(path));
    }

    pub fn redact_in(&mut self, path: PathBuf) {
        self.targets.push(PurgeTarget::Redact(path));
    }

    pub fn delete_matching(&mut self, dir: PathBuf) {
        self.targets.push(PurgeTarget::DeleteMatching(dir));
    }

    pub fn with_consent(mut self, registry: consent::Registry) -> Self {
        self.consent = Some(registry);
        self
    }

    /// Sign certificates with `key`. The cert's `signing_body` is the
    /// canonical payload.
    pub fn with_signer(mut self, key: SigningKey) -> Self {
        self.signer = Some(key);
        self
    }

    pub fn with_audit<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, Value) + Send + Sync + 'static,
    {
        self.audit = Some(Box::new(f));
        self
    }

    /// Re-apply incidental purges for every destroyed subject. Run at
    /// init: if state was rolled back past an erasure, the tombstones
    /// still live in the vault and the mentions die again.
    pub fn replay_forgotten(&self) {
        for name in self.vault.replay_names() {
            if !name.is_empty() {
                self.purge_incidental(&name);
            }
        }
    }

    /// Purge + revoke + crypto-shred + certify.
    ///
    /// The subject's sealed data is addressed by `key_id = subject_ref`
    /// — the convention callers use when sealing subject PII. The
    /// returned certificate is written to `cert_dir` and, when a signer
    /// is configured, Ed25519-signed over its canonical body.
    pub fn forget(&self, subject: &str) -> io::Result<Certificate> {
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty subject"));
        }
        let sref = subject_ref(subject);
        let key_id = &sref;

        // Arm a probe before the shred: seal a known blob so we can
        // prove decrypt-failure after the key dies.
        let probe = self.vault.seal(b"camazotz-probe", key_id).ok();
        let mut removed = Vec::new();
        let mut detail: BTreeMap<String, Value> = BTreeMap::new();

        // 1. Incidental mentions across registered free-text stores.
        for (kind, count) in self.purge_incidental(subject) {
            detail.insert(kind.clone(), json!(count));
            removed.push(format!("{kind}:{count}"));
        }

        // 2. Consent grants — revoked, never silently deleted. The
        //    revocation is itself part of the record.
        if let Some(reg) = &self.consent {
            let scopes: Vec<String> = reg
                .current()
                .into_iter()
                .filter(|(s, _)| s.eq_ignore_ascii_case(subject))
                .map(|(_, scope)| scope)
                .collect();
            for scope in &scopes {
                let _ = reg.record("revoked", subject, scope, "subject erasure");
            }
            if !scopes.is_empty() {
                removed.push(format!("consent_revoked:{}", scopes.len()));
                detail.insert("consent_revoked".into(), json!(scopes));
            }
        }

        // 3. The crypto-shred, then the proof: attempt a decrypt that
        //    must now fail.
        let dek_destroyed = self.vault.destroy_key(key_id);
        let decrypt_verified = dek_destroyed
            && probe
                .as_ref()
                .map(|p| self.vault.open(p, key_id).is_none())
                .unwrap_or(false);
        if dek_destroyed {
            removed.push("subject_dek_destroyed".to_string());
            self.vault.record_destroyed(&sref, subject)?;
            if let Some(audit) = &self.audit {
                audit(
                    "dek_destroyed",
                    json!({
                        "subject_ref": sref,
                        "verify": if decrypt_verified { "decrypt-fails" } else { "unverified" },
                    }),
                );
            }
        }

        // 4. Certificate.
        let mut cert = Certificate {
            kind: "camazotz.erasure_certificate".to_string(),
            version: 1,
            issued_at: consent::now(),
            subject_ref: sref.clone(),
            method: if dek_destroyed {
                "crypto-shred+purge+consent-revocation+signed_certificate".to_string()
            } else {
                "purge+revocation+signed_certificate".to_string()
            },
            dek_destroyed,
            decrypt_verified,
            purged: removed.clone(),
            detail: detail.clone(),
            signed: false,
            signature: None,
            signature_scheme: None,
        };
        if let Some(signer) = &self.signer {
            let sig = signer.sign(&cert.signing_body());
            cert.signature = Some(hex::encode(sig.to_bytes()));
            cert.signature_scheme = Some("ed25519".to_string());
            cert.signed = true;
        }

        fs::create_dir_all(&self.cert_dir)?;
        let path = self
            .cert_dir
            .join(format!("{}-{}.json", cert.issued_at, sref));
        fs::write(&path, serde_json::to_vec_pretty(&cert)?)?;

        if let Some(audit) = &self.audit {
            let cert_hash = hex::encode(Sha256::digest(
                &serde_json::to_vec(&cert).unwrap_or_default(),
            ));
            audit(
                "erasure_certified",
                json!({
                    "subject_ref": sref,
                    "certificate_sha256": cert_hash,
                    "certificate": path.display().to_string(),
                    "signed": cert.signed,
                    "dek_destroyed": dek_destroyed,
                    "purged": removed.join(","),
                }),
            );
        }
        Ok(cert)
    }

    /// Apply all registered incidental-mention purges for `subject`.
    /// Returns `(kind, count)` pairs.
    fn purge_incidental(&self, subject: &str) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        for target in &self.targets {
            match target {
                PurgeTarget::FilterLines(path) => {
                    if let Some(n) = filter_lines(path, subject) {
                        out.push(("filtered_lines".to_string(), n));
                    }
                }
                PurgeTarget::Redact(path) => {
                    if redact_file(path, subject).unwrap_or(false) {
                        out.push(("capture_records_redacted".to_string(), 1));
                    }
                }
                PurgeTarget::DeleteMatching(dir) => {
                    if let Some(n) = delete_matching(dir, subject) {
                        out.push(("files_deleted".to_string(), n));
                    }
                }
            }
        }
        out
    }
}

/// Drop every line containing `subject` (case-insensitive). Returns the
/// number dropped.
fn filter_lines(path: &PathBuf, subject: &str) -> Option<usize> {
    let text = fs::read_to_string(path).ok()?;
    let lower = subject.to_lowercase();
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| !l.to_lowercase().contains(&lower))
        .collect();
    let dropped = text.lines().count() - kept.len();
    if dropped > 0 {
        let mut body = kept.join("\n");
        if text.ends_with('\n') {
            body.push('\n');
        }
        fs::write(path, body).ok()?;
    }
    (dropped > 0).then_some(dropped)
}

/// Replace every case-insensitive occurrence of `subject` with
/// `[forgotten]`. Returns whether the file changed.
fn redact_file(path: &PathBuf, subject: &str) -> Option<bool> {
    let text = fs::read_to_string(path).ok()?;
    let out = redact(&text, subject);
    if out != text {
        fs::write(path, &out).ok()?;
        return Some(true);
    }
    Some(false)
}

/// Case-insensitive literal redaction.
pub fn redact(text: &str, subject: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let lower = text.to_lowercase();
    let needle = subject.to_lowercase();
    let mut pos = 0;
    while let Some(off) = lower[pos..].find(&needle) {
        let start = pos + off;
        out.push_str(&text[pos..start]);
        out.push_str("[forgotten]");
        pos = start + needle.len();
    }
    out.push_str(&text[pos..]);
    out
}

/// Delete files in `dir` whose filename contains `subject`.
fn delete_matching(dir: &PathBuf, subject: &str) -> Option<usize> {
    let lower = subject.to_lowercase();
    let entries = fs::read_dir(dir).ok()?;
    let mut n = 0;
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .to_lowercase()
            .contains(&lower)
            && fs::remove_file(entry.path()).is_ok()
        {
            n += 1;
        }
    }
    (n > 0).then_some(n)
}

/// Convenience: generate a random Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut secret);
    SigningKey::from_bytes(&secret)
}
