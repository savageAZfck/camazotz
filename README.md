# camazotz

Certified erasure with crypto-shredding. Named for the Maya death-bat of the Popol Vuh — the god of endings. This crate makes deletion **provable**.

Extracted from Bad Apple's `forget <name>` flow, generalized for any system that holds personal data.

## The problem

`rm` asserts deletion. Snapshots, backups, and state-rollback systems resurrect "deleted" data. GDPR's right-to-erasure asks for a proof nobody can actually produce — until now: **crypto-shredding with verified decrypt-failure.**

## What `forget(subject)` does

1. **Purge** — incidental mentions dropped from registered free-text stores (line filter), occurrences redacted in capture files (`[forgotten]`), matching files deleted.
2. **Revoke** — consent grants revoked *on record*, never silently deleted. The revocation is itself part of the record.
3. **Crypto-shred** — the per-subject XChaCha20-Poly1305 DEK is destroyed. Every blob sealed under it becomes unrecoverable **everywhere the ciphertext survives** — including inside backups and snapshots.
4. **Verify** — a probe blob is sealed *before* the shred; after it, a decrypt attempt must provably fail. The certificate carries `decrypt_verified: true` only when it does. The certificate *verifies* irrecoverability — it does not assert it.
5. **Certify** — an Ed25519-signed JSON certificate lands on disk: subject hash (never the name), method, what was purged, the verification result.
6. **Tombstone** — the destroyed subject is recorded in the key vault, outside the data roots.

## The load-bearing detail

Keys and tombstones live in a vault *outside* the data roots. A state rollback can resurrect ciphertext — it cannot resurrect the key, and it cannot erase the tombstone. `replay_forgotten()` re-applies incidental purges for every tombstoned subject after a rollback, so **an erasure survives state reversion**.

## Usage

```rust
use camazotz::{Erasure, Vault, generate_signing_key};
use std::path::PathBuf;

let vault = Vault::new(PathBuf::from("/var/lib/app/keys"))?;
let signer = generate_signing_key();
let mut erasure = Erasure::new(vault, PathBuf::from("/var/lib/app/erasure"))
    .with_signer(signer);

// Register the stores that might mention people.
erasure.purge_lines(PathBuf::from("working_memory.txt"));
erasure.redact_in(PathBuf::from("captures.json"));
erasure.delete_matching(PathBuf::from("notes/"));

// Seal subject PII under key_id = subject_ref("alice").
// Then: `forget "alice"` —
let cert = erasure.forget("alice")?;
assert!(cert.dek_destroyed);
assert!(cert.decrypt_verified);
assert!(cert.verify_signature(&vk));
```

## Consent registry

`camazotz::consent::Registry` keeps the append-only `granted|revoked|attested` log that capture surfaces check before recording bystanders. Erasure appends revocations — never deletes.

## Origin

Bad Apple's erasure organ runs this exact ceremony: purge, revoke, shred, verify, certify, tombstone, replay. This crate is the extracted implementation — the first `right to be forgotten` primitive that produces a verifiable artifact instead of a promise.

## License

MIT
