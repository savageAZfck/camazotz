# camazotz specification

Certified subject erasure with crypto-shredding.

## Components

- **Vault** — per-subject key store. `seal`/`open` XChaCha20-Poly1305
  blobs under a data-encryption key addressed by `key_id`. Key files
  are named `sha256(key_id)` so key ids never leak into directory
  listings. `destroy_key` removes the DEK — the crypto-shred.
- **Registry** (`consent`) — append-only NDJSON consent log; the active
  set is a fold where a `(subject, scope)` pair is live iff its latest
  record is `granted` or `attested`.
- **Erasure** — the ceremony: incidental purge → consent revocation →
  key destruction → decrypt-failure verification → signed certificate
  → tombstone.
- **Certificate** — the proof artifact (below).

## Erasure ceremony (`forget(subject)`)

1. **Probe armed.** A known blob is sealed under `key_id =
   subject_ref(subject)` *before* any destruction.
2. **Incidental purge.** Registered `PurgeTarget`s apply:
   `FilterLines` drops lines containing the subject,
   `Redact` replaces occurrences with `[forgotten]`,
   `DeleteMatching` removes files named for the subject.
3. **Consent revocation.** Active grants for the subject get a
   `revoked` record — appended, never deleted.
4. **Crypto-shred.** `destroy_key(subject_ref)`.
5. **Verification.** The probe is opened; `decrypt_verified` is `true`
   only when the open provably fails.
6. **Certificate.** Written to `cert_dir/<ts>-<subject_ref>.json`;
   Ed25519-signed over the canonical body (all fields except
   `signature`, `signature_scheme`, `signed`) when a signer is
   configured.
7. **Tombstone.** `(subject_ref, name)` appended to
   `vault/destroyed.jsonl`.
8. **Audit.** If an audit sink is configured it receives
   `dek_destroyed` and `erasure_certified` events carrying only the
   subject hash — the name never enters the audit chain.

## Certificate fields

`kind`, `version`, `issued_at`, `subject_ref` (SHA-256 of the subject),
`method`, `dek_destroyed`, `decrypt_verified`, `purged` (`kind:count`
entries), `detail`, `signed`, `signature`, `signature_scheme`.

## Rollback survival

The vault must live outside snapshot/rollback roots. A revert may
resurrect ciphertext and plaintext mentions; it cannot resurrect the
key or the tombstone. `replay_forgotten()` re-runs incidental purges
for every tombstoned subject — designed to run at init.

## Invariants

- `decrypt_verified` is never written without a failed post-destruction
  decrypt.
- Consent records are append-only; erasure appends revocations.
- `subject_ref` — not the subject name — is the only identity the
  certificate and audit chain carry.

## Non-goals

- The crate does not find *every* place a subject might appear — it
  purges registered targets. Coverage is the integrator's job; the
  crypto-shred is what makes covered PII unrecoverable regardless.
- It does not verify a certificate was issued by a legitimate process —
  signature verification is the caller's check.
