# Threat model

camazotz assumes an honest-but-unsafe storage system: plaintext data is
sealed per-subject, and the erasure ceremony must produce *proof* —
usable under GDPR-style "right to erasure" obligations — that a
subject's data is unrecoverable.

## What it defends against

- **Resurrection by backup/snapshot.** The crypto-shred destroys the
  DEK, not the ciphertext. Snapshots keep the ciphertext forever; the
  math makes it unreadable. `decrypt_verified` is proof, not policy.
- **Resurrection by rollback.** Tombstones live in the vault outside
  data roots; `replay_forgotten` re-purges mentions that reappear after
  a state revert. An erasure cannot be un-erased by reverting state.
- **Silent revocation.** Consent revocations are appended to an
  append-only log — the grant and its revocation are both on record.
- **Identity leakage into audit.** Only `subject_ref` (SHA-256) enters
  certificates and audit events.

## What it does not defend against

- **Unregistered stores.** Purge coverage is the integrator's
  responsibility; a store nobody registered won't be purged. The
  crypto-shred bounds the blast: anything sealed under the subject's
  DEK is unreadable regardless of where copies linger.
- **Plaintext that was never sealed.** camazotz can't shred what was
  never under the DEK — seal subject PII at ingest.
- **Vault compromise before erasure.** If an attacker copied the DEK
  while it existed, post-destruction irrecoverability does not hold.
  Protect the vault directory (0600 keys, operator-owned).
- **Coercion of the erasure actor.** `forget` is an operation, not a
  consent check — gate it with a deliberation layer (e.g. `xipe`,
  `tokala`) if erasure needs approval.

## Design posture

Never assert what can be verified. The certificate's strongest claim —
irrecoverability — is backed by a failed decrypt, not a boolean the
code decided to write.
