# Security policy

## Reporting

Open a private security advisory on the GitHub repository, or email the
maintainer (see `Cargo.toml` authors). Do not file public issues for
erasure-completeness bugs — e.g. a path where `decrypt_verified` could
be written without a real decrypt failure.

## Scope

In scope:

- `decrypt_verified` set to `true` without an actual failed decrypt.
- Key files surviving `destroy_key`, or key material leaking (log,
  filename, error message).
- Certificate signatures validating over a body different from the
  certified one.
- Tombstone loss that lets `replay_forgotten` miss a destroyed subject.
- The subject's name reaching certificates or audit events (only
  `subject_ref` may appear).

Out of scope:

- Purge coverage of stores the integrator never registered.
- Data never sealed under the subject DEK.
- Attacks with write access to the vault directory — the vault is a
  filesystem trust boundary (operator-owned, 0600 keys).

## Guidance

- Put the vault on a filesystem outside every snapshot/rollback root;
  the entire rollback-survival property depends on it.
- Seal subject PII at ingest under `key_id = subject_ref(name)` —
  unsealed data cannot be crypto-shredded.
- Gate `forget` behind an approval layer if erasure shouldn't be
  unilateral.
