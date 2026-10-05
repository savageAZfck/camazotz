use camazotz::consent::Registry;
use camazotz::{generate_signing_key, subject_ref, Erasure, Vault};
use std::fs;
use std::path::PathBuf;

fn tempdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("camazotz-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn seal_open_roundtrip() {
    let dir = tempdir("seal");
    let vault = Vault::new(dir.join("keys")).unwrap();
    let sref = subject_ref("alice");
    let sealed = vault.seal(b"alice's secrets", &sref).unwrap();
    assert_eq!(vault.open(&sealed, &sref).unwrap(), b"alice's secrets");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn key_destruction_makes_ciphertext_unrecoverable() {
    let dir = tempdir("shred");
    let vault = Vault::new(dir.join("keys")).unwrap();
    let sref = subject_ref("alice");
    let sealed = vault.seal(b"alice's secrets", &sref).unwrap();
    assert!(vault.destroy_key(&sref));
    // The ciphertext survives — snapshots keep it. The key is gone.
    assert!(vault.open(&sealed, &sref).is_none());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn forget_purges_revokes_shreds_certifies() {
    let dir = tempdir("forget");

    // A free-text store with incidental mentions.
    let notes = dir.join("notes.txt");
    fs::write(&notes, "alice called\nbob wrote\nAlice again\n").unwrap();

    // A capture store to redact.
    let capture = dir.join("heard.txt");
    fs::write(&capture, "alice said hi\n").unwrap();

    // Consent on file.
    let registry = Registry::new(dir.join("consent.jsonl"));
    registry
        .record("granted", "alice", "meeting", "weekly sync")
        .unwrap();
    registry
        .record("granted", "bob", "meeting", "weekly sync")
        .unwrap();

    // Sealed PII under the subject ref.
    let vault = Vault::new(dir.join("keys")).unwrap();
    let sref = subject_ref("alice");
    let sealed = vault.seal(b"{\"name\":\"alice\"}", &sref).unwrap();

    let signer = generate_signing_key();
    let vk = signer.verifying_key();

    let mut erasure = Erasure::new(vault, dir.join("certs")).with_signer(signer);
    erasure.purge_lines(notes.clone());
    erasure.redact_in(capture.clone());
    let erasure = erasure.with_consent(Registry::new(dir.join("consent.jsonl")));

    let cert = erasure.forget("alice").unwrap();

    assert!(cert.dek_destroyed);
    assert!(
        cert.decrypt_verified,
        "post-shred decrypt must provably fail"
    );
    assert!(cert.signed);
    assert!(
        cert.verify_signature(&vk),
        "certificate signature must verify"
    );
    assert!(cert.purged.iter().any(|p| p.starts_with("filtered_lines")));
    assert!(cert.purged.iter().any(|p| p.starts_with("consent_revoked")));

    // The plaintext mentions are gone.
    let notes_text = fs::read_to_string(&notes).unwrap();
    assert!(!notes_text.to_lowercase().contains("alice"));
    assert!(notes_text.contains("bob"));

    let capture_text = fs::read_to_string(&capture).unwrap();
    assert!(capture_text.contains("[forgotten]"));

    // Consent is revoked on record, not deleted.
    let reg = Registry::new(dir.join("consent.jsonl"));
    assert!(!reg
        .active_subjects("meeting")
        .contains(&"alice".to_string()));
    assert!(reg.active_subjects("meeting").contains(&"bob".to_string()));

    // Sealed copies are unrecoverable — the vault key is destroyed.
    assert!(erasure.vault.open(&sealed, &sref).is_none());

    // Tombstone recorded.
    assert!(erasure.vault.replay_names().contains(&"alice".to_string()));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn erasure_survives_state_rollback() {
    let dir = tempdir("rollback");
    let notes = dir.join("notes.txt");
    fs::write(&notes, "alice called\n").unwrap();

    let vault = Vault::new(dir.join("keys")).unwrap();
    let mut erasure = Erasure::new(vault, dir.join("certs"));
    erasure.purge_lines(notes.clone());
    let cert = erasure.forget("alice").unwrap();
    assert!(cert.dek_destroyed);

    // Simulate a rollback: the "deleted" data returns from a snapshot.
    fs::write(&notes, "alice called\n").unwrap();

    // replay_forgotten re-kills resurrected mentions — the tombstone
    // lives in the vault, outside the rolled-back data roots.
    let mut erasure2 = Erasure::new(Vault::new(dir.join("keys")).unwrap(), dir.join("certs"));
    erasure2.purge_lines(notes.clone());
    erasure2.replay_forgotten();
    let text = fs::read_to_string(&notes).unwrap();
    assert!(!text.to_lowercase().contains("alice"));
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn consent_registry_folds_latest_record() {
    let dir = tempdir("consent");
    let reg = Registry::new(dir.join("consent.jsonl"));
    reg.record("granted", "alice", "voice", "").unwrap();
    reg.record("granted", "alice", "meeting", "").unwrap();
    reg.record("revoked", "alice", "voice", "").unwrap();
    assert_eq!(reg.active_subjects("meeting"), vec!["alice"]);
    assert!(reg.active_subjects("voice").is_empty());
    fs::remove_dir_all(&dir).ok();
}
