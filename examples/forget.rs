use camazotz::consent::Registry;
use camazotz::{generate_signing_key, subject_ref, Erasure, Vault};
use std::fs;

fn main() {
    let dir = std::env::temp_dir().join(format!("camazotz-example-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();

    // A system that knows things about people.
    fs::write(
        dir.join("memory.txt"),
        "alice likes tea\nbob likes coffee\n",
    )
    .unwrap();
    fs::write(dir.join("heard.json"), "{\"said\":\"alice is here\"}\n").unwrap();
    let registry = Registry::new(dir.join("consent.jsonl"));
    registry.record("granted", "alice", "meeting", "").unwrap();

    // Her PII lives sealed under her subject ref.
    let vault = Vault::new(dir.join("keys")).unwrap();
    let sref = subject_ref("alice");
    let sealed = vault
        .seal(b"{\"notes\":\"prefers mornings\"}", &sref)
        .unwrap();

    let signer = generate_signing_key();
    let vk = signer.verifying_key();
    let mut erasure = Erasure::new(vault, dir.join("certs")).with_signer(signer);
    erasure.purge_lines(dir.join("memory.txt"));
    erasure.redact_in(dir.join("heard.json"));
    let erasure = erasure.with_consent(registry);

    println!("`forget alice`:");
    let cert = erasure.forget("alice").unwrap();
    println!("  dek_destroyed:    {}", cert.dek_destroyed);
    println!("  decrypt_verified: {}", cert.decrypt_verified);
    println!("  signed:           {}", cert.signed);
    println!("  signature valid:  {}", cert.verify_signature(&vk));
    println!("  purged:           {}", cert.purged.join(", "));

    assert!(cert.dek_destroyed && cert.decrypt_verified && cert.verify_signature(&vk));

    // Rollback: a snapshot resurrects the plaintext — but not the key.
    fs::write(dir.join("memory.txt"), "alice likes tea\n").unwrap();
    let mut erasure2 = Erasure::new(Vault::new(dir.join("keys")).unwrap(), dir.join("certs"));
    erasure2.purge_lines(dir.join("memory.txt"));
    erasure2.replay_forgotten();
    let after = fs::read_to_string(dir.join("memory.txt")).unwrap();
    assert!(!after.to_lowercase().contains("alice"));
    println!("  rollback survival: resurrected mention re-purged");

    // The ciphertext that survived the rollback is math now.
    let _ = sealed;
    fs::remove_dir_all(&dir).ok();
}
