use camazotz::{generate_signing_key, subject_ref, Erasure, Vault};
use std::fs;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let dir = std::env::temp_dir().join(format!("camazotz-bench-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();

    // Seal+open throughput.
    let vault = Vault::new(dir.join("keys")).unwrap();
    let sref = subject_ref("bench");
    let body = vec![7u8; 4096];
    let n = 1_000;
    let t = Instant::now();
    for _ in 0..n {
        let sealed = vault.seal(black_box(&body), &sref).unwrap();
        black_box(vault.open(&sealed, &sref));
    }
    println!(
        "seal+open 4KiB: {n} ops in {:?} ({:.0} µs/op)",
        t.elapsed(),
        t.elapsed().as_micros() as f64 / n as f64 / 1000.0
    );

    // Full erasure ceremony.
    let t = Instant::now();
    for i in 0..100 {
        let name = format!("subject{i}");
        let sref = subject_ref(&name);
        let _ = vault.seal(b"pii", &sref).unwrap();
        let notes = dir.join(format!("notes{i}.txt"));
        fs::write(&notes, format!("{name} line\nkeep\n")).unwrap();
        let mut e = Erasure::new(Vault::new(dir.join("keys")).unwrap(), dir.join("certs"))
            .with_signer(generate_signing_key());
        e.purge_lines(notes);
        black_box(e.forget(&name).unwrap());
    }
    println!("forget ceremony: 100 erasures in {:?}", t.elapsed());
    fs::remove_dir_all(&dir).ok();
}
