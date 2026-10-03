//! Append-only consent registry for capture surfaces.
//!
//! Sensors capture people who never agreed to anything. This registry
//! keeps an operator-attested record of who consented to which scope —
//! `granted`, `revoked`, or `attested` — as an append-only NDJSON log.
//! The current state is a fold: a `(subject, scope)` pair is active
//! when its latest record is `granted` or `attested`.
//!
//! Erasure never deletes consent records — it appends a `revoked`
//! record, so the revocation itself is part of the record.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// One line of the consent log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub ts: u64,
    /// `granted` | `revoked` | `attested`
    pub action: String,
    /// Who — "alice", "household", "operator".
    pub subject: String,
    /// What — "ambient_hearing", "meeting", "voice", free-form.
    pub scope: String,
    pub note: String,
}

/// The append-only registry.
pub struct Registry {
    pub path: PathBuf,
}

impl Registry {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Append a record. Returns the record appended.
    pub fn record(
        &self,
        action: &str,
        subject: &str,
        scope: &str,
        note: &str,
    ) -> io::Result<ConsentRecord> {
        let rec = ConsentRecord {
            ts: now(),
            action: action.to_string(),
            subject: subject.to_string(),
            scope: scope.to_string(),
            note: note.to_string(),
        };
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(serde_json::to_string(&rec)?.as_bytes())?;
        f.write_all(b"\n")?;
        Ok(rec)
    }

    /// Fold the log into currently-active `(subject, scope)` pairs.
    pub fn current(&self) -> Vec<(String, String)> {
        let mut state: HashMap<String, String> = HashMap::new();
        if let Ok(text) = fs::read_to_string(&self.path) {
            for line in text.lines() {
                if let Ok(rec) = serde_json::from_str::<ConsentRecord>(line) {
                    state.insert(format!("{}|{}", rec.subject, rec.scope), rec.action);
                }
            }
        }
        let mut active: Vec<(String, String)> = state
            .iter()
            .filter(|(_, a)| a.as_str() == "granted" || a.as_str() == "attested")
            .filter_map(|(key, _)| {
                let mut parts = key.splitn(2, '|');
                Some((parts.next()?.to_string(), parts.next()?.to_string()))
            })
            .collect();
        active.sort();
        active
    }

    /// Subjects with an active grant for `scope`.
    pub fn active_subjects(&self, scope: &str) -> Vec<String> {
        self.current()
            .into_iter()
            .filter(|(_, s)| s == scope)
            .map(|(subj, _)| subj)
            .collect()
    }
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
