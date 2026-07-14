//! Schema fingerprinting: deterministic serialization + HMAC-SHA256, and a
//! JSON-file-backed baseline store.
//!
//! On the first sighting of a tool name the tool object's fingerprint is
//! stored as the trusted baseline. Every later sighting is recomputed and
//! compared. A mismatch is the signature of the documented "MCP rug pull"
//! pattern: a server presents a clean schema at approval time, then silently
//! swaps in a mutated one (typically with instructions injected into the
//! description) on a later `tools/list`.
//!
//! An HMAC (keyed hash) is used instead of a plain SHA-256 so that a
//! malicious server that somehow learns the baseline file's contents cannot
//! forge a colliding "clean-looking" record without also knowing the local
//! secret key.

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// Recursively serialize a JSON value with object keys sorted, producing a
/// deterministic canonical form. `serde_json::Map` preserves insertion order
/// by default, so two semantically identical tool objects could otherwise
/// hash differently just because a server reordered its fields.
pub fn canonicalize(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    // Key encoded exactly as serde_json would encode a string.
                    format!(
                        "{}:{}",
                        Value::String(k.clone()),
                        canonicalize(&map[k])
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonicalize).collect();
            format!("[{}]", inner.join(","))
        }
        // Scalars (null, bool, number, string) already serialize
        // deterministically.
        other => other.to_string(),
    }
}

/// HMAC-SHA256 of `data` under `key`, hex-encoded (64 chars).
pub fn hmac_hex(key: &[u8], data: &str) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| anyhow!("invalid HMAC key: {e}"))?;
    mac.update(data.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Fingerprint one tool object from a `tools/list` result.
pub fn fingerprint_tool(key: &[u8], tool: &Value) -> Result<String> {
    hmac_hex(key, &canonicalize(tool))
}

/// First 16 hex chars of a hash — enough to eyeball in logs.
pub fn short(hash: &str) -> &str {
    &hash[..hash.len().min(16)]
}

/// One trusted baseline record. The description is stored alongside the hash
/// so a later mismatch can show a human-readable diff, and the full tool
/// object is stored so enforce mode can rewrite a mutated response back to
/// the trusted schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub hash: String,
    pub description: String,
    pub first_seen_ms: u128,
    /// Complete tool object as first seen. `Null` only for baseline files
    /// written by pre-enforce versions of mcp-shield; such entries can be
    /// flagged but not rewritten (delete the file to re-register).
    #[serde(default)]
    pub tool: Value,
}

/// Outcome of checking a freshly computed fingerprint against the store.
#[derive(Debug)]
pub enum Verdict {
    /// First-ever sighting; the hash was registered as the trusted baseline.
    Registered,
    /// Hash matches the trusted baseline.
    Match,
    /// Hash differs from the trusted baseline — possible rug pull. The
    /// baseline is deliberately NOT overwritten: the original approval-time
    /// schema stays trusted until an operator deletes the baseline file.
    /// A direct consequence (also deliberate): every later sighting of the
    /// mutated schema re-flags — each serving of a poisoned schema is a
    /// live attempt against the agent, never suppressed as a duplicate.
    Mismatch { baseline: BaselineEntry },
}

/// Persistent per-tool baseline hashes, backed by a plain JSON file
/// (`baseline_hashes.json` by default).
#[derive(Debug)]
pub struct BaselineStore {
    path: PathBuf,
    tools: HashMap<String, BaselineEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BaselineFile {
    tools: HashMap<String, BaselineEntry>,
}

impl BaselineStore {
    /// Load the store from disk, starting empty if the file doesn't exist.
    /// A corrupt file is treated as empty (with a loud warning) rather than
    /// crashing the proxy.
    pub fn load(path: &Path) -> Self {
        let tools = match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<BaselineFile>(&raw) {
                Ok(file) => {
                    tracing::info!(
                        path = %path.display(),
                        tool_count = file.tools.len(),
                        "loaded baseline hash store"
                    );
                    file.tools
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "baseline store is corrupt; starting with an empty store"
                    );
                    HashMap::new()
                }
            },
            Err(_) => {
                tracing::info!(
                    path = %path.display(),
                    "no baseline store found; will create one on first tools/list"
                );
                HashMap::new()
            }
        };
        Self {
            path: path.to_path_buf(),
            tools,
        }
    }

    /// Compare a freshly computed hash against the baseline, registering it
    /// (hash + full tool object) if the tool has never been seen before.
    pub fn check(
        &mut self,
        tool_name: &str,
        hash: &str,
        description: &str,
        tool: &Value,
    ) -> Verdict {
        match self.tools.get(tool_name) {
            None => {
                self.tools.insert(
                    tool_name.to_string(),
                    BaselineEntry {
                        hash: hash.to_string(),
                        description: description.to_string(),
                        first_seen_ms: crate::events::now_ms(),
                        tool: tool.clone(),
                    },
                );
                Verdict::Registered
            }
            Some(entry) if entry.hash == hash => Verdict::Match,
            Some(entry) => Verdict::Mismatch {
                baseline: entry.clone(),
            },
        }
    }

    /// Persist the store to its JSON file (pretty-printed for easy review).
    pub fn save(&self) -> Result<()> {
        let file = BaselineFile {
            tools: self.tools.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .context("failed to serialize baseline store")?;
        std::fs::write(&self.path, json).with_context(|| {
            format!("failed to write baseline store to {}", self.path.display())
        })
    }
}

/// Human-readable summary of how a description changed, for mismatch logs.
/// Finds the common prefix/suffix and reports the segment that was removed
/// and the segment that was added (for an appended rug-pull instruction the
/// "removed" segment is empty and "added" is exactly the injected sentence).
pub fn describe_diff(old: &str, new: &str) -> String {
    let old_chars: Vec<char> = old.chars().collect();
    let new_chars: Vec<char> = new.chars().collect();

    let prefix = old_chars
        .iter()
        .zip(new_chars.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let max_suffix = old_chars.len().min(new_chars.len()) - prefix;
    let suffix = old_chars
        .iter()
        .rev()
        .zip(new_chars.iter().rev())
        .take_while(|(a, b)| a == b)
        .count()
        .min(max_suffix);

    let removed: String = old_chars[prefix..old_chars.len() - suffix].iter().collect();
    let added: String = new_chars[prefix..new_chars.len() - suffix].iter().collect();

    format!(
        "    - baseline description: {old:?}\n    + current  description: {new:?}\n    removed segment: {removed:?}\n    added   segment: {added:?}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalize_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":{"y":2,"x":3}}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":{"x":3,"y":2},"b":1}"#).unwrap();
        assert_eq!(canonicalize(&a), canonicalize(&b));
    }

    #[test]
    fn mismatch_is_reflagged_on_every_subsequent_sighting() {
        // Load from a path that doesn't exist: in-memory store, never saved.
        let mut store =
            BaselineStore::load(Path::new("mcp-shield-test-nonexistent-baseline.json"));
        let tool = json!({ "name": "t", "description": "clean" });

        assert!(matches!(
            store.check("t", "hash-clean", "clean", &tool),
            Verdict::Registered
        ));
        // Every repeat sighting of a non-matching hash must flag again:
        // each serving of the poisoned schema is a live attack attempt,
        // never suppressed as an already-seen duplicate.
        for _ in 0..3 {
            assert!(matches!(
                store.check("t", "hash-evil", "evil", &tool),
                Verdict::Mismatch { .. }
            ));
        }
        // And the trusted baseline was never overwritten by the mismatches.
        assert!(matches!(
            store.check("t", "hash-clean", "clean", &tool),
            Verdict::Match
        ));
    }
}
