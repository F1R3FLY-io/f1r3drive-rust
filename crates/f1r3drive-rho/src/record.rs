//! Typed accessors for the Map-shaped records returned by `Dir.stat`,
//! `Dir.entries`, and friends.
//!
//! The Fs agent's `stat` returns a Rholang Map with keys `name`, `kind`,
//! `size` (file only), `mode`, and in Oracular mode `mtime`/`ctime`/
//! `atime`/`owner`/`group`. See
//! `f1r3node-rust/rholang/src/rust/interpreter/io/stat.rs:80`.

use f1r3drive_proto::rhoapi::expr::ExprInstance;
use f1r3drive_proto::rhoapi::{EMap, Par};

use crate::reply::{par_as_int, par_as_string};

/// A decoded `Dir.stat` / per-entry record.
#[derive(Debug, Clone, Default)]
pub struct StatRecord {
    /// Basename as reported by the agent (last path segment, or the
    /// logical name for a top-level entry).
    pub name: Option<String>,
    /// `"file"`, `"directory"`, or `"other"`.
    pub kind: Option<String>,
    /// Length in bytes. Only present for regular files.
    pub size: Option<u64>,
    /// POSIX permission bits, masked to the low 12 (consensus) or 12
    /// (oracular). None if the agent omitted it (e.g. error record).
    pub mode: Option<u32>,
    /// Milliseconds since UNIX epoch, oracular-only.
    pub mtime_ms: Option<i64>,
    pub ctime_ms: Option<i64>,
    pub atime_ms: Option<i64>,
    pub owner: Option<String>,
    pub group: Option<String>,
    /// If present, the record is an error row rather than a stat row.
    pub error: Option<String>,
}

impl StatRecord {
    /// `true` iff the record describes a directory.
    pub fn is_dir(&self) -> bool {
        self.kind.as_deref() == Some("directory")
    }

    /// `true` iff the record describes a regular file.
    pub fn is_file(&self) -> bool {
        self.kind.as_deref() == Some("file")
    }
}

/// Decode a `Par` whose first expr is an `EMap` into a `StatRecord`.
pub fn par_as_stat_record(par: &Par) -> Option<StatRecord> {
    let map = par_as_map(par)?;
    let mut rec = StatRecord::default();
    for kv in &map.kvs {
        let key = kv.key.as_ref().and_then(par_as_string)?;
        let value = kv.value.as_ref()?;
        match key.as_str() {
            "name" => rec.name = par_as_string(value),
            "kind" => rec.kind = par_as_string(value),
            "size" => rec.size = par_as_int(value).and_then(|n| u64::try_from(n).ok()),
            "mode" => rec.mode = par_as_int(value).and_then(|n| u32::try_from(n).ok()),
            "mtime" => rec.mtime_ms = par_as_int(value),
            "ctime" => rec.ctime_ms = par_as_int(value),
            "atime" => rec.atime_ms = par_as_int(value),
            "owner" => rec.owner = par_as_string(value),
            "group" => rec.group = par_as_string(value),
            "error" => rec.error = par_as_string(value),
            _ => {} // Unknown keys are forward-compatible — ignore.
        }
    }
    Some(rec)
}

/// Extract a reference to an `EMap` payload from a Par.
pub fn par_as_map(par: &Par) -> Option<&EMap> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::EMapBody(m) => Some(m),
        _ => None,
    }
}

/// Extract the elements of an `EList` from a Par. Used by `Dir.entries`,
/// which returns `[true, [row0, row1, ...]]`.
pub fn par_as_list(par: &Par) -> Option<&Vec<Par>> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::EListBody(l) => Some(&l.ps),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use f1r3drive_proto::rhoapi::{EList, Expr, KeyValuePair};

    fn string_par(s: &str) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GString(s.into())),
            }],
            ..Par::default()
        }
    }

    fn int_par(i: i64) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GInt(i)),
            }],
            ..Par::default()
        }
    }

    fn kv(k: &str, v: Par) -> KeyValuePair {
        KeyValuePair {
            key: Some(string_par(k)),
            value: Some(v),
        }
    }

    fn map_par(pairs: Vec<KeyValuePair>) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::EMapBody(EMap {
                    kvs: pairs,
                    ..EMap::default()
                })),
            }],
            ..Par::default()
        }
    }

    #[test]
    fn decodes_file_stat_record() {
        let par = map_par(vec![
            kv("name", string_par("hello.txt")),
            kv("kind", string_par("file")),
            kv("size", int_par(42)),
            kv("mode", int_par(0o644)),
        ]);
        let rec = par_as_stat_record(&par).unwrap();
        assert_eq!(rec.name.as_deref(), Some("hello.txt"));
        assert!(rec.is_file());
        assert_eq!(rec.size, Some(42));
        assert_eq!(rec.mode, Some(0o644));
        assert!(rec.mtime_ms.is_none());
    }

    #[test]
    fn decodes_oracular_fields() {
        let par = map_par(vec![
            kv("name", string_par("dir")),
            kv("kind", string_par("directory")),
            kv("mode", int_par(0o755)),
            kv("mtime", int_par(1_000)),
            kv("ctime", int_par(2_000)),
            kv("atime", int_par(3_000)),
            kv("owner", string_par("alice")),
            kv("group", string_par("staff")),
        ]);
        let rec = par_as_stat_record(&par).unwrap();
        assert!(rec.is_dir());
        assert_eq!(rec.mode, Some(0o755));
        assert_eq!(rec.mtime_ms, Some(1_000));
        assert_eq!(rec.owner.as_deref(), Some("alice"));
        // Dirs omit size.
        assert!(rec.size.is_none());
    }

    #[test]
    fn error_record_decodes() {
        let par = map_par(vec![
            kv("name", string_par("locked")),
            kv("error", string_par("EACCES")),
        ]);
        let rec = par_as_stat_record(&par).unwrap();
        assert_eq!(rec.error.as_deref(), Some("EACCES"));
        assert!(!rec.is_dir());
        assert!(!rec.is_file());
    }

    #[test]
    fn list_payload_extraction() {
        let items = vec![int_par(1), int_par(2)];
        let par = Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::EListBody(EList {
                    ps: items.clone(),
                    ..EList::default()
                })),
            }],
            ..Par::default()
        };
        let got = par_as_list(&par).unwrap();
        assert_eq!(got.len(), 2);
    }
}
