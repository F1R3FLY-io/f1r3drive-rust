//! Rholang snippet generators.
//!
//! Every snippet follows the same shape:
//!
//! ```rholang
//! new return, rl(`rho:registry:lookup`), fsCh in {
//!   rl!(`rho:id:...`, *fsCh) |
//!   for (@(_, fs) <- fsCh) {
//!     // verb-specific body — leaves at most one Par on *return
//!   }
//! }
//! ```
//!
//! The leading `new return` is critical: the f1r3node runtime pulls the
//! deploy's return value from the FIRST unforgeable name allocated at the
//! top-level `new`, so `return!(reply)` is what surfaces back through
//! `ExploratoryDeployResponse.post_block_data`. See
//! `f1r3node-rust/casper/src/rust/rholang/runtime.rs:2874` where
//! `rand.next()` fixes `return_name`.
//!
//! All verbs below assemble this preamble plus a verb-specific body. They
//! return `Snippet` wrapping the generated Rholang source.

use std::borrow::Cow;

use crate::urn::FS_AGENT_URN;

/// A ready-to-deploy Rholang program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet(pub String);

impl Snippet {
    /// The Rholang source text.
    pub fn term(&self) -> &str {
        &self.0
    }
}

/// Builder for one FUSE operation.
///
/// Fluent API so each verb reads clearly in call-site code and so the
/// generated Rholang is easy to inspect in logs during development.
pub struct SnippetBuilder {
    fs_urn: Cow<'static, str>,
}

impl Default for SnippetBuilder {
    fn default() -> Self {
        Self {
            fs_urn: Cow::Borrowed(FS_AGENT_URN),
        }
    }
}

impl SnippetBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the Fs agent URN (test shards or custom deployments).
    pub fn with_fs_urn(mut self, urn: impl Into<Cow<'static, str>>) -> Self {
        self.fs_urn = urn.into();
        self
    }

    fn preamble(&self) -> String {
        format!(
            "new return, rl(`rho:registry:lookup`), fsCh in {{\n  \
             rl!(`{urn}`, *fsCh) |\n  \
             for (@(_, fs) <- fsCh) {{\n",
            urn = self.fs_urn,
        )
    }

    fn finish(body: String) -> Snippet {
        Snippet(format!("{body}  }}\n}}\n"))
    }

    // ----------------------------------------------------------------
    // Read-only verbs (safe for ExploratoryDeploy).
    // ----------------------------------------------------------------

    /// `Dir.stat(rel)` on the directory identified by `dir_name` from the
    /// static bundle. Reply shape: `[true, {record}]` or `[false, code, msg]`.
    pub fn dir_stat(&self, dir_name: &str, rel: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r\"}})) {{\n      \
             for (@reply <- @dir!?(\"stat\", {rel})) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel = rho_str(rel),
        );
        Self::finish(body)
    }

    /// `Dir.entries()` — list a directory's children. Reply:
    /// `[true, [[name, kind, size, mode], ...]]` or `[false, code, msg]`.
    pub fn dir_entries(&self, dir_name: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r\"}})) {{\n      \
             for (@reply <- @dir!?(\"entries\")) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
        );
        Self::finish(body)
    }

    /// `Dir.exists(rel)` → `[true, bool]` or `[false, code, msg]`.
    pub fn dir_exists(&self, dir_name: &str, rel: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r\"}})) {{\n      \
             for (@reply <- @dir!?(\"exists\", {rel})) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel = rho_str(rel),
        );
        Self::finish(body)
    }

    /// `File.bytesAt(offset, length)` — read `length` bytes starting at
    /// `offset` from a top-level bundle entry. Reply: `[true, bytes]`.
    /// Opens the file in "r" mode and closes it. Honors
    /// `MAX_READ_BYTES = 64 MiB` from the native layer.
    pub fn file_read_at(&self, file_name: &str, offset: u64, length: u64) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r\"}})) {{\n      \
             for (@reply <- @f!?(\"bytesAt\", {offset}, {length})) {{\n        \
             return!(reply) |\n        \
             @f!?(\"close\") // discard reply\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            fn_ = rho_str(file_name),
        );
        Self::finish(body)
    }

    /// Open the bundle-entry dir `dir_name`, open a file within it by
    /// relative path, read `length` bytes starting at `offset`, close
    /// everything. Reply: `[true, bytes]`.
    pub fn dir_read_file_at(&self, dir_name: &str, rel: &str, offset: u64, length: u64) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r\"}})) {{\n      \
             for (@[true, f] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"r\"}})) {{\n        \
             for (@reply <- @f!?(\"bytesAt\", {offset}, {length})) {{\n          \
             return!(reply) |\n          \
             @f!?(\"close\")\n        \
             }}\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel_ = rho_str(rel),
        );
        Self::finish(body)
    }

    /// `File.size()` → `[true, int]` or `[false, code, msg]`.
    pub fn file_size(&self, file_name: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r\"}})) {{\n      \
             for (@reply <- @f!?(\"size\")) {{\n        \
             return!(reply) |\n        \
             @f!?(\"close\")\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            fn_ = rho_str(file_name),
        );
        Self::finish(body)
    }

    // ----------------------------------------------------------------
    // Mutators (require signed deploy + propose).
    // ----------------------------------------------------------------

    /// `File.writeBytesAt(offset, maxLength, byteStream)` writing a literal
    /// byte array. We cap the stream to `bytes.len()` so a short payload
    /// doesn't overrun.
    pub fn file_write_at(&self, file_name: &str, offset: u64, bytes: &[u8]) -> Snippet {
        let len = bytes.len();
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r+\"}})) {{\n      \
             new byteStream in {{\n        \
             byteStream!({payload}) |\n        \
             for (@reply <- @f!?(\"writeBytesAt\", {offset}, {len}, *byteStream)) {{\n          \
             return!(reply) |\n          \
             @f!?(\"close\")\n        \
             }}\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            fn_ = rho_str(file_name),
            payload = rho_byte_array(bytes),
        );
        Self::finish(body)
    }

    /// Open the bundle-entry dir `dir_name`, open a file within it by
    /// relative path in `r+` mode, write bytes at `offset`, close.
    /// Reply: `[true, nWritten]`.
    pub fn dir_write_file_at(
        &self,
        dir_name: &str,
        rel: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Snippet {
        let len = bytes.len();
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"rw\"}})) {{\n      \
             for (@[true, f] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"r+\"}})) {{\n        \
             new byteStream in {{\n          \
             byteStream!({payload}) |\n          \
             for (@reply <- @f!?(\"writeBytesAt\", {offset}, {len}, *byteStream)) {{\n            \
             return!(reply) |\n            \
             @f!?(\"close\")\n          \
             }}\n        \
             }}\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel_ = rho_str(rel),
            payload = rho_byte_array(bytes),
        );
        Self::finish(body)
    }

    /// Open the bundle-entry dir, open a file within it, truncate to
    /// `new_len`, close.
    pub fn dir_truncate_file(&self, dir_name: &str, rel: &str, new_len: u64) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"rw\"}})) {{\n      \
             for (@[true, f] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"r+\"}})) {{\n        \
             for (@reply <- @f!?(\"truncate\", {new_len})) {{\n          \
             return!(reply) |\n          \
             @f!?(\"close\")\n        \
             }}\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel_ = rho_str(rel),
        );
        Self::finish(body)
    }

    /// `File.truncate(n)` — set file length to `n`.
    pub fn file_truncate(&self, file_name: &str, new_len: u64) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r+\"}})) {{\n      \
             for (@reply <- @f!?(\"truncate\", {new_len})) {{\n        \
             return!(reply) |\n        \
             @f!?(\"close\")\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            fn_ = rho_str(file_name),
        );
        Self::finish(body)
    }

    /// `File.chmod(mode)` — change the POSIX mode bits (passed as the mode
    /// string, e.g. `"0644"`). The native handler ignores host-side effects
    /// in consensus mode but still journals the intent.
    pub fn file_chmod(&self, file_name: &str, mode: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r+\"}})) {{\n      \
             for (@reply <- @f!?(\"chmod\", {mode_})) {{\n        \
             return!(reply) |\n        \
             @f!?(\"close\")\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            fn_ = rho_str(file_name),
            mode_ = rho_str(mode),
        );
        Self::finish(body)
    }

    /// `Dir.removeFile(rel)` — unlink a file within `dir_name`.
    pub fn dir_remove_file(&self, dir_name: &str, rel: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"rw\"}})) {{\n      \
             for (@reply <- @dir!?(\"removeFile\", {rel})) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel = rho_str(rel),
        );
        Self::finish(body)
    }

    /// `Dir.removeDir(rel, options)` — remove `rel` inside `dir_name`.
    /// `recursive=true` enables tree deletion.
    pub fn dir_remove_dir(&self, dir_name: &str, rel: &str, recursive: bool) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"rw\"}})) {{\n      \
             for (@reply <- @dir!?(\"removeDir\", {rel}, {{\"recursive\": {recursive}}})) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel = rho_str(rel),
        );
        Self::finish(body)
    }

    /// `Dir.rename(from, to)` — rename within one directory.
    pub fn dir_rename(&self, dir_name: &str, from_rel: &str, to_rel: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"rw\"}})) {{\n      \
             for (@reply <- @dir!?(\"rename\", {from_}, {to})) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            from_ = rho_str(from_rel),
            to = rho_str(to_rel),
        );
        Self::finish(body)
    }

    /// `Dir.chmod(rel, mode)` — change mode of an entry inside a dir.
    pub fn dir_chmod(&self, dir_name: &str, rel: &str, mode: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"rw\"}})) {{\n      \
             for (@reply <- @dir!?(\"chmod\", {rel}, {mode_})) {{\n        \
             return!(reply)\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel = rho_str(rel),
            mode_ = rho_str(mode),
        );
        Self::finish(body)
    }
}

/// Quote a string for inclusion as a Rholang `GString` literal. Rholang
/// uses backslash escaping similar to JSON for the strings we actually
/// generate (bundle names, relative paths, mode strings). We don't support
/// arbitrary content here — the input must be printable ASCII/UTF-8.
fn rho_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Emit a Rholang `ByteArray` literal from a `&[u8]`. The spec prefers
/// `"0x…".hexToBytes()` for brevity so we use that form.
fn rho_byte_array(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "\"\".hexToBytes()".to_string();
    }
    format!("\"0x{}\".hexToBytes()", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_mentions_fs_urn_and_registry_lookup() {
        let b = SnippetBuilder::new();
        let s = b.dir_entries("root");
        assert!(s.term().contains(FS_AGENT_URN));
        assert!(s.term().contains("rho:registry:lookup"));
        assert!(s.term().starts_with("new return"));
    }

    #[test]
    fn custom_fs_urn_is_honored() {
        let s = SnippetBuilder::new()
            .with_fs_urn("rho:id:testshardfs")
            .dir_entries("root");
        assert!(s.term().contains("rho:id:testshardfs"));
        assert!(!s.term().contains("rho:id:zphjgsfy"));
    }

    #[test]
    fn file_read_at_includes_offset_length_and_close() {
        let s = SnippetBuilder::new().file_read_at("doc", 128, 4096);
        let t = s.term();
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"bytesAt\""));
        assert!(t.contains(" 128, 4096)"));
        assert!(t.contains("\"close\""));
    }

    #[test]
    fn dir_write_file_at_nests_dir_openfile_r_plus_and_writebytes() {
        let s = SnippetBuilder::new().dir_write_file_at("root", "a.txt", 42, b"hi");
        let t = s.term();
        assert!(t.contains("\"openDir\""));
        assert!(t.contains("\"rw\""));
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"a.txt\""));
        assert!(t.contains("\"r+\""));
        assert!(t.contains("\"writeBytesAt\""));
        assert!(t.contains(" 42, 2, "));
        assert!(t.contains("\"0x6869\".hexToBytes()"));
        assert!(t.contains("\"close\""));
    }

    #[test]
    fn dir_truncate_file_opens_r_plus_and_calls_truncate() {
        let s = SnippetBuilder::new().dir_truncate_file("root", "a.txt", 0);
        let t = s.term();
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"r+\""));
        assert!(t.contains("\"truncate\", 0"));
        assert!(t.contains("\"close\""));
    }

    #[test]
    fn dir_read_file_at_nests_dir_openfile_and_bytesat() {
        let s = SnippetBuilder::new().dir_read_file_at("root", "sub/x.txt", 0, 10);
        let t = s.term();
        assert!(t.contains("\"openDir\""));
        assert!(t.contains("\"root\""));
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"sub/x.txt\""));
        assert!(t.contains("\"bytesAt\""));
        assert!(t.contains(" 0, 10)"));
        assert!(t.contains("\"close\""));
    }

    #[test]
    fn file_write_at_encodes_bytes_as_hex() {
        let s = SnippetBuilder::new().file_write_at("doc", 0, b"hi");
        let t = s.term();
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"r+\""));
        assert!(t.contains("\"writeBytesAt\""));
        assert!(t.contains(" 0, 2, "));
        assert!(t.contains("\"0x6869\".hexToBytes()"));
    }

    #[test]
    fn remove_dir_passes_recursive_flag() {
        let non_recursive = SnippetBuilder::new().dir_remove_dir("root", "sub", false);
        let recursive = SnippetBuilder::new().dir_remove_dir("root", "sub", true);
        assert!(non_recursive.term().contains("\"recursive\": false"));
        assert!(recursive.term().contains("\"recursive\": true"));
    }

    #[test]
    fn rename_quotes_both_paths() {
        let s = SnippetBuilder::new().dir_rename("root", "a/b", "c/d");
        let t = s.term();
        assert!(t.contains("\"rename\""));
        assert!(t.contains("\"a/b\""));
        assert!(t.contains("\"c/d\""));
    }

    #[test]
    fn rho_str_escapes_backslash_quote_and_newline() {
        assert_eq!(rho_str(r#"a"b\n"#), r#""a\"b\\n""#);
    }

    #[test]
    fn rho_byte_array_empty() {
        assert_eq!(rho_byte_array(&[]), "\"\".hexToBytes()");
    }
}
