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

    /// Shape of a dir-method snippet with explicit failure forwarding.
    ///
    /// This is the hand-written expansion of the File-I/O FIP's
    /// try/catch sugar (FIP 2026-02-06 §"Error syntax"), which looks
    /// like:
    ///
    /// ```rholang
    /// try @[dir] <- @fs!?("openDir", name, opts) { <body> }
    /// catch @err { return!([false] ++ err) }
    /// ```
    ///
    /// The parser desugars it to the `for … / if ok / let` form we
    /// emit below. We emit the desugared form directly for two reasons:
    ///
    ///   1. The deployed f1r3fly-rust image at the time of writing
    ///      predates the parser's try_block integration — the keyword
    ///      `try` still parses as a bare identifier and the submission
    ///      is rejected with `UnexpectedVar`. Once the image carries
    ///      a parser from rholang-rs 02cef80+ we can swap this helper
    ///      to emit literal `try`/`catch` keywords with no behavioral
    ///      change.
    ///   2. The sugar lives in the parser only; the on-wire term the
    ///      node evaluates is the desugared form either way, so our
    ///      WAL / consensus fingerprint is independent of which form
    ///      we emit.
    ///
    /// The outer `[ok, ...rest]` destructuring puts the Fs agent's
    /// first element in `ok` and the tail in `rest`. On the success
    /// branch we destructure `rest` into the caller-chosen shape
    /// (here `[dir]`). On the failure branch we destructure `rest` as
    /// `[code, msg]` and forward the full `[false, code, msg]` to the
    /// return channel so the client's `decode_reply` can report a
    /// canonical `FSERR_*` back to FUSE.
    fn dir_method(&self, dir_name: &str, mode: &str, body: impl FnOnce(&str) -> String) -> Snippet {
        let inner = body("dir");
        let s = format!(
            "{}    \
             for (@[ok, ...rest] <- @fs!?(\"openDir\", {dn}, {{\"mode\": {mode_}}})) {{\n      \
             if (ok) {{\n        \
             let @[dir] <- rest in {{\n          \
             {inner}        \
             }}\n      \
             }} else {{\n        \
             let @[code, msg] <- rest in {{\n          \
             return!([false, code, msg])\n        \
             }}\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            mode_ = rho_str(mode),
        );
        Self::finish(s)
    }

    /// `Dir.stat(rel)` on the directory identified by `dir_name` from the
    /// static bundle. Reply shape: `[true, {record}]` or `[false, code, msg]`.
    pub fn dir_stat(&self, dir_name: &str, rel: &str) -> Snippet {
        self.dir_method(dir_name, "r", |dir| {
            format!(
                "for (@reply <- @{dir}!?(\"stat\", {rel})) {{\n            \
                 return!(reply)\n          \
                 }}\n",
                rel = rho_str(rel),
            )
        })
    }

    /// `Dir.entries()` — list a directory's children. On dev the method
    /// returns a Stream iterator cap `[true, stream]`; we materialize up
    /// to `MAX_CHUNK_ITEMS` (65_536) entries into a flat list via
    /// `stream.chunk(n)` so the client sees `[true, [{stat1}, ...]]`
    /// unchanged from the pre-stream shape. Reply:
    /// `[true, [{stat records}, ...]]` or `[false, code, msg]`.
    pub fn dir_entries(&self, dir_name: &str) -> Snippet {
        self.dir_method(dir_name, "r", |dir| {
            format!(
                "for (@entriesReply <- @{dir}!?(\"entries\")) {{\n            \
                 match entriesReply {{\n              \
                 [true, stream] => {{\n                \
                 for (@chunkReply <- @stream!?(\"chunk\", 65536)) {{\n                  \
                 return!(chunkReply)\n                \
                 }}\n              \
                 }}\n              \
                 _ => return!(entriesReply)\n            \
                 }}\n          \
                 }}\n",
            )
        })
    }

    /// `Dir.exists(rel)` → `[true, bool]` or `[false, code, msg]`.
    pub fn dir_exists(&self, dir_name: &str, rel: &str) -> Snippet {
        self.dir_method(dir_name, "r", |dir| {
            format!(
                "for (@reply <- @{dir}!?(\"exists\", {rel})) {{\n            \
                 return!(reply)\n          \
                 }}\n",
                rel = rho_str(rel),
            )
        })
    }

    /// `File.bytesAt(offset, length)` — read `length` bytes starting at
    /// `offset` from a top-level bundle entry. Reply: `[true, bytes]`.
    /// Opens the file in "r" mode and closes it. Honors
    /// `MAX_READ_BYTES = 64 MiB` from the native layer.
    pub fn file_read_at(&self, file_name: &str, offset: u64, length: u64) -> Snippet {
        // bytesAt returns a byte Stream whose chunk method is one
        // `next()` call per byte (per Stream.rho §chunk / ByteStream
        // chunkBuilder) — a 32 KiB read then costs 32 K deploy-local
        // COMMs and runs well past the exploratory execution budget on
        // dev. seek(offset,"start") + readN(length) hits `fs_read`
        // directly instead and finishes in ~180 ms for 32 KiB. Reply:
        // `[true, bytes]` or `[false, code, msg]`.
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r\"}})) {{\n      \
             for (@_seekReply <- @f!?(\"seek\", {offset}, \"set\")) {{\n        \
             for (@readReply <- @f!?(\"readN\", {length})) {{\n          \
             for (@_closeReply <- @f!?(\"close\")) {{\n            \
             return!(readReply)\n          \
             }}\n        \
             }}\n      \
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
        // See `file_read_at` for why we take the seek+readN path
        // instead of bytesAt+stream.chunk — same perf cliff on dev's
        // ByteStream chunk impl.
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r\"}})) {{\n      \
             for (@[true, f] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"r\"}})) {{\n        \
             for (@_seekReply <- @f!?(\"seek\", {offset}, \"set\")) {{\n          \
             for (@readReply <- @f!?(\"readN\", {length})) {{\n            \
             for (@_closeReply <- @f!?(\"close\")) {{\n              \
             return!(readReply)\n            \
             }}\n          \
             }}\n        \
             }}\n      \
             }}\n    \
             }}\n",
            self.preamble(),
            dn = rho_str(dir_name),
            rel_ = rho_str(rel),
        );
        Self::finish(body)
    }

    /// Create a new empty file at `rel` under bundle dir `dir_name` by
    /// opening it in `w+` mode (POSIX "truncate-or-create + read-write")
    /// and immediately closing. Reply shape: `[true]` on success,
    /// `[false, code, msg]` on failure. The on-disk file lands with
    /// mode 0o644 and zero length.
    pub fn dir_create_file(&self, dir_name: &str, rel: &str) -> Snippet {
        let body = format!(
            "{}    \
             for (@[ok, ...rest] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
             if (ok) {{\n        \
             let @[dir] <- rest in {{\n          \
             for (@[ok2, ...rest2] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"w+\"}})) {{\n            \
             if (ok2) {{\n              \
             let @[f] <- rest2 in {{\n                \
             for (@closeReply <- @f!?(\"close\")) {{\n                  \
             return!([true])\n                \
             }}\n              \
             }}\n            \
             }} else {{\n              \
             let @[code, msg] <- rest2 in {{\n                \
             return!([false, code, msg])\n              \
             }}\n            \
             }}\n          \
             }}\n        \
             }}\n      \
             }} else {{\n        \
             let @[code, msg] <- rest in {{\n          \
             return!([false, code, msg])\n        \
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
             for (@_closeReply <- @f!?(\"close\")) {{\n          \
             return!(reply)\n        \
             }}\n      \
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
    /// byte array. The server's `writeBytesAtLoop` consumes `byteStream`
    /// via `stream!?("next")` / `stream!?("close")` — i.e. a producer
    /// contract, not a bare channel. We synthesize a one-shot producer
    /// that returns the whole payload on first `"next"` and nil-replies
    /// on `"close"`; because the loop advances `remaining` by chunk
    /// length and exits via `remaining == 0 → close + ret!([true])`,
    /// the one-shot form is sufficient when `maxLength == bytes.len()`.
    pub fn file_write_at(&self, file_name: &str, offset: u64, bytes: &[u8]) -> Snippet {
        let len = bytes.len();
        let body = format!(
            "{}    \
             for (@[true, f] <- @fs!?(\"openFile\", {fn_}, {{\"mode\": \"r+\"}})) {{\n      \
             new byteStream in {{\n        \
             contract byteStream(ret, @cmd) = {{\n          \
             match cmd {{\n            \
             \"next\"  => ret!([true, {payload}])\n            \
             \"close\" => ret!([true])\n          \
             }}\n        \
             }} |\n        \
             for (@reply <- @f!?(\"writeBytesAt\", {offset}, {len}, *byteStream)) {{\n          \
             for (@_closeReply <- @f!?(\"close\")) {{\n            \
             return!(reply)\n          \
             }}\n        \
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
    /// Reply: `[true, nWritten]`. See [`Self::file_write_at`] for the
    /// one-shot producer rationale.
    pub fn dir_write_file_at(
        &self,
        dir_name: &str,
        rel: &str,
        offset: u64,
        bytes: &[u8],
    ) -> Snippet {
        // writeBytesAt is a POSIX pwrite under the hood (positional,
        // doesn't touch the shadow cursor). The server's one-shot
        // producer-contract protocol is correct for a single chunk per
        // deploy. Parallel deploys that each pwrite to non-overlapping
        // ranges should commute — if they don't, that's a server-side
        // bug we're surfacing (see f1r3drive-rust bug report).
        let len = bytes.len();
        let body = format!(
            "{}    \
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
             for (@[true, f] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"r+\"}})) {{\n        \
             new byteStream in {{\n          \
             contract byteStream(ret, @cmd) = {{\n            \
             match cmd {{\n              \
             \"next\"  => ret!([true, {payload}])\n              \
             \"close\" => ret!([true])\n            \
             }}\n          \
             }} |\n          \
             for (@reply <- @f!?(\"writeBytesAt\", {offset}, {len}, *byteStream)) {{\n            \
             for (@_closeReply <- @f!?(\"close\")) {{\n              \
             return!(reply)\n            \
             }}\n          \
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
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
             for (@[true, f] <- @dir!?(\"openFile\", {rel_}, {{\"mode\": \"r+\"}})) {{\n        \
             for (@reply <- @f!?(\"truncate\", {new_len})) {{\n          \
             for (@_closeReply <- @f!?(\"close\")) {{\n            \
             return!(reply)\n          \
             }}\n        \
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
             for (@_closeReply <- @f!?(\"close\")) {{\n          \
             return!(reply)\n        \
             }}\n      \
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
             for (@_closeReply <- @f!?(\"close\")) {{\n          \
             return!(reply)\n        \
             }}\n      \
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
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
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
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
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
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
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
             for (@[true, dir] <- @fs!?(\"openDir\", {dn}, {{\"mode\": \"r+\"}})) {{\n      \
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
    // Rholang's `"0xHEX".hexToBytes()` treats the hex as a signed-BigInt
    // encoding and PREPENDS a 0x00 sign byte to the result, so a 4-byte
    // input `CAFEBABE` becomes 5 bytes `00 CA FE BA BE`. Drop that
    // leading byte with `.slice(1, N+1)` to get back the raw N bytes we
    // intended. Verified against `fileio_fs_spec` fixtures that use the
    // same slice idiom.
    let n = bytes.len();
    format!(
        "\"0x{}\".hexToBytes().slice(1, {end})",
        hex::encode(bytes),
        end = n + 1,
    )
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
        // Uses seek+readN to avoid the ByteStream-chunk per-byte cost.
        assert!(t.contains("\"seek\", 128, \"set\""));
        assert!(t.contains("\"readN\", 4096"));
        assert!(t.contains("\"close\""));
    }

    #[test]
    fn dir_write_file_at_nests_dir_openfile_r_plus_and_writebytes() {
        let s = SnippetBuilder::new().dir_write_file_at("root", "a.txt", 42, b"hi");
        let t = s.term();
        assert!(t.contains("\"openDir\""));
        // dev whitelists dir modes to {"r","r+"}; the dir and file are
        // both opened "r+".
        assert!(t.contains("\"r+\""));
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"a.txt\""));
        assert!(t.contains("\"writeBytesAt\", 42, 2, "));
        assert!(t.contains("\"0x6869\".hexToBytes().slice(1, 3)"));
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
    fn dir_create_file_opens_w_plus_and_closes() {
        let s = SnippetBuilder::new().dir_create_file("root", "newfile.txt");
        let t = s.term();
        assert!(t.contains("\"openDir\""));
        // dev's Dir mode whitelist is {"r","r+"}; mutators open the dir
        // in "r+" and then open the leaf file in a mutating mode.
        assert!(t.contains("\"r+\""));
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"newfile.txt\""));
        assert!(t.contains("\"w+\""));
        assert!(t.contains("\"close\""));
        assert!(t.contains("return!([true])"));
    }

    #[test]
    fn dir_read_file_at_nests_dir_openfile_and_seek_readn() {
        let s = SnippetBuilder::new().dir_read_file_at("root", "sub/x.txt", 0, 10);
        let t = s.term();
        assert!(t.contains("\"openDir\""));
        assert!(t.contains("\"root\""));
        assert!(t.contains("\"openFile\""));
        assert!(t.contains("\"sub/x.txt\""));
        // Uses seek+readN to avoid the ByteStream-chunk per-byte cost.
        assert!(t.contains("\"seek\", 0, \"set\""));
        assert!(t.contains("\"readN\", 10"));
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
