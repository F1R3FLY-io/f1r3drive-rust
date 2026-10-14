# Architecture

## Layering

```
┌──────────────────────────────────────────────────────────────┐
│                    kernel                                     │
│                        │                                      │
│                        │  NFSv4 (fuse-t) or /dev/fuse (Linux) │
│                        ▼                                      │
├──────────────────────────────────────────────────────────────┤
│                      libfuse-t                                │
│  Userspace NFSv4 server + libfuse 2.9 shim; no kext.          │
└──────────────────────────────────────────────────────────────┘
                         │  C API: fuse_operations
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                libfuse-t-sys  (unsafe FFI)                    │
│                        │                                      │
│                        ▼                                      │
│                libfuse-t-rs   (safe wrapper)                  │
│  - `Filesystem` trait with path-oriented ops                  │
│  - `extern "C"` trampolines with panic isolation              │
│  - RAII `BackgroundSession`                                   │
└──────────────────────────────────────────────────────────────┘
                         │  trait call: fs.getattr(&Path) etc.
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                    f1r3drive-fs                               │
│  - `F1r3Fs: Filesystem`                                       │
│  - Path → bundle-relative string                              │
│  - Blocks fuser-callback thread via tokio runtime handle      │
└──────────────────────────────────────────────────────────────┘
                         │  (snippet, signer, shard_id)
                         ▼
┌──────────────────────────────────────────────────────────────┐
│    f1r3drive-rho               f1r3drive-client               │
│  - `SnippetBuilder`           - `NodeClient` (tonic)           │
│  - Rholang term generation    - secp256k1 ECDSA DER signing    │
│  - Reply decoding             - exploratory_deploy / do_deploy │
└──────────────────────────────────────────────────────────────┘
                         │  gRPC
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                    f1r3node                                   │
│  On-chain `Fs` agent at                                        │
│  `rho:id:zphjgsfy13h1k85isc8rtwtgt3t9zzt5pjd5ihykfmyapfc4wt3x5h` │
│  dispatches to the 28 native `fs_*` handlers.                 │
└──────────────────────────────────────────────────────────────┘
```

## Why not `fuser`?

`fuser` speaks the Linux `/dev/fuse` kernel protocol directly: it reads
raw FUSE messages from a file descriptor returned by `fuse_mount` (or
the kernel-opened `/dev/fuse`). This works on Linux and on macFUSE
(which ships a kext that exposes a `/dev/osxfuse` carrying the same
protocol).

`fuse-t` has no kernel component and no `/dev/fuse`-like fd. Its
`libfuse-t.dylib` presents the libfuse 2.9 **high-level C API** — you
register callbacks in a `fuse_operations` table and `fuse_loop_mt`
dispatches NFSv4 requests into them.

The two models are mutually incompatible: fuser's symbols link against
libfuse-t (both export `fuse_mount_compat25`, etc.), but the ABI the
daemon fd carries is different. During development we observed the mount
handshake succeed with fuser 0.14 and 0.18, but only the initial `/`
`getattr` would fire — every subsequent op was absorbed by libfuse-t
without reaching fuser's event loop.

This is why we ship our own `libfuse-t-sys` + `libfuse-t-rs` crates
instead of using an existing FUSE binding on macOS.

## Rholang snippet shape

Every FUSE op compiles to a Rholang program like:

```rholang
new return, rl(`rho:registry:lookup`), fsCh in {
  rl!(`rho:id:zphj…wt3x5h`, *fsCh) |
  for (@(_, fs) <- fsCh) {
    // op-specific body — leaves one Par on *return
    for (@[true, dir] <- @fs!?("openDir", "root", {"mode": "r"})) {
      for (@reply <- @dir!?("stat", "foo/bar.txt")) {
        return!(reply)
      }
    }
  }
}
```

The leading `new return` is load-bearing: f1r3node extracts the deploy's
return value from the first unforgeable name allocated at the top-level
`new`. We shape every snippet to leave at most one `Par` sent on that
name; the client decodes it.

## Reply decoding

Replies follow one of three shapes:

- `[true]` — op succeeded, no payload.
- `[true, payload]` — op succeeded, payload is op-specific (bytes for
  `read`, int for `size`, map for `stat`, list of maps for `entries`).
- `[false, "FSERR_*", "message"]` — the agent rejected the op.

`f1r3drive-rho::decode_reply` returns a typed `FsReply` and
`f1r3drive-rho::par_as_stat_record` / `par_as_bytes` / `par_as_list` do
the per-shape unwrapping. `FSERR_*` codes map to the appropriate FUSE
error at the `f1r3drive-fs` layer.

## Threading model

- The tokio runtime lives in the daemon main; `F1r3Fs` holds a `Handle`
  clone.
- `libfuse-t-rs::spawn_mount` runs `fuse_loop_mt` on a dedicated
  thread; libfuse-t's internal thread pool fans FUSE requests out to
  the trampolines.
- Each trampoline is `extern "C" fn` with no closure capture; it pulls
  the `&dyn Filesystem` from `fuse_get_context()->private_data` and
  calls the trait method.
- Trait methods are `&self + Send + Sync`; interior mutability lives in
  `Arc<tokio::sync::Mutex<NodeClient>>`.
- gRPC calls are awaited inside `runtime.block_on`, which blocks the
  calling trampoline thread. libfuse-t has multiple worker threads so
  one blocked call doesn't stall others.
- Panic isolation: every trampoline wraps its body in
  `catch_unwind`. A panicking trait method returns `-EIO` to libfuse-t
  rather than unwinding across a C stack frame.

## macOS pkg-config / rpath

fuse-t installs headers under `/usr/local/include/fuse/` and the dylib
with install name `@rpath/libfuse-t.dylib`. Three pieces knit this to
Cargo:

- `crates/libfuse-t-sys/build.rs` probes `pkg-config fuse-t` and emits
  `-lfuse-t`.
- `.cargo/config.toml` prepends `/usr/local/lib/pkgconfig` and
  `/opt/homebrew/lib/pkgconfig` to `PKG_CONFIG_PATH` so Nix dev shells
  don't hide the brew-installed .pc files.
- `.cargo/config.toml` injects `-Wl,-rpath,/usr/local/lib` into every
  macOS build via `rustflags`, since Cargo filters `rustc-link-arg`
  output from build scripts and the install name requires an rpath to
  resolve at launch.
