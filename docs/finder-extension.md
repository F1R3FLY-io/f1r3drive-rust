# macOS Finder Sync extension — adoption

Stage 7 of tokens-as-files (plan: `~/.claude/plans/tokens-as-files.md`;
design: `architecture/ADR-0001-token-as-file.md`).

**Status**: the shipping Swift extension at
[`F1R3FLY-io/f1r3drive-extension`](https://github.com/F1R3FLY-io/f1r3drive-extension)
links against the same `generic.FinderSyncExtensionService` proto
that `f1r3drive-proto` serves. **No code changes in this repo**:
f1r3drive-rust was explicitly designed to be wire-compatible with
the existing extension; adoption is a Finder-side-only operation.
This doc records the adoption path, build steps, and the install
recipe users follow.

## Wire-compatibility verification

The extension's proto file at `Protos/FinderSyncExntesionService.proto`
(note the typo in the upstream filename — preserved on their side)
is byte-identical to our vendored
`crates/f1r3drive-proto/proto/FinderSyncExtensionService.proto`
excluding the provenance header we added. Diffed on
2026-10-17 against upstream commit on branch `dev`:

```
$ gh api 'repos/F1R3FLY-io/f1r3drive-extension/contents/Protos/FinderSyncExntesionService.proto' \
    --jq .content | base64 -d \
    | diff - crates/f1r3drive-proto/proto/FinderSyncExtensionService.proto
# only our header lines differ; message / service / enum shapes agree
```

The ADR pins "treat the shape as frozen; all new surface area lands
as additional messages / services, not edits." If we need to add a
new RPC later, we land it in both repos simultaneously, keeping the
existing shape intact.

## Build + install (users)

1. Clone the extension repo:
   ```
   git clone https://github.com/F1R3FLY-io/f1r3drive-extension.git
   cd f1r3drive-extension
   ```
2. Open `f1r3drive-extensions.xcodeproj` in Xcode (16.x or newer).
3. Build the `RevFolderUnlockerApp` scheme in Release mode. The
   output is a signed `.app` bundle containing the Finder Sync
   extension.
4. Launch the app once so macOS registers the extension and the
   `f1r3drive://` URL scheme (via `CFBundleURLSchemes` in the
   bundle's `Info.plist`).
5. In **System Settings → Privacy & Security → Extensions → Finder
   Extensions**, enable the F1R3Drive extension.
6. Start the daemon from this repo in wallets mode:
   ```
   f1r3drive --mount-mode=wallets --track-address <REV> /mnt/f1r3
   ```
   The daemon's extension gRPC will listen on `127.0.0.1:40411`
   by default — the extension expects that same port, inherited
   from the Java daemon's convention.

## Install recipe (CI / scripted)

A reproducible notarize + install path is a v2 release concern. For
dev, `xcodebuild archive` + `xcodebuild -exportArchive` against the
repo's `ExportOptions.plist` produces an unsigned `.app` fine; the
first-launch macOS gatekeeper prompt is the only extra step.

## URL-scheme handoff

The `.app` bundle registers scheme `f1r3drive://`. When macOS opens
an `f1r3drive://unlock?revAddress=...&privateKey=...` URL (e.g. the
user clicks a link in a password manager), the OS routes it to the
bundle, which shells out to:

```
f1r3drive --open-url 'f1r3drive://unlock?...'
```

The daemon (running separately — the extension does NOT spawn it)
receives the forwarded `UnlockWalletDirectory` RPC on its loopback
port and promotes the wallet from `LOCKED-REMOTE-REV-*` to the
unlocked `/<addr>/` form. See `../crates/f1r3drive-ext/src/deep_link.rs`
for the Rust-side parser + forwarder.

## Divergence watch

The Java daemon's extension sends paths as absolute paths from the
user's filesystem. Our ext server strips the mountpoint prefix
before classifying — see `ExtensionService::resolve` in
`crates/f1r3drive-ext/src/lib.rs`. If the Swift side ever changes
its path format (relative, URL-encoded, etc.) this is where to
update.

## Verification matrix

| Behavior                                       | Verified against                                   |
|------------------------------------------------|----------------------------------------------------|
| Proto wire bytes identical                     | `diff` against upstream `Protos/*.proto`           |
| `SubmitAction(CHANGE, path)` round-trips       | `grpcurl` smoke test; e2e lands with Stage 8       |
| `SubmitAction(COMBINE, _)` returns error       | Covered by `f1r3drive-ext` unit tests              |
| `UnlockWalletDirectory` promotes               | Covered by `f1r3drive-ext` unit tests + manual     |
| `f1r3drive://unlock` deep link forwards        | Stage 6 unit tests; manual with running daemon     |

## Non-goals

- **No f1r3drive-rust-extension fork.** The upstream extension is
  the one source of truth; forking creates two codepaths to keep
  wire-compatible. If upstream becomes unmaintained we revisit.
- **No bundled installer in this repo.** The Rust daemon is a CLI;
  the `.app` bundle lives in the extension repo.
- **No automatic daemon spawn from the extension.** Users start
  the daemon separately via `f1r3drive --mount-mode=wallets ...`.
  The ADR notes that bundling + autostart lands with a Stage-7+
  app packaging effort if we take it on.
