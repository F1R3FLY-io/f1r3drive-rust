# ADR-0003: Stateless SELF envelopes — ECIES-wrapped K, no keystore

- **Status**: Accepted
- **Date**: 2026-10-27
- **Supersedes**: part of [ADR-0002](ADR-0002-extension-design.md) §"On-chain blob format" (SELF envelope shape) and §"Local state" (the `keys/` subdirectory).

## Context

ADR-0002 defined two blob envelope formats:

- **SELF** — the owner wrote it to themself. The envelope carries
  `blake2b256(K)` and the AES-GCM-sealed body; the symmetric key `K`
  lives in a separate on-disk keystore at
  `~/.f1r3drive/keys/<hex(blake2b256(K))>`.
- **RECV** — someone sent it to a specific recipient. The envelope
  carries `ECIES(recipient_pubkey, K)` directly and is fully
  self-contained — the recipient's identity private key is sufficient
  to decrypt.

RECV is self-contained. SELF requires a side table.

### Pain points of the keystore side table

- **GC complexity.** `gc_orphaned_key` scans every own-prefix blob
  looking for other references to a key fingerprint before deleting
  it. O(N blobs) per unlink / rename / write-overwrite.
- **State drift risk.** The daemon writes the key file to
  `~/.f1r3drive/keys/` and the blob to the chain in two separate
  I/O paths. If the keystore write fails after the blob lands, the
  blob is unreadable until the daemon re-mints the key — which can't
  happen because the fingerprint is baked into the on-chain blob.
- **Backup burden.** Restoring daemon state from a backup requires
  restoring the keystore directory. Losing it means every SELF blob
  on-chain becomes unreadable. The chain is replicated; the keystore
  isn't.
- **Fingerprint linkability.** `blake2b256(K)` leaks a stable
  identifier for `K` across all blobs that share it. A chain observer
  can group blobs by fingerprint even without decrypting them. The
  RECV envelope's ECIES wrapper has no such linkable identifier (each
  wrap uses a fresh ephemeral key).
- **Code surface.** The keystore adds ~140 LOC (`crates/f1r3drive-crypto/src/keystore.rs`),
  plus `self_key_for`, `self_key_fingerprint`, `gc_replaced_blob`,
  `gc_orphaned_key` in `extension_fs.rs`, plus every test fixture.
  All of it goes away.

### Why the keystore existed in the first place

Legitimate reasons at the time of ADR-0002:
- **Performance.** AES-GCM is faster than ECIES by ~1 ms per op.
- **Key reuse.** Multiple files could share a single `K` and only
  pay keystore cost once.

Both arguments weaken in practice:
- ADR-0002's hot path never actually reuses `K`; every `flush_pending`
  mints a fresh key via `generate_key()`. The keystore holds exactly
  one entry per blob, same cardinality it would hold with a
  per-blob self-ECIES wrap. The reuse benefit is theoretical.
- The daemon already caches decrypted plaintext in `read_cache` and
  size in `size_cache`, so the ECIES cost is paid once per blob per
  mount session, not once per `read()`.

## Decision

Define a new envelope tag `SLFW` ("SELF with Wrapped K") for own-side
blobs. The format mirrors RECV targeted at the owner's own pubkey:

```text
SLFW: "SLFW" || ECIES(own_pubkey, K) || AES-GCM(K, hdr || padded_plaintext)
```

Decryption uses the owner's identity private key (same key that
unwraps RECV blobs). The AES-GCM body shape — header + bucket-padded
plaintext — is unchanged from `SELF`/`RECV`.

The `SELF` tag is NOT redefined: legacy fingerprint-indexed blobs on
chain continue to decrypt via the existing keystore path. The daemon
distinguishes by inspecting the first four bytes of each envelope.

### Why keep `SELF` and `SLFW` as distinct tags

`SLFW` and `RECV` have the same wire shape and same decryption
procedure. The semantic distinction (own vs received) still matters:
- The owner's `readdir` lists SELF+SLFW+RECV; a non-owner can't
  decrypt any of them, but tooling that inspects on-chain state
  (debugging, auditing) benefits from a clean "I wrote this" vs
  "someone sent this to me" tag.
- Future ACL work (e.g. selective pre-purchase browsing of folder
  listings) may differentiate ownership intent at the envelope level.
- Collapsing to a single tag can happen later; keeping them distinct
  now has no downside and preserves optionality.

## Migration

### Dual-decrypt forever

`envelope::unwrap(blob, &own_privkey, &keystore)` dispatches on tag:
- `b"SELF"` → look up K in keystore by fingerprint, AES-decrypt.
- `b"SLFW"` → ECIES-unwrap K with `own_privkey`, AES-decrypt.
- `b"RECV"` → ECIES-unwrap K with `own_privkey`, AES-decrypt (unchanged).

Legacy blobs stay readable indefinitely without migration.

### Eager startup migration pass

`ExtensionFs::with_registry` performs a one-time migration at mount
time:

1. `blobs.list(own_pubkey)` to enumerate the owner's channels.
2. For each channel whose blob has tag `SELF`:
   - Load K from the keystore via the stored fingerprint.
   - If K is missing: log a warn, skip (data loss already present —
     migration can't invent K).
   - Otherwise: decrypt → re-wrap as `SLFW` with the owner's
     pubkey → put at the new channel → delete the legacy channel
     → delete the keystore entry (`keystore.delete(fp)`).
3. Log a summary: `migrated N SELF blobs → SLFW, skipped M`.

The pass is best-effort: a transient blob-store error on any single
blob logs + skips but doesn't block mount. A re-run of the daemon
retries.

Migration failures leave the legacy SELF blob intact: no data loss,
just a lagging migration.

### Keystore lifecycle after migration

- The keystore directory stays on disk and keeps serving reads for
  any legacy SELF blob that didn't migrate (e.g. because its
  key file was lost — in which case the daemon can't decrypt it
  through either path, and the migration pass itself failed to
  decrypt it).
- Factory-side K_listing in `mint_listing_*` previously went through
  the keystore. Those are owner-side too and become SLFW. The
  purchase flow's `envelope::unwrap_self(k, bundle_bytes)` already
  gets `k` directly from the factory reply — no keystore involvement
  there, so it's unaffected.
- A future ADR can drop the keystore crate entirely once we're
  confident every daemon has run through the migration.

### Mixed-version daemons

A daemon running pre-ADR-0003 code cannot read `SLFW` blobs
(`CryptoError::UnknownTag` on decrypt). This is acceptable:
- The demo setup runs identical binaries across all nodes.
- Upgrading a single daemon in a shared shard is already blocked
  by other schema invariants (listings manifest, folders manifest).

A downgrade back to pre-ADR-0003 code would leave previously-written
SLFW blobs unreadable. We do not plan to support downgrade; a user
rolling back would need to also roll back their on-chain state.

## Consequences

### Positive

- Daemon state fits in a single file (`identity.key`). The
  `~/.f1r3drive/keys/` directory becomes empty after the migration
  pass and can be deleted.
- `gc_orphaned_key` + `self_key_fingerprint` + `gc_replaced_blob`'s
  key-fingerprint branch all go away (follow-up cleanup; initial
  landing keeps them for the legacy SELF path).
- "I lost my keystore" ⇒ "data is gone" failure mode is eliminated
  for all post-migration writes. Only `identity.key` matters.
- On-chain blobs no longer carry a linkable blake2b256(K)
  fingerprint. Chain observers can group blobs by owner prefix but
  not by shared key.
- SELF and RECV decryption share one code path (both ECIES-unwrap-K
  via own privkey). The only distinguishing bit becomes the tag.

### Negative

- Each own-side decrypt costs one ECIES operation (~1 ms on
  secp256k1 for the `ecies` crate v0.2) on top of the AES-GCM.
  Previously it was a keystore filesystem lookup (microseconds) +
  AES-GCM. The hit is masked by the daemon's `read_cache` and
  `size_cache` on repeated access.
- `SLFW` envelope grows by `ECIES_WRAPPED_KEY_LEN - FINGERPRINT_LEN =
  129 - 32 = 97` bytes over the legacy `SELF`. Negligible for
  content files; a 97-byte overhead per entry for the gzip-tar
  bundle inside a folder listing.
- Identity rotation now destructively affects SELF blobs (previously
  the keystore survived rotation). Mitigation: identity rotation is
  not yet a shipped feature; when it lands, the implementation must
  include a bulk re-wrap step.

### Neutral

- Factory purchase (`purchase_via_factory`) is unaffected: the
  factory's reply payload carries K directly, and we decrypt the
  bundle via a locally-passed `SymKey`.

- **Listing envelopes stay SELF.** `mint_listing_*` writes a blob
  whose eventual consumer is the buyer, who receives `K` from the
  factory and must decrypt with a caller-supplied key. The SLFW
  design ECIES-wraps K to the owner's pubkey, so a buyer with the
  factory-released K could not decrypt an SLFW listing envelope.
  Listings therefore stay in the legacy SELF format (K explicit,
  verified against the embedded fingerprint). The migration pass
  skips channels whose name matches a known listing id. A future ADR
  may introduce a third "K-explicit, no fingerprint" tag to retire
  the listing's keystore dependency as well; this ADR scopes to the
  regular own-blob case.

## References

- [ADR-0002: Encrypted per-pubkey folders + contract-folder plug-ins](ADR-0002-extension-design.md) — defines SELF/RECV in the first place.
- `crates/f1r3drive-crypto/src/envelope.rs` — envelope wire format.
- `crates/f1r3drive-crypto/src/keystore.rs` — the keystore subsystem being phased out.
- `crates/f1r3drive-fs/src/extension_fs.rs` — the FUSE-side `try_decrypt` dispatcher plus every `wrap_self` call site.
