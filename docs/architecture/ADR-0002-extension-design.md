# ADR-0002: Encrypted per-pubkey folders + contract-folder plug-ins

- **Status**: Accepted (supersedes ADR-0001's §Wallets-mode naming + CHANGE/COMBINE for Finder context menus; preserves token-as-file dedicated entries and the Finder-ext gRPC transport)
- **Date**: 2026-10-18
- **Supersedes**: parts of [ADR-0001](ADR-0001-token-as-file.md)

## Context

ADR-0001's `--mount-mode=wallets` surface models wallets as REV-address directories with `.tokens/` denominated bills. It ships (PR #12 merged) but the surface is narrow: no file content, no payment-triggered actions beyond raw token transfer, no identity-scoped privacy. The new design keeps the token-side (bills, drag-to-transfer, `.tokens/`) and adds:

- Per-user **encrypted file folders** keyed by secp256k1 public key.
- **Contract-folder plug-ins** that the daemon knows how to render as directories; dragging into them triggers templated on-chain + client-side orchestration. First template: *paid transfer* (sell a file for N REV).

## Decision drivers

- End-to-end encryption, client-side. Rholang doesn't do ECIES; the daemon handles both symmetric (AES-GCM) and asymmetric (ECIES over secp256k1) crypto locally. On-chain state stores ciphertext only.
- Owner identity is **the uncompressed secp256k1 pubkey**, not the REV address. REV addresses are derived (keccak + blake2b + base58) and lossy — you can't ECIES-encrypt against them. Pubkey folders cost 130 chars of display name; cost accepted for crypto cleanliness.
- Readdir and attribute lookups preserve **privacy by lying at the FUSE layer**. Non-owners see other users' folders exist but `ls <foreign-folder>` returns empty. Filenames and sizes do not leak. On-chain state is still readable by anyone with gRPC access — the daemon enforces, the chain doesn't.
- Contract folders are a plug-in surface. The daemon knows a fixed set of template classes; each template describes how to render its folder and what drag-event handlers it binds.

## Decisions (answers to the five gaps)

1. **Folder naming primitive**: uncompressed 130-char secp256k1 pubkey (hex of 65 bytes = `04 || x || y`). Same encoding `KeyPair::public_key_bytes()` already returns.
2. **Readdir visibility of foreign folders**: empty — the daemon returns `Vec::new()` for `readdir` on a pubkey folder whose matching private key isn't in the local keystore.
3. **Filename + size encryption**: filenames and sizes are not visible to non-owners. Filenames stored on-chain are AES-GCM-encrypted with the file's per-blob symmetric key `K` (and hex-encoded for channel-name legibility). File sizes are padded to the next bucket boundary (1 KiB, 4 KiB, 64 KiB, 1 MiB, 16 MiB) with the true size stored encrypted in the blob header.
4. **Paid-transfer lifecycle**: persistent. A uuid-folder, once created, accepts repeat purchases from different buyers until Alice deletes it.
5. **Token movement**: still through dedicated `.tokens/<denom>-REV.<i>.token` entries, now **inside** the user's own pubkey folder (not under a separate `/<revAddress>/` tree). The pubkey folder is the single identity namespace; `.tokens/` is one subtree under it.

## Decision

### Mount mode

Add `--mount-mode=extension`. The existing `--mount-mode={root,wallets}` modes stay — users on the stable UX from PR #12 are unaffected. `extension` is additive. If and when `extension` subsumes `wallets` for all users, a follow-up ADR deprecates the latter.

### Top-level tree

```text
/
├── <alice-pubkey-130hex>/                 Alice's folder; empty readdir unless caller == Alice
│   ├── .tokens/                           bills (same denomination model as ADR-0001)
│   │   └── <denom>-REV.<i>.token
│   ├── Paid transfer/                     factory folder; drag file in to list it
│   └── <plaintext-filenames>              encrypted blobs; names/sizes visible only to Alice
├── <bob-pubkey-130hex>/                   Bob's folder; empty readdir for Alice
└── <uuid-of-paid-transfer-listing>/       per-sale listing in the shared root; visible to all
```

The daemon enforces at `mkdir` time that root-level names are either (a) 130-hex-char pubkeys the daemon can derive from a key in `.f1r3drive/`, or (b) uuids that match a known contract-folder registry entry. Anything else: `EPERM`.

### Local state: `.f1r3drive/`

Under `$HOME` by default; configurable via `--state-dir`.

```text
~/.f1r3drive/
├── identity.key                           secp256k1 private key, 32 bytes raw
├── identity.pub                           uncompressed pubkey, 65 bytes (also the folder name)
└── keys/
    └── <hex(blake2b256(K))>               raw 32-byte symmetric key K per SELF-stored blob
```

If `.f1r3drive/` is missing on daemon startup, it is created. If `identity.key` is missing, a fresh secp256k1 key is generated. If no folder in the shared root matches the derived pubkey, the daemon creates one on first mount (one-time setup deploy).

### On-chain blob format

Two type tags, both followed by content encrypted with a symmetric key `K`:

- **SELF** (`"SELF" || hash(K) || AES-GCM(K, header || padded_plaintext)`): the owner stored it. `K` lives in the owner's `.f1r3drive/keys/<hex(hash(K))>` — the on-chain `hash(K)` is the lookup index. Nobody else can decrypt.
- **RECV** (`"RECV" || ECIES(recipient_pubkey, K) || AES-GCM(K, header || padded_plaintext)`): a sender posted it for a specific recipient. The recipient's privkey ECIES-decrypts the `K`, then AES-GCM-decrypts the payload. No one else can decrypt.

`header` carries true content length + plaintext filename, both encrypted. `padded_plaintext` is zero-padded to the next bucket boundary (1 KiB, 4 KiB, 64 KiB, 1 MiB, 16 MiB — chosen by the client to minimise waste while still disclosing a bucket, not an exact size).

AES-GCM uses a random 12-byte nonce prepended to the ciphertext inside each wrap. ECIES follows the `ecies` crate's conventions: ephemeral secp256k1 public key || AES-GCM(KDF(ECDH), K).

### FUSE op → protocol action

| FUSE op on `/<my-pubkey>/<file>` | Action |
|---|---|
| `create` + `write` | generate `K` locally; save to `.f1r3drive/keys/<hex(hash(K))>`; AES-GCM-encrypt filename + content; prepend `"SELF" || hash(K)`; `Fs.openDir(my-pubkey)` + `Dir.createFile(cipher-name)` + `File.writeBytesAt`. Padding to the next bucket boundary. |
| `read` | fetch bytes via `File.bytesAt`; parse `"SELF" || hash(K)`; load K from `.f1r3drive/keys/<hex(hash(K))>`; AES-GCM-decrypt; strip padding using encrypted length; return plaintext bytes starting at the requested offset |
| `readdir` | if caller is owner (pubkey matches local key): decrypt filenames from `Dir.entries` and return; else return `Vec::new()` |
| `getattr` on a file in own folder | decrypt header to get real size; return |
| `getattr` on a file in foreign folder | ENOENT (we lied in readdir; stay consistent) |
| `unlink` on own file | `Dir.removeFile(cipher-name)`; drop local `.f1r3drive/keys/<hex>` entry |
| `rename` from `/<me>/<file>` to `/<me>/<new>` | re-encrypt filename under same K, swap entry |
| `rename` from `/<me>/<file>` to `/<bob>/<file>` | SELF-decrypt locally; mint fresh `K'`; wrap as `"RECV" || ECIES(bob-pubkey, K') || AES-GCM(K', ...)`; write to `/<bob>/`-channel |
| `rename` from `/<bob>/<file>` to `/<me>/...` | reject — Bob's readdir is empty for us; the file isn't visible to move |
| `rename` of a `.token` under `/<me>/.tokens/` | unchanged — current wallet-token transfer path |
| any mutation on `/<not-me>/*` | EACCES |

### Contract-folder registry

A daemon-side manifest: a list of known template IDs plus their behavior. Rendered as subfolders of each user's own folder (e.g. `/<me>/Paid transfer/`).

```rust
pub struct ContractTemplate {
    pub name: &'static str,            // e.g. "Paid transfer"
    pub id: Uuid,                      // stable identifier
    pub factory: Box<dyn FactoryFn>,   // called on drop-into
}
```

v1 has exactly one entry: Paid transfer. The template factory is called when the daemon detects a `create` or `rename` targeting `/<me>/<Template.name>/`; it parses the filename (for Paid transfer: `<N>REV-<rest>`), deploys the appropriate Rholang factory, and the resulting uuid-listing-folder appears at root on next readdir.

### Paid-transfer contract (v1)

- Alice drops `<N>REV-foo.txt` into `/<me>/Paid transfer/`.
- Daemon parses `N` and `foo.txt`, re-encrypts the file as `SELF` under a one-off key `K_listing` stored at the uuid folder's channel on-chain (not in Alice's local keystore).
- A Rholang factory contract deploys:
  - a persistent uuid-folder channel that accepts incoming transfers,
  - a `K_listing` wrapped once per-buyer by the factory on each purchase,
  - a per-sale accounting of refunded change.
- Bob drags `M-REV` tokens from `/<bob>/.tokens/` into `/<uuid-listing>/`:
  - Daemon routes to `Paid transfer`-factory handler.
  - If `M < N`: refund M to Bob, no file transfer.
  - If `M >= N`: forward `N` to Alice (REV transfer deploy); refund `M - N` to Bob; re-wrap `K_listing` under Bob's pubkey as `RECV`; store the resulting blob under `/<bob>/`-channel so it appears in Bob's folder on next readdir.
- Alice can `rmdir /<uuid-listing>/`; the contract burns its state and the folder disappears. Bob cannot.

### Non-goals (v1)

- Nested folders inside pubkey folders (beyond the fixed `.tokens/` + contract-template subfolders).
- Group/share capabilities (Alice→multiple recipients).
- Revocation of a SELF blob once posted (chain-side immutable).
- Content-addressed deduplication of ciphertext.
- Any contract template beyond Paid transfer.

## Consequences

### Positive

- Users have an actual **identity** on the filesystem; "owner" is unambiguous and backed by cryptographic key possession.
- Encrypted-by-default — no accident where a mis-provisioned ACL makes a user's files world-readable.
- Contract folders generalise the drag-triggered-deploy idiom. The paid-transfer template proves out the pattern; later templates reuse the same registry.
- No new on-chain primitives required. All crypto happens client-side; the Fs agent stores opaque bytes.

### Negative

- 130-char folder names in Finder. Visually heavy. Mitigated by Finder sidebar aliases and the fact that users spend time inside their own folder, not browsing the root.
- Readdir ACL is daemon-enforced, not chain-enforced. A direct gRPC consumer can enumerate on-chain ciphertext names (encrypted) and sizes (padded). Metadata leakage is bounded to bucket-size and entry-count.
- Local keystore (`.f1r3drive/keys/`) is now a first-class state surface. Lose it → lose access to your SELF-encrypted files. Backup is on the user.
- The symmetric key per blob is random, not derived from a user secret. Can't key-rotate without rewriting all SELF entries.

## Implementation sequence

1. **This PR**: ADR + `f1r3drive-crypto` crate with SELF/RECV envelope primitives + `.f1r3drive/` keystore. Pure Rust, no mount changes, unit-testable.
2. Next PR: `f1r3drive-identity` crate (identity.key / identity.pub bootstrap, derivation of REV address from identity for token integration).
3. Next: `ExtensionFs` — `WalletFs`-sibling implementing the new tree shape without encryption yet (just the ACL + pubkey-folder gating).
4. Next: wire encrypted upload/download/readdir through `ExtensionFs`.
5. Next: delete + rename + SELF/RECV transfer.
6. Next: contract-folder registry trait + Paid transfer template.
7. Next: paid-transfer Rholang factory contract + e2e test.
