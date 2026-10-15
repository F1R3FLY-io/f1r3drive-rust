---
title: Proposer self-validation fails with `replay admission mismatch` on the first mutating oracular `Dir.openFile` deploy
component: f1r3node-rust (casper proposer + rholang executor)
reporter: f1r3drive-rust integration
date: 2026-10-15
severity: blocker (prevents any on-chain progress on a fresh standalone shard once a client calls the Fs agent)
node-version: F1r3node Rust 0.4.46 (image `f1r3flyindustries/f1r3fly-rust:local-rebuild`)
---

## Summary

On a freshly-wiped `standalone-dev` shard with an `oracle-static-dirs.root → /var/lib/rnode/f1r3drive (rw)` provisioning entry, the first mutating client deploy — a canonical `dir.openFile(…, {"mode": "w+"})` + `file.close` round-trip against the registered oracular `Dir` — admits cleanly on the deploy service and lands in the pending pool, but **every subsequent `propose` attempt fails with `Runtime error: Validation of self created block failed with reason: Invalid(InvalidTransaction), cancelling propose.`** The proposer's self-validation step reports a `replay admission mismatch` at admitted-index 0, even though the admit/reject *counts* match.

Because propose is non-recoverable from this state (the same deploy stays at the top of the pool and causes the same failure on every attempt), on-chain state never advances and the heartbeat proposer eventually enters its 60s backoff loop. All further client writes queue in the pool and compound the problem.

## Impact

- A clean shard cannot advance past block `#3` the moment any client issues a `Dir.openFile(…, "w+")`-shaped mutation against an oracular bundle entry.
- The f1r3drive FUSE daemon ([F1R3FLY-io/f1r3drive-rust](https://github.com/F1R3FLY-io/f1r3drive-rust)) is end-to-end functional up to this point (v6-cosigned deploy admission works; Finder-driven creates and writes stream in; 94 `write` deploys + 2 `create`s + 3 `unlink`s all admitted cleanly from a single drag-and-drop test) but every one of them sits unproposable in the pool.

## Environment

- Host: macOS 14.6 (Darwin 23.6.0), Apple M3 Max.
- Container: `podman compose -f docker/standalone.yml` with an override that bind-mounts `/Users/stay/f1r3drive-seed:/var/lib/rnode/f1r3drive:z`.
- Node config (`docker/conf/standalone-dev.conf`) excerpt:

  ```hocon
  storage {
    oracle-static-dirs = {
      root = { path = "/var/lib/rnode/f1r3drive", mode = "rw" }
    }
  }
  ```

- `/Users/stay/f1r3drive-seed/` host contents at reproduction time: `hello.txt`, `other.txt`, `Asimov - The Complete Robot.epub` (0 bytes, from a prior test).
- Node reported ready: `"H-5: root-identity registry populated from static provisioning", registered=1`.

## Reproduction

1. Wipe node state: `podman volume rm docker_standalone-data && podman compose -f docker/standalone.yml up -d`.
2. Wait for `Node is ready (EnteredRunningState received)` in the node log and `isReady=true` from `casper.v1.DeployService/status`.
3. From any v6-protocol client, submit a deploy whose term is the following (shard `root`, `valid_after_block_number = LFB`, secp256k1-signed):

   ```rholang
   new return, rl(`rho:registry:lookup`), fsCh in {
     rl!(`rho:id:naz9dp5st6droro6dm7f3ehe5rh1s6hbs9pj8wnxpx1ckr89xthw3e`, *fsCh) |
     for (@(_, fs) <- fsCh) {
       for (@[ok, ...rest] <- @fs!?("openDir", "root", {"mode": "rw"})) {
         if (ok) {
           let @[dir] <- rest in {
             for (@[ok2, ...rest2] <- @dir!?("openFile", "ang.png", {"mode": "w+"})) {
               if (ok2) {
                 let @[f] <- rest2 in {
                   for (@closeReply <- @f!?("close")) {
                     return!([true])
                   }
                 }
               } else {
                 let @[code, msg] <- rest2 in {
                   return!([false, code, msg])
                 }
               }
             }
           }
         } else {
           let @[code, msg] <- rest in {
             return!([false, code, msg])
           }
         }
       }
     }
   }
   ```

   The filename doesn't matter — any `w+` openFile on the oracular `root` dir reproduces it.

4. Call `casper.v1.ProposeService/propose` on the internal port (`is_async: false`).

### Expected

Propose succeeds, publishes block `#4`, LFB advances, the file appears in `/Users/stay/f1r3drive-seed/ang.png`.

### Observed

```
Propose service method error: Failure: Proposal failed: BugError (seqNum 4)
```

## Server log excerpt (first failing attempt, pool size 1)

```
2026-10-15T14:38:50.847686Z INFO  casper::rust::blocks::proposer::block_creator:
  Creating block #4 (seqNum 4)
2026-10-15T14:38:50.866439Z INFO  f1r3fly.casper.deploy_lifecycle:
  deploy lifecycle event=selected
    deploy_sig=fe28494ddf404d746f44f9851f69bfe0f6f489a836fdfbef97a6316fd43bcd1c
    next_block=4 retry=false in_scope_recovery=false valid_after_block=3
2026-10-15T14:38:50.866474Z INFO  casper::rust::blocks::proposer::block_creator:
  Deploy selection for block #4: pool=1, future=0, blockExpired=0, timeExpired=0,
    valid=1, alreadyInScope=0, selected=1
2026-10-15T14:38:51.854920Z WARN  casper::rust::util::rholang::interpreter_util:
  Found replay admission mismatch
    (expected_admitted=1, replay_admitted=1,
     expected_rejected=0, replay_rejected=0):
    block execution evidence differs from state-bound recomputation
    at admitted index 0
2026-10-15T14:38:51.855105Z ERROR node::rust::instances::proposer_instance:
  propose call failed error="Runtime error: Validation of self created block
    failed with reason: Invalid(InvalidTransaction), cancelling propose."
```

The pattern repeats verbatim for every subsequent propose attempt. As the client keeps submitting (Finder's write chunks), later attempts have `expected_admitted=N` with `N` matching the growing pool size — the mismatch stays stuck at `admitted index 0`, i.e. **the first-ever oracular `w+` openFile deploy is the one the replay can't reproduce.**

## Why this points at the proposer / Rholang executor, not the client

- **Admit succeeded.** The deploy clears `DeployService.doDeploy` with the v6 cosigned envelope accepted; it's visible in `getPendingDeploys` with a valid 32-byte `deployId`, `authorizationV61.formatVersion=0x00060001`, secp256k1 witness, low-s DER signature.
- **Deploy selection succeeded.** `block_creator` picks it, `valid_after_block=3` is fresh, no expiration/alreadyInScope filtering.
- **First execution succeeded.** The admit/reject counts (`expected_admitted=1, expected_rejected=0`) say the proposer's first run through this deploy admitted it cleanly.
- **Replay from committed pre-state disagrees.** The state-bound recomputation at admitted index 0 produces different evidence than the first execution. This is the proposer's own self-validation gate — nothing the client sent is in play at this point.
- **Deterministic in the deploy content.** Repeated attempts (with increasing pool size, after container restart on fresh LMDB) land on the same `admitted index 0` mismatch. The surface that differs is specifically the first-ever write-mode open against the oracular `root` dir.

## Hypothesis

The oracular `Dir.openFile(mode="w+")` path probably has a first-call vs. replay-call divergence somewhere in its state-bound recomputation path — e.g. a WAL / payload-source-index record that is written during the initial execution and consulted (or not consulted) during replay, so the two executions disagree on evidence even though both admit the deploy. Candidates to inspect:

1. **DD-7b-2 (a) payload-source recorder** — `node/src/rust/runtime/setup.rs:447` logs `Consensus-cap writes will record payload_hash → deploy_sig for joiner-side reproduction`. If this recorder captures state on initial exec but is skipped on state-bound replay (or vice versa), the two runs would produce divergent evidence.
2. **`fs_create_file` / `openFileImpl` first-create path** — the first `w+` open against an oracular `Dir` performs a filesystem-level `creat()` on the host; replay runs against the already-created file. If the implementation records `fs_wal` evidence conditional on the host-side "did we actually create a file?" fact, that fact is `true` first-time and `false` on replay (the file exists already from the committed state's side-effects), producing the mismatch.
3. **Mode-string normalization** — `"w+"` has to translate to `O_TRUNC | O_CREAT | O_RDWR`-equivalent evidence. If the recorded evidence captures `O_CREAT` conditional on "file didn't exist beforehand", replay sees a different flag set.

## Follow-up / asks

- Dump the admitted-index-0 evidence record from both executions for a reproduction run — the diff is the signal.
- Confirm whether an `oracle-static-files.*` single-file provisioning (bypassing `Dir.openFile(…, w+)` first-create path) also reproduces, or whether the bug is specific to directory-mode writes.
- Check whether oracle writes under test (`casper/tests/genesis/contracts/fileio_fs_spec.rs`) exercise the propose self-validation step, or whether tests only cover first-execution admission.

## Attached client-side evidence

- Client version/branch: f1r3drive-rust main (commit on branch at bug-report submission — this file is being added in the same commit).
- Client log: `/tmp/f1r3drive.log` on reporter's host; roughly 95 deploy admissions, every one followed by `WARN propose after deploy failed; deploy remains in pool err=ServiceError("Propose service method error: Failure: Proposal failed: BugError (seqNum 4)")`.
- `getPendingDeploys` response confirms v6-envelope shape (`formatVersion=0x00060001`, `authorizationV61.policy.allOf.members[0].scheme=SIGNATURE_SCHEME_V61_SECP256K1`, 32-byte `deployId`).
