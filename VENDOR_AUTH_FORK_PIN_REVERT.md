# ⚠️ TEMPORARY caliptra-sw FORK PIN — MUST REVERT BEFORE MERGE

The MCU vendor-auth relay references Caliptra-core commands (`VENDOR_AUTH_HELLO` /
`VENDOR_AUTH_CHALLENGE`) that are **not yet in upstream `chipsalliance/caliptra-sw`**.
To build and validate the relay end-to-end in this branch, the pinned `caliptra-*`
git rev in `Cargo.toml` has been **temporarily** bumped to a **fork commit**:

- **Fork commit:** `5e6a161b` on `https://github.com/RaunakGu/caliptra-sw`, branch `raunakgupta/vendor-auth`
- **Previous (upstream-ancestor) pin:** `a29882e210df17021240837f47d15d57c5ce5ffd`
- **Lines:** `Cargo.toml` caliptra-* rev pins (the block that was all `a29882e2…`)

## This is VALIDATION-ONLY. Do NOT merge to `main-2.1` while this pin is a fork commit.

### Revert / correct-before-merge checklist
1. Land the caliptra-sw vendor-auth work upstream (`caliptra-sw#3928` + the vendor-auth PR) into `chipsalliance/caliptra-sw`.
2. Re-point every `caliptra-*` rev in `Cargo.toml` from the fork commit back to the **upstream-merged** commit (single rev across all ~24 crates; `caliptra-cfi` is a separate URL, leave as-is).
3. `cargo update -p caliptra-api` (etc.) / rebuild so `Cargo.lock` reflects the upstream commit.
4. Delete this file.

Search anchor for the pin change: `git log --oneline | grep -i "fork pin"`.
