# SET_AUTH_MANIFEST Vendor Authorization Issue

**Issue Reference:** [chipsalliance/caliptra-sw#3485](https://github.com/chipsalliance/caliptra-sw/issues/3485)

---

## Issue Summary

The `SET_AUTH_MANIFEST` API allows replacing **all** IMC (Image Metadata Collection) entries — including ones originally signed by both vendor + owner — with entries signed by **only the owner**, when the vendor signature is marked as optional.

---

## How It Works Today

1. During manufacturing/provisioning, a "golden" auth manifest is loaded with IMC entries signed by **both vendor and owner**. This ensures every firmware image is approved by the silicon vendor (rooted to fuses).

2. Later, the `SET_AUTH_MANIFEST` command can be called again with a new manifest where the `VENDOR_SIGNATURE_REQUIRED` flag is **not set**.

3. When that flag is unset, the vendor IMC signature check is skipped entirely (`set_auth_manifest.rs:314-315`) — it just returns `Ok(())`.

4. The new IMC then **completely replaces** the old one (`set_auth_manifest.rs:639-642`) — the persistent storage is zeroed and overwritten with the new entries.

---

## Security Concern

This means an attacker (or even a legitimate owner) can:

1. Start with a vendor+owner signed manifest authorizing firmware images A, B, C.
2. Issue a new `SET_AUTH_MANIFEST` with `vendor-signature-optional`, containing entries A', B', C' (or entirely different entries) signed only by the owner.
3. The original vendor-approved entries are **destroyed** and replaced.

This **bypasses vendor authorization** — the silicon vendor's approval of which firmware images are allowed to run is no longer enforced.

---

## The Recommendation

The issue recommends that when a manifest arrives with only owner signatures (vendor optional), the system should **extend/append** new IMC entries to the existing collection rather than **replacing** it. This way:

- Original vendor+owner approved entries remain intact.
- Owner can add new entries but cannot remove/modify vendor-approved ones.

---

## The Duplicate Entry Problem

There's one persistent `AuthManifestImageMetadataCollection` with a **fixed capacity of 127 entries**. Today it's a full replace. If the fix changes to "extend" semantics for owner-only manifests, you'd hit these scenarios:

**Same `fw_id`, two different authorization levels:**

- Entry A (`fw_id=1`) signed by vendor+owner — from the original manifest.
- Entry A' (`fw_id=1`) signed by owner-only — from the new manifest.

The current `sort_and_check_duplicate_fwid()` check (`set_auth_manifest.rs` lines 648–670) rejects duplicates within a single manifest, but it doesn't cover the merge case. After merging, you'd have two entries with the same `fw_id`.

---

## Design Questions This Raises

1. **Which entry wins at lookup time?** The `AUTHORIZE_AND_STASH` and `GET_IMAGE_INFO` commands do binary search by `fw_id` on the sorted list. Two entries with the same `fw_id` would cause ambiguous lookups.

2. **Can the owner override a vendor-approved entry?** If yes, you've just re-introduced the original security problem (owner replaces vendor-approved image metadata). If no, the owner can only add new `fw_id`s that the vendor didn't already define.

3. **Capacity exhaustion:** If the initial vendor+owner manifest has 100 entries and the owner wants to add 50 more, you'd exceed the 127-entry limit.

---

## Likely Implementation Approach

The cleanest resolution would be one of:

- **Append only new `fw_id`s** — reject or skip any `fw_id` that already exists in the persistent collection (vendor entries are immutable).
- **Two separate collections** — one vendor-signed, one owner-only, checked independently (requires schema changes in persistent data).
- **A per-entry flag** — indicating whether the entry is vendor+owner or owner-only, with vendor+owner entries being non-replaceable.