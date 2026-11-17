# Threat model (MVP)

## Goal

Detect accidental or malicious changes to a skill folder compared with a previously generated SHA-256 manifest that the verifier trusts.

## In scope

- File-byte changes.
- New and deleted regular files.
- Malformed or internally inconsistent JSON manifests.
- Symlink files and directories observed during traversal.
- Resource exhaustion bounded by file-count and byte limits.
- Reports revealing only relative bundle paths, not absolute local machine paths.

## Out of scope

- Proof of publisher identity or authorship.
- Protecting a manifest stored beside the bundle from coordinated replacement.
- Malware, prompt-injection, policy, compatibility or quality analysis.
- A race-free filesystem snapshot under concurrent hostile mutation.
- Cryptographic signatures, trusted timestamps, online registries or key distribution.
- Safe execution or installation of bundled scripts.

## Safe-use recommendation

Review the skill and scripts first. Store the baseline manifest somewhere protected from the bundle's writers or obtain its digest through a trusted independent channel. Verify on a stable copy before use. Treat a passing result as integrity relative to that baseline only.
