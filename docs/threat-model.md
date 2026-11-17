# Threat model

## Security objective

Detect file-level divergence from a previously inspected skill bundle and, where requested, authenticate the manifest using Ed25519 against an independently trusted public key.

## In scope

- Added, missing and modified regular files.
- Manifest tampering, malformed structures and duplicate JSON object keys.
- Signed manifest authenticity relative to the supplied trusted Ed25519 public key.
- Observed symlink and special-file rejection.
- Bounded file count, directory entry count, file size, bundle bytes and manifest bytes.
- Avoiding disclosure of absolute paths in verification results.

## Out of scope

- Determining whether a public key belongs to a particular person or organization. The user must establish that out-of-band.
- Malware, prompt-injection, license, policy or compatibility analysis.
- Race-free snapshots against concurrent hostile filesystem changes.
- Encryption, hardware-backed key storage, key recovery, rotation, revocation, timestamping, certificates or transparency logs.
- Execution safety or installation enforcement.

## Key handling

The private key is unencrypted PEM; protect it with operating-system account security and encrypted backups. Do not commit it, send it in chat, or place it beside distributable skill files. Share the public key and its fingerprint via a separate trusted route. If a private key is compromised, stop signing with it and distribute a replacement public key through that trusted route. This version does not maintain a revocation list.

## Safe-use procedure

1. Review skill contents before signing or installing; signature is not a safety review.
2. Generate the signing key in a protected location.
3. Verify the public key/fingerprint independently with the maintainer.
4. Keep a detached signed manifest and public key under trusted control.
5. Verify a stable, read-only bundle copy with `--trusted-key` and `--require-signature`.
6. If any path differs, do not treat the bundle as the approved copy; investigate and re-review it.
