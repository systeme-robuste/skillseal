# SkillSeal

**Create a verifiable integrity baseline for an AI-agent skill bundle.** SkillSeal records SHA-256 digests for every regular file and can sign the manifest with Ed25519. Later, it detects changed, missing or added files and verifies the signature against a public key you trust.

It runs locally and does not upload skill contents or execute them. **A valid signature proves that the manifest was signed by the corresponding private key; it does not prove that the signer is who they claim to be, that the skill is safe, or that its code is benign.** You must obtain and verify the public key through an independent trusted channel.

## Install from source

Python 3.10 or newer is required. Clone the repository and install the checked-out source:

```sh
git clone https://github.com/systeme-robuste/skillseal.git
cd skillseal
python -m pip install .
skillseal --help
```

The source is distributed under the MIT License. A package-index release is not part of this repository release.

## Recommended signed workflow

Generate a signing key pair once. Keep the private key secret, backed up securely, and out of the repository. Share the public key and its SHA-256 fingerprint through a separately trusted channel.

```sh
skillseal keygen --private ~/.skillseal/author-private.pem --public ./author-public.pem
skillseal seal ./my-skill --output ./trusted-baselines/my-skill.json --signing-key ~/.skillseal/author-private.pem
skillseal verify ./my-skill --manifest ./trusted-baselines/my-skill.json --trusted-key ./author-public.pem --require-signature
```

A manifest stored outside the skill folder is a detached baseline. On POSIX systems, keygen sets the private-key file to owner-only permissions (`0600`). The key is unencrypted PEM; protect the machine and backup that holds it. Do not use `--overwrite` on an existing private or public key path; keygen refuses replacement.

You can also create an unsigned integrity manifest:

```sh
skillseal seal ./my-skill
skillseal verify ./my-skill
```

Unsigned manifests can detect accidental changes but do not authenticate who created the baseline. `--require-signature` rejects an unsigned manifest. `--trusted-key` rejects unsigned manifests and signatures from any other key. When checking only integrity, omit both flags.

## What it checks

- File additions, deletions and byte changes.
- SHA-256 consistency of each file and a deterministic bundle digest.
- Ed25519 signatures, optionally pinned to a trusted public key.
- Unsafe input: symlinks, special files, duplicate JSON keys, malformed paths and malformed manifests.
- Resource bounds: at most 10,000 files, 20,000 directory entries, 64 MiB per file, 512 MiB total, and an 8 MiB manifest.

Exit codes: `0` created or verified, `1` bundle differs from its baseline, `2` malformed input, unsafe path, missing required signature, or signature/trust failure.

## JSON output

Pass `--json` to `seal` or `verify` for machine-readable output. Verification lists `missing`, `added`, and `changed` paths and reports whether the signature is valid and whether a supplied trusted key matches.

## Development and tests

```sh
python -m pip install -e '.[dev]'
python -m unittest discover -s tests -v
python -m build
python -m twine check dist/*
```

The 0.2.0 release candidate was tested locally on Python 3.13: 17 unit tests pass; source and wheel distributions build and pass `twine check`; a clean virtual-environment install successfully generated keys, signed a manifest and verified it against the public key. Automated GitHub Actions CI is not yet configured in the public repository, and the other Python versions/operating systems have not been verified here.

## Threat model and limitations

- Trust the public key independently. A public key embedded in the manifest alone only proves internal signature consistency; it is not identity verification.
- Hashes and signatures do not scan for malware, prompt injection, risky instructions, compatibility, or quality.
- Never execute a skill just because verification succeeds.
- SkillSeal rejects observed symlinks and special files and bounds resource use. It cannot provide a race-free filesystem snapshot if files are changed concurrently while being read. Verify a stable, read-only copy for stronger assurance.
- Key management, revocation, trusted timestamps, multi-signer policies and a remote registry are not provided.
- A signing key compromise requires trusting a new public key through an independent channel; this MVP has no automated revocation system.

See [`docs/threat-model.md`](docs/threat-model.md) for security details and [`CHANGELOG.md`](CHANGELOG.md) for version history.
