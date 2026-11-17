# SkillSeal

**A local integrity seal for AI-agent skill bundles.** Record SHA-256 hashes for a skill's files, then detect edits, missing files, or unexpected additions before you install or share it.

SkillSeal is deliberately small and offline. It does not execute a skill, upload content, or require an API key. It does **not** certify that a skill is safe, authentic, or compatible, and a hash manifest is **not a digital signature**. If an attacker can replace both the skill and its manifest, the hashes alone cannot prove provenance. Keep the manifest in a trusted location or verify it through a separately trusted channel.

## Quick start

Requires Python 3.10+.

```sh
python -m pip install .
skillseal seal ./my-skill
skillseal verify ./my-skill
```

Keep a detached baseline manifest outside the folder being checked:

```sh
skillseal seal ./my-skill --output ./trusted-baselines/my-skill.SKILLSEAL.json
skillseal verify ./my-skill --manifest ./trusted-baselines/my-skill.SKILLSEAL.json --json
```

The tool refuses to overwrite an existing manifest unless you pass `--overwrite`. It rejects symlinks, bounds files to 10,000 entries, 64 MiB each and 512 MiB total, and reports relative paths only.

## What gets sealed

All regular files under the skill folder except the generated root `SKILLSEAL.json` manifest. The deterministic JSON manifest records each relative POSIX path, byte size and SHA-256 digest, plus a bundle digest over the ordered file records. Verification also checks for added, removed and changed files. For a stronger baseline, store it outside the skill folder using `--output` / `--manifest`; otherwise the manifest itself is ignored during inventory. Exit codes: `0` verified/created, `1` bundle mismatch, `2` invalid input or manifest.

## Why this project

A package can be edited after review, copied into a workspace, or changed in transit. Static validators check format; scanners look for suspicious content; a local integrity baseline answers a narrower question: **is this byte-for-byte bundle the one I previously inspected?** The project complements those tools and does not replace them.

## Development

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPYCACHEPREFIX=/tmp/skillseal-pycache python -m compileall -q src tests
```

## Limitations and threat model

- Hashes detect divergence only relative to a trusted baseline.
- This MVP has no digital signatures, key management, remote registry, publisher identity, or automatic install hook.
- A successful check is not a malware scan and does not make execution safe.
- Concurrent filesystem mutation during inventory is not a full filesystem snapshot; rerun checks on a stable, read-only copy for high assurance.
- Files are not opened with platform-specific no-follow flags; symlinks are rejected in the observed tree, but hostile concurrent replacement remains outside this MVP's guarantee.

See [`docs/threat-model.md`](docs/threat-model.md). MIT licensed; see [`LICENSE`](LICENSE).
