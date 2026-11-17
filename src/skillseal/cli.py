"""CLI for sealing/verifying local agent skill bundles."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .core import MANIFEST_NAME, SealError, seal, verify
from .signatures import generate_keypair


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillseal", description="Create and verify local SHA-256 integrity manifests for skill bundles.")
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("seal", help="Create a manifest for a skill bundle")
    make.add_argument("path", type=Path, help="Skill bundle directory")
    make.add_argument("-o", "--output", type=Path, help=f"Manifest destination (default: PATH/{MANIFEST_NAME})")
    make.add_argument("--overwrite", action="store_true", help="Replace an existing manifest")
    make.add_argument("--signing-key", type=Path, help="Ed25519 private key used to sign the manifest")
    make.add_argument("--json", action="store_true", help="Print machine-readable result")
    keys = sub.add_parser("keygen", help="Generate an Ed25519 signing key pair")
    keys.add_argument("--private", required=True, type=Path, help="Private key output path; keep secret")
    keys.add_argument("--public", required=True, type=Path, help="Public key output path; distribute to verifiers")
    check = sub.add_parser("verify", help="Compare a skill bundle against a manifest")
    check.add_argument("path", type=Path, help="Skill bundle directory")
    check.add_argument("-m", "--manifest", type=Path, help=f"Manifest path (default: PATH/{MANIFEST_NAME})")
    check.add_argument("--trusted-key", type=Path, help="Trusted Ed25519 public key; rejects unsigned/different-key manifests")
    check.add_argument("--require-signature", action="store_true", help="Reject unsigned manifests")
    check.add_argument("--json", action="store_true", help="Print machine-readable result")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            generate_keypair(args.private, args.public)
            print(json.dumps({"ok": True, "private_key": str(args.private), "public_key": str(args.public), "warning": "Protect the private key; never commit or share it."}, indent=2))
            return 0
        if args.command == "seal":
            manifest = seal(args.path, args.output, args.overwrite, args.signing_key)
            result = {"ok": True, "manifest": str(manifest), "signed": bool(args.signing_key), "message": "Keep your private signing key secret and distribute the trusted public key separately."}
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(f"Sealed bundle → {manifest}\nKeep the manifest in a trusted location; this hash is not a digital signature.")
            return 0
        result = verify(args.path, args.manifest, args.trusted_key, args.require_signature)
        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            status = "VERIFIED" if result["valid"] else "MISMATCH"
            signer = result['signer_key_sha256'] or 'unsigned'
            print(f"{status}: baseline {result['baseline_bundle_sha256']} (signature: {'valid' if result['signature_valid'] else 'absent'}; key: {signer})")
            if result["missing"]:
                print("Missing:")
                for item in result["missing"]:
                    print(f"  - {item}")
            if result["added"]:
                print("Added:")
                for item in result["added"]:
                    print(f"  + {item}")
            if result["changed"]:
                print("Changed:")
                for item in result["changed"]:
                    print(f"  * {item['path']} (expected {item['expected']['sha256']}, got {item['actual']['sha256']})")
            print(result["note"])
        return 0 if result["valid"] else 1
    except (SealError, OSError) as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
        else:
            print(f"skillseal: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
