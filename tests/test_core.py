from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skillseal.core import MANIFEST_NAME, SealError, seal, verify
from skillseal.signatures import generate_keypair


class SealTests(unittest.TestCase):
    def create_bundle(self, root: Path) -> Path:
        skill = root / "demo-skill"
        (skill / "references").mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: demo-skill\ndescription: Demo.\n---\nInstructions.\n", encoding="utf-8")
        (skill / "references" / "guide.md").write_text("Reference text\n", encoding="utf-8")
        return skill

    def keys(self, root: Path) -> tuple[Path, Path]:
        private, public = root / "signing.pem", root / "trusted.pem"
        generate_keypair(private, public)
        return private, public

    def test_seal_then_verify(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            manifest = seal(bundle)
            result = verify(bundle)
            self.assertTrue(manifest.exists())
            self.assertTrue(result["valid"])
            self.assertFalse(result["signature_valid"])
            self.assertEqual(result["missing"], [])
            self.assertEqual(result["added"], [])
            self.assertEqual(result["changed"], [])

    def test_changed_file_is_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            seal(bundle)
            (bundle / "SKILL.md").write_text("modified\n", encoding="utf-8")
            result = verify(bundle)
            self.assertFalse(result["valid"])
            self.assertEqual([row["path"] for row in result["changed"]], ["SKILL.md"])

    def test_added_and_missing_files_are_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            seal(bundle)
            (bundle / "references" / "guide.md").unlink()
            (bundle / "extra.txt").write_text("added", encoding="utf-8")
            result = verify(bundle)
            self.assertEqual(result["missing"], ["references/guide.md"])
            self.assertEqual(result["added"], ["extra.txt"])

    def test_manifest_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first, second = self.create_bundle(root / "a"), self.create_bundle(root / "b")
            seal(first)
            seal(second)
            one = json.loads((first / MANIFEST_NAME).read_text())
            two = json.loads((second / MANIFEST_NAME).read_text())
            self.assertEqual(one["files"], two["files"])
            self.assertEqual(one["bundle_sha256"], two["bundle_sha256"])

    def test_refuses_overwrite_without_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            seal(bundle)
            with self.assertRaises(SealError):
                seal(bundle)
            seal(bundle, overwrite=True)

    def test_rejects_symlink_files_and_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            outside = root / "outside.txt"
            outside.write_text("not included")
            (bundle / "link.txt").symlink_to(outside)
            with self.assertRaisesRegex(SealError, "symbolic links"):
                seal(bundle)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            outside = root / "outside"
            outside.mkdir()
            (bundle / "linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(SealError, "symbolic links"):
                seal(bundle)

    def test_refuses_manifest_inside_bundle_under_other_name(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            with self.assertRaisesRegex(SealError, "only manifest allowed"):
                seal(bundle, bundle / "wrong.json")

    def test_external_baseline_detects_bundle_manifest_substitution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            detached = root / "baseline.json"
            seal(bundle, detached)
            (bundle / MANIFEST_NAME).write_text('{"bad": true}', encoding="utf-8")
            result = verify(bundle, detached)
            self.assertIn(MANIFEST_NAME, result["added"])

    def test_tampered_manifest_detected(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            manifest = seal(bundle)
            data = json.loads(manifest.read_text())
            data["files"][0]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(SealError, "internally inconsistent"):
                verify(bundle)

    def test_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            manifest = bundle / MANIFEST_NAME
            manifest.write_text('{"schema_version":"1","schema_version":"1"}', encoding="utf-8")
            with self.assertRaisesRegex(SealError, "duplicate JSON key"):
                verify(bundle)

    def test_rejects_symlink_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            external = root / "manifest.json"
            seal(bundle, external)
            link = root / "linked.json"
            link.symlink_to(external)
            with self.assertRaisesRegex(SealError, "symbolic link"):
                verify(bundle, link)

    def test_keygen_and_signature_trusted_verify(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            private, public = self.keys(root)
            manifest = root / "trusted-baseline.json"
            seal(bundle, manifest, signing_key=private)
            result = verify(bundle, manifest, trusted_key=public, require_signature=True)
            self.assertTrue(result["valid"])
            self.assertTrue(result["signature_valid"])
            self.assertTrue(result["signature_trusted"])

    def test_rejects_wrong_trusted_key(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            private, _ = self.keys(root)
            (root / "other").mkdir()
            other_private, other_public = self.keys(root / "other")
            manifest = root / "baseline.json"
            seal(bundle, manifest, signing_key=private)
            with self.assertRaisesRegex(SealError, "different key"):
                verify(bundle, manifest, trusted_key=other_public)

    def test_rejects_unsigned_when_signature_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            _, public = self.keys(root)
            seal(bundle)
            with self.assertRaisesRegex(SealError, "unsigned"):
                verify(bundle, trusted_key=public)

    def test_detects_tampered_signature(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            private, public = self.keys(root)
            manifest = seal(bundle, signing_key=private)
            data = json.loads(manifest.read_text())
            data["signature"]["value"] = "A" * len(data["signature"]["value"])
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(SealError, "signature is invalid"):
                verify(bundle, trusted_key=public)

    def test_keygen_refuses_overwrite_and_sets_private_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            private, public = self.keys(root)
            with self.assertRaisesRegex(SealError, "already exists"):
                generate_keypair(private, public)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)

    def test_cli_json_roundtrip(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from skillseal.cli import main
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["seal", str(bundle), "--json"]), 0)
            self.assertTrue(json.loads(output.getvalue())["ok"])
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["verify", str(bundle), "--json"]), 0)
            self.assertTrue(json.loads(output.getvalue())["valid"])


if __name__ == "__main__":
    unittest.main()
