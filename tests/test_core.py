from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from skillseal.core import MANIFEST_NAME, SealError, seal, verify


class SealTests(unittest.TestCase):
    def create_bundle(self, root: Path) -> Path:
        skill = root / "demo-skill"
        (skill / "references").mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: demo-skill\ndescription: Demo.\n---\nInstructions.\n", encoding="utf-8")
        (skill / "references" / "guide.md").write_text("Reference text\n", encoding="utf-8")
        return skill

    def test_seal_then_verify(self):
        with tempfile.TemporaryDirectory() as temp:
            bundle = self.create_bundle(Path(temp))
            manifest = seal(bundle)
            result = verify(bundle)
            self.assertTrue(manifest.exists())
            self.assertTrue(result["valid"])
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

    def test_rejects_symlink_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bundle = self.create_bundle(root)
            outside = root / "outside.txt"
            outside.write_text("secret")
            (bundle / "link.txt").symlink_to(outside)
            with self.assertRaisesRegex(SealError, "symbolic links"):
                seal(bundle)

    def test_rejects_symlink_directories(self):
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
