"""Deterministic inventory and integrity verification for skill bundles."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_NAME = "SKILLSEAL.json"
MAX_FILES = 10_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


class SealError(Exception):
    """Invalid or unsafe bundle/manifest."""


def _safe_files(root: Path, exclude_manifest: bool = True) -> list[Path]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise SealError(f"not a directory: {root}")
    files: list[Path] = []
    total = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirs.sort()
        names.sort()
        # Reject symlink directories; do not silently skip content at a link boundary.
        for directory in list(dirs):
            candidate = current_path / directory
            if candidate.is_symlink():
                raise SealError(f"symbolic links are not allowed: {candidate.relative_to(root).as_posix()}")
        for name in names:
            candidate = current_path / name
            rel = candidate.relative_to(root).as_posix()
            if exclude_manifest and rel == MANIFEST_NAME:
                continue
            if candidate.is_symlink():
                raise SealError(f"symbolic links are not allowed: {rel}")
            try:
                st = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise SealError(f"cannot inspect {rel}: {exc}") from exc
            if not candidate.is_file():
                raise SealError(f"not a regular file: {rel}")
            if st.st_size > MAX_FILE_BYTES:
                raise SealError(f"file exceeds {MAX_FILE_BYTES} byte limit: {rel}")
            total += st.st_size
            if total > MAX_TOTAL_BYTES:
                raise SealError(f"bundle exceeds {MAX_TOTAL_BYTES} byte total limit")
            files.append(candidate)
            if len(files) > MAX_FILES:
                raise SealError(f"bundle exceeds {MAX_FILES} file limit")
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def inventory(root: Path, exclude_manifest: bool = True) -> list[dict[str, Any]]:
    """Hash bundle files without following symlinks; outputs relative paths only."""
    root = root.resolve(strict=True)
    records = []
    for path in _safe_files(root, exclude_manifest=exclude_manifest):
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise SealError(f"file grew beyond size limit while reading: {rel}")
        records.append({"path": rel, "size": size, "sha256": digest.hexdigest()})
    return records


def _payload(root: Path) -> dict[str, Any]:
    records = inventory(root)
    return {
        "schema_version": "1",
        "tool": {"name": "skillseal", "version": "0.1.0"},
        "algorithm": "sha256",
        "files": records,
        "bundle_sha256": hashlib.sha256(_canonical(records)).hexdigest(),
    }


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def seal(root: Path, output: Path | None = None, overwrite: bool = False) -> Path:
    root = root.resolve(strict=True)
    output = (output or (root / MANIFEST_NAME)).expanduser().resolve()
    if not overwrite and output.exists():
        raise SealError(f"manifest already exists: {output}; use --overwrite to replace it")
    try:
        relative_output = output.relative_to(root)
    except ValueError:
        pass  # External manifests are useful for a detached baseline.
    else:
        if relative_output.as_posix() != MANIFEST_NAME:
            raise SealError(f"the only manifest allowed inside the bundle is {MANIFEST_NAME} at its root")
        if output.is_symlink():
            raise SealError("manifest path must not be a symbolic link")
    payload = _payload(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(output.name + ".tmp")
    try:
        with tmp.open("xb") as stream:
            stream.write(_canonical(payload))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, output)
    except FileExistsError as exc:
        raise SealError(f"temporary manifest already exists: {tmp}") from exc
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise SealError(f"could not write manifest: {exc}") from exc
    return output


def _validate_manifest(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("schema_version") != "1" or data.get("algorithm") != "sha256":
        raise SealError("unsupported or malformed manifest")
    files = data.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise SealError("manifest files must be a bounded list")
    seen: set[str] = set()
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}:
            raise SealError("malformed file entry")
        rel = row["path"]
        if not isinstance(rel, str) or not rel or "\\" in rel:
            raise SealError("manifest paths must be non-empty POSIX relative paths")
        pure = PurePosixPath(rel)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts) or rel in seen:
            raise SealError(f"unsafe or duplicate path in manifest: {rel}")
        seen.add(rel)
        if not isinstance(row["size"], int) or row["size"] < 0 or row["size"] > MAX_FILE_BYTES:
            raise SealError(f"invalid file size in manifest: {rel}")
        digest = row["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SealError(f"invalid SHA-256 digest in manifest: {rel}")
    expected = hashlib.sha256(_canonical(files)).hexdigest()
    if data.get("bundle_sha256") != expected:
        raise SealError("manifest bundle digest is internally inconsistent")
    return data


def verify(root: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    root = root.resolve(strict=True)
    manifest_path = (manifest_path or (root / MANIFEST_NAME)).resolve()
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError(f"cannot read manifest: {exc}") from exc
    if manifest_path.is_relative_to(root) and manifest_path.name != MANIFEST_NAME:
        raise SealError(f"manifest inside the bundle must be named {MANIFEST_NAME} at its root")
    if manifest_path.is_symlink():
        raise SealError("manifest path must not be a symbolic link")
    data = _validate_manifest(data)
    expected = {row["path"]: row for row in data["files"]}
    actual = {row["path"]: row for row in inventory(root, exclude_manifest=manifest_path.parent == root)}
    missing = sorted(set(expected) - set(actual))
    added = sorted(set(actual) - set(expected))
    changed = []
    for path in sorted(set(expected) & set(actual)):
        if expected[path] != actual[path]:
            changed.append({"path": path, "expected": expected[path], "actual": actual[path]})
    return {
        "schema_version": "1",
        "tool": {"name": "skillseal", "version": "0.1.0"},
        "valid": not (missing or added or changed),
        "baseline_bundle_sha256": data["bundle_sha256"],
        "actual_bundle_sha256": hashlib.sha256(_canonical(list(actual.values()))).hexdigest(),
        "missing": missing,
        "added": added,
        "changed": changed,
        "note": "Hash consistency detects changes against this manifest; it does not prove who created the manifest or prevent an attacker from replacing both bundle and manifest.",
    }
