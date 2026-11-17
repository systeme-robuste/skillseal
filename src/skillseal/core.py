"""Deterministic inventory and integrity verification for skill bundles."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

MANIFEST_NAME = "SKILLSEAL.json"
MAX_FILES = 10_000
MAX_ENTRIES = 20_000
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024


class SealError(Exception):
    """Invalid or unsafe bundle/manifest."""


def _safe_files(root: Path, exclude_manifest: bool = True) -> list[Path]:
    """Bounded scandir walk; reject links and special files instead of following them."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise SealError(f"not a directory: {root}")
    result: list[Path] = []
    stack = [root]
    total_bytes = 0
    entries_seen = 0
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                batch = []
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > MAX_ENTRIES:
                        raise SealError(f"bundle exceeds {MAX_ENTRIES} directory-entry limit")
                    batch.append(entry)
        except OSError as exc:
            raise SealError(f"cannot scan directory {directory.relative_to(root).as_posix() or '.'}: {exc}") from exc
        batch.sort(key=lambda entry: entry.name)
        child_dirs = []
        for entry in batch:
            path = Path(entry.path)
            rel = path.relative_to(root).as_posix()
            if entry.is_symlink():
                raise SealError(f"symbolic links are not allowed: {rel}")
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise SealError(f"cannot inspect {rel}: {exc}") from exc
            if stat.S_ISDIR(mode):
                child_dirs.append(path)
                continue
            if not stat.S_ISREG(mode):
                raise SealError(f"not a regular file: {rel}")
            if exclude_manifest and rel == MANIFEST_NAME:
                continue
            size = entry.stat(follow_symlinks=False).st_size
            if size > MAX_FILE_BYTES:
                raise SealError(f"file exceeds {MAX_FILE_BYTES} byte limit: {rel}")
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise SealError(f"bundle exceeds {MAX_TOTAL_BYTES} byte total limit")
            result.append(path)
            if len(result) > MAX_FILES:
                raise SealError(f"bundle exceeds {MAX_FILES} file limit")
        # Push reverse to preserve lexical depth-first traversal; final list sorted anyway.
        stack.extend(reversed(child_dirs))
    return sorted(result, key=lambda p: p.relative_to(root).as_posix())


def inventory(root: Path, exclude_manifest: bool = True) -> list[dict[str, Any]]:
    """Hash bundle files without following symlinks; outputs relative paths only."""
    root = root.resolve(strict=True)
    records = []
    total = 0
    for path in _safe_files(root, exclude_manifest=exclude_manifest):
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
                    total += len(chunk)
                    if size > MAX_FILE_BYTES:
                        raise SealError(f"file grew beyond size limit while reading: {rel}")
                    if total > MAX_TOTAL_BYTES:
                        raise SealError(f"bundle grew beyond {MAX_TOTAL_BYTES} byte total limit while reading")
        except OSError as exc:
            raise SealError(f"cannot read {rel}: {exc}") from exc
        records.append({"path": rel, "size": size, "sha256": digest.hexdigest()})
    return records


def _payload(root: Path) -> dict[str, Any]:
    records = inventory(root)
    return {
        "schema_version": "1",
        "tool": {"name": "skillseal", "version": "0.2.0"},
        "algorithm": "sha256",
        "files": records,
        "bundle_sha256": hashlib.sha256(_canonical(records)).hexdigest(),
    }


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _resolve_output(root: Path, path: Path | None) -> Path:
    path = path or (root / MANIFEST_NAME)
    path = path.expanduser()
    if not path.is_absolute():
        path = root / path
    return path.parent.resolve() / path.name


def seal(root: Path, output: Path | None = None, overwrite: bool = False, signing_key: Path | None = None) -> Path:
    root = root.resolve(strict=True)
    output = _resolve_output(root, output)
    if output.is_symlink():
        raise SealError("manifest path must not be a symbolic link")
    if not overwrite and output.exists():
        raise SealError(f"manifest already exists: {output}; use --overwrite to replace it")
    try:
        relative_output = output.relative_to(root)
    except ValueError:
        pass  # External manifests provide a detached baseline.
    else:
        if relative_output.as_posix() != MANIFEST_NAME:
            raise SealError(f"the only manifest allowed inside the bundle is {MANIFEST_NAME} at its root")
    payload = _payload(root)
    if signing_key is not None:
        from .signatures import add_signature, load_private_key
        payload = add_signature(payload, load_private_key(signing_key))
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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SealError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_manifest(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("schema_version") != "1" or data.get("algorithm") != "sha256":
        raise SealError("unsupported or malformed manifest")
    if set(data) - {"schema_version", "tool", "algorithm", "files", "bundle_sha256", "signature"}:
        raise SealError("manifest contains unknown top-level fields")
    files = data.get("files")
    if not isinstance(files, list) or len(files) > MAX_FILES:
        raise SealError("manifest files must be a bounded list")
    seen: set[str] = set()
    total = 0
    for row in files:
        if not isinstance(row, dict) or set(row) != {"path", "size", "sha256"}:
            raise SealError("malformed file entry")
        rel = row["path"]
        if not isinstance(rel, str) or not rel or "\\" in rel:
            raise SealError("manifest paths must be non-empty POSIX relative paths")
        pure = PurePosixPath(rel)
        if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts) or rel in seen:
            raise SealError(f"unsafe or duplicate path in manifest: {rel}")
        if rel == MANIFEST_NAME:
            raise SealError("manifest cannot list itself")
        seen.add(rel)
        size = row["size"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > MAX_FILE_BYTES:
            raise SealError(f"invalid file size in manifest: {rel}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise SealError("manifest declared sizes exceed bundle limit")
        digest = row["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise SealError(f"invalid SHA-256 digest in manifest: {rel}")
    expected = hashlib.sha256(_canonical(files)).hexdigest()
    if data.get("bundle_sha256") != expected:
        raise SealError("manifest bundle digest is internally inconsistent")
    return data


def verify(root: Path, manifest_path: Path | None = None, trusted_key: Path | None = None, require_signature: bool = False) -> dict[str, Any]:
    root = root.resolve(strict=True)
    manifest_path = _resolve_output(root, manifest_path)
    if manifest_path.is_symlink():
        raise SealError("manifest path must not be a symbolic link")
    try:
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise SealError(f"manifest exceeds {MAX_MANIFEST_BYTES} byte limit")
        data = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except SealError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SealError(f"cannot read manifest: {exc}") from exc
    if manifest_path.is_relative_to(root) and manifest_path.relative_to(root).as_posix() != MANIFEST_NAME:
        raise SealError(f"manifest inside the bundle must be named {MANIFEST_NAME} at its root")
    data = _validate_manifest(data)
    from .signatures import load_public_key, verify_signature
    trusted = load_public_key(trusted_key) if trusted_key is not None else None
    signed, fingerprint = verify_signature(data, trusted)
    if require_signature and not signed:
        raise SealError("manifest signature required but manifest is unsigned")
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
        "tool": {"name": "skillseal", "version": "0.2.0"},
        "valid": not (missing or added or changed),
        "signature_valid": signed,
        "signature_trusted": signed and trusted is not None,
        "signer_key_sha256": fingerprint,
        "baseline_bundle_sha256": data["bundle_sha256"],
        "actual_bundle_sha256": hashlib.sha256(_canonical(list(actual.values()))).hexdigest(),
        "missing": missing,
        "added": added,
        "changed": changed,
        "note": "A valid signature authenticates the manifest only when the public key is independently trusted. It does not establish that the skill is safe.",
    }
