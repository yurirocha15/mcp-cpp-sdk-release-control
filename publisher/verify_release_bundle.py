#!/usr/bin/env python3
"""Verify downloaded immutable release control files without executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile


FINGERPRINT = re.compile(r"[0-9A-F]{40}|[0-9A-F]{64}")
HEX64 = re.compile(r"[0-9a-f]{64}")
CONTROL_FILES = {"release-manifest.json", "release-manifest.json.asc", "SHA256SUMS", "SHA256SUMS.asc"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(
    directory: Path,
    *,
    tag: str,
    commit: str,
    manifest_digest: str,
    primary_fingerprint: str,
    artifact_fingerprint: str,
    public_key: Path,
) -> None:
    manifest_path = directory / "release-manifest.json"
    if sha256(manifest_path) != manifest_digest:
        raise ValueError("release manifest digest mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("tag") != tag or manifest.get("commit") != commit:
        raise ValueError("manifest tag or commit mismatch")
    if manifest.get("schema_version") != 2 or manifest.get("channel_capabilities") != [
        "github", "conan2", "apt", "rpm", "aur", "homebrew", "chocolatey"
    ]:
        raise ValueError("manifest does not authorize the complete stable channel set")
    signers = manifest.get("signers")
    if not isinstance(signers, dict):
        raise ValueError("manifest signer object is missing")
    if signers.get("primary_fingerprint") != primary_fingerprint:
        raise ValueError("manifest primary fingerprint mismatch")
    if signers.get("artifact_subkey_fingerprint") != artifact_fingerprint:
        raise ValueError("manifest artifact fingerprint mismatch")

    payloads = manifest.get("payloads")
    if not isinstance(payloads, list):
        raise ValueError("manifest payload list is missing")
    payload_records = {}
    for item in payloads:
        if not isinstance(item, dict) or not {"name", "size", "sha256"} <= set(item):
            raise ValueError("manifest payload record is malformed")
        name = item["name"]
        if not isinstance(name, str) or Path(name).name != name or name in payload_records or name in CONTROL_FILES:
            raise ValueError("manifest payload name is unsafe or duplicated")
        payload_records[name] = item
    detached_signatures = {
        f"{name}.asc" for name in payload_records if name.endswith((".tar.gz", ".zip"))
    }
    downloaded_assets = {path.name for path in directory.iterdir() if path.is_file()}
    if downloaded_assets != set(payload_records) | CONTROL_FILES | detached_signatures:
        raise ValueError("manifest payload and detached-signature sets do not match downloaded release assets")
    for name, item in payload_records.items():
        path = directory / name
        if item["size"] != path.stat().st_size or item["sha256"] != sha256(path):
            raise ValueError(f"manifest payload identity mismatch for {name}")

    checksums = _parse_checksums((directory / "SHA256SUMS").read_text(encoding="utf-8"))
    expected = {path.name for path in directory.iterdir() if path.is_file()} - {"SHA256SUMS", "SHA256SUMS.asc"}
    if set(checksums) != expected:
        raise ValueError("SHA256SUMS file set mismatch")
    for name, expected_digest in checksums.items():
        if sha256(directory / name) != expected_digest:
            raise ValueError(f"checksum mismatch for {name}")

    signed_assets = [
        (manifest_path, directory / "release-manifest.json.asc"),
        (directory / "SHA256SUMS", directory / "SHA256SUMS.asc"),
    ]
    signed_assets.extend(
        (directory / name, directory / f"{name}.asc")
        for name in sorted(payload_records)
        if name.endswith((".tar.gz", ".zip"))
    )
    for signed, signature in signed_assets:
        _verify_signature(signed, signature, public_key, primary_fingerprint, artifact_fingerprint)


def _parse_checksums(text: str) -> dict[str, str]:
    records: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
        if match is None or match.group(2) in records:
            raise ValueError("SHA256SUMS contains a malformed or duplicate record")
        records[match.group(2)] = match.group(1)
    if not records or CONTROL_FILES - {"SHA256SUMS", "SHA256SUMS.asc"} - set(records):
        raise ValueError("SHA256SUMS omits required signed manifest controls")
    return records


def _verify_signature(
    signed: Path, signature: Path, public_key: Path, primary_fingerprint: str, artifact_fingerprint: str
) -> None:
    with tempfile.TemporaryDirectory() as home:
        imported = subprocess.run(
            ["gpg", "--batch", "--homedir", home, "--import", str(public_key)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if imported.returncode != 0:
            raise ValueError("public release key import failed")
        result = subprocess.run(
            ["gpgv", "--homedir", home, "--status-fd", "1", "--keyring", f"{home}/pubring.kbx", str(signature), str(signed)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    if result.returncode != 0:
        raise ValueError(f"signature verification failed for {signed.name}")
    signatures = []
    for line in result.stdout.splitlines():
        if line.startswith("[GNUPG:] VALIDSIG "):
            signatures.append(line.split())
    if len(signatures) != 1 or len(signatures[0]) < 12:
        raise ValueError(f"signature status is ambiguous for {signed.name}")
    signing = signatures[0][2]
    primary = signatures[0][-1]
    if FINGERPRINT.fullmatch(signing) is None or FINGERPRINT.fullmatch(primary) is None:
        raise ValueError("signature fingerprints are malformed")
    if signing != artifact_fingerprint or primary != primary_fingerprint:
        raise ValueError(f"signature identity mismatch for {signed.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--primary-fingerprint", required=True)
    parser.add_argument("--artifact-fingerprint", required=True)
    parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        if HEX64.fullmatch(args.manifest_sha256) is None:
            raise ValueError("manifest SHA-256 is not canonical")
        verify(
            args.directory,
            tag=args.tag,
            commit=args.commit,
            manifest_digest=args.manifest_sha256,
            primary_fingerprint=args.primary_fingerprint,
            artifact_fingerprint=args.artifact_fingerprint,
            public_key=args.public_key,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError, ValueError) as error:
        print(f"verify-release-bundle: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
