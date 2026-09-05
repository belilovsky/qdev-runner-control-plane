"""Create and verify the offline bootstrap runtime wheelhouse."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "qdev-bootstrap-wheelhouse-v1"
MANIFEST = "bootstrap-wheelhouse.json"
_PIN = re.compile(
    r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)"
    r" --hash=sha256:([0-9a-f]{64})$"
)
_WHEEL = re.compile(r"^([A-Za-z0-9_.]+)-([A-Za-z0-9_.+!]+)-.+\.whl$")
_APP = "qdev-runner-control-plane"


class WheelhouseError(RuntimeError):
    """The wheelhouse is incomplete, ambiguous, or has changed."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _normalise(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _requirements(path: Path) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN.fullmatch(line)
        if match is None:
            raise WheelhouseError("bootstrap requirement is not exactly pinned")
        name = _normalise(match.group(1))
        if name in result:
            raise WheelhouseError("bootstrap requirement is duplicated")
        result[name] = (match.group(2), match.group(3))
    if not result:
        raise WheelhouseError("bootstrap requirements are empty")
    return result


def _wheel_records(root: Path) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    records: dict[str, dict[str, str]] = {}
    packages: dict[str, str] = {}
    for path in sorted(root.iterdir()):
        if path.name == MANIFEST:
            continue
        if path.is_symlink() or not path.is_file():
            raise WheelhouseError("wheelhouse contains an invalid entry")
        match = _WHEEL.fullmatch(path.name)
        if match is None:
            raise WheelhouseError("wheelhouse contains a non-wheel artifact")
        name = _normalise(match.group(1))
        version = match.group(2)
        if name in packages:
            raise WheelhouseError("wheelhouse contains duplicate distributions")
        packages[name] = version
        records[path.name] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "distribution": name,
            "version": version,
        }
    return records, packages


def _sbom(records: dict[str, dict[str, str]]) -> dict[str, Any]:
    packages = [
        {
            "SPDXID": f"SPDXRef-Package-{record['distribution']}",
            "checksums": [{"algorithm": "SHA256", "checksumValue": record["sha256"]}],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "name": record["distribution"],
            "versionInfo": record["version"],
        }
        for record in records.values()
    ]
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": "1970-01-01T00:00:00Z",
            "creators": ["Tool: qdev-bootstrap-wheelhouse-v1"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://run.qdev.invalid/sbom/controller-bootstrap/v1",
        "name": "qdev-controller-bootstrap-wheelhouse",
        "packages": packages,
        "spdxVersion": "SPDX-2.3",
    }


def build(root: Path, requirements_path: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    requirements_path = requirements_path.resolve(strict=True)
    requirements = _requirements(requirements_path)
    records, packages = _wheel_records(root)
    if packages.get(_APP) is None:
        raise WheelhouseError("application wheel is unavailable")
    for name, (version, expected_hash) in requirements.items():
        if packages.get(name) != version:
            raise WheelhouseError(f"wheelhouse does not match pinned requirement: {name}")
        wheel = next(record for record in records.values() if record["distribution"] == name)
        if wheel["sha256"] != expected_hash:
            raise WheelhouseError(f"wheelhouse hash does not match pinned requirement: {name}")
    if set(packages) != set(requirements) | {_APP}:
        raise WheelhouseError("wheelhouse contains an undeclared distribution")
    sbom = _sbom(records)
    identity = {
        "schema": SCHEMA,
        "python": "3.12",
        "requirements_sha256": hashlib.sha256(requirements_path.read_bytes()).hexdigest(),
        "wheels": records,
        "sbom": sbom,
        "sbom_sha256": hashlib.sha256(_canonical(sbom)).hexdigest(),
    }
    manifest = {**identity, "wheelhouse_digest": hashlib.sha256(_canonical(identity)).hexdigest()}
    target = root / MANIFEST
    if target.exists() or target.is_symlink():
        raise WheelhouseError("wheelhouse manifest already exists")
    target.write_bytes(_canonical(manifest) + b"\n")
    target.chmod(0o444)
    verify(root, requirements_path)
    return manifest


def verify(root: Path, requirements_path: Path) -> dict[str, Any]:
    root = root.resolve(strict=True)
    requirements_path = requirements_path.resolve(strict=True)
    try:
        manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise WheelhouseError("wheelhouse manifest is unavailable") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "python",
        "requirements_sha256",
        "wheels",
        "sbom",
        "sbom_sha256",
        "wheelhouse_digest",
    }:
        raise WheelhouseError("wheelhouse manifest shape is invalid")
    requirements = _requirements(requirements_path)
    records, packages = _wheel_records(root)
    identity = {
        key: manifest[key]
        for key in ("schema", "python", "requirements_sha256", "wheels", "sbom", "sbom_sha256")
    }
    expected_packages = set(requirements) | {_APP}
    if (
        manifest["schema"] != SCHEMA
        or manifest["python"] != "3.12"
        or manifest["requirements_sha256"]
        != hashlib.sha256(requirements_path.read_bytes()).hexdigest()
        or manifest["wheels"] != records
        or manifest["sbom"] != _sbom(records)
        or manifest["sbom_sha256"] != hashlib.sha256(_canonical(_sbom(records))).hexdigest()
        or set(packages) != expected_packages
        or any(
            packages.get(name) != version
            or next(record for record in records.values() if record["distribution"] == name)[
                "sha256"
            ]
            != expected_hash
            for name, (version, expected_hash) in requirements.items()
        )
        or manifest["wheelhouse_digest"] != hashlib.sha256(_canonical(identity)).hexdigest()
    ):
        raise WheelhouseError("wheelhouse identity mismatch")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build", "verify"))
    parser.add_argument("root", type=Path)
    parser.add_argument("--requirements", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = (
            build(args.root, args.requirements)
            if args.command == "build"
            else verify(args.root, args.requirements)
        )
    except (WheelhouseError, OSError, UnicodeError, ValueError):
        print("bootstrap_wheelhouse_invalid")
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
