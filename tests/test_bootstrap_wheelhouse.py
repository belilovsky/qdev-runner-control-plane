from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qdev_runner import bootstrap_wheelhouse as wheelhouse


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "wheelhouse"
    root.mkdir(parents=True)
    (root / "dependency-1.2.3-py3-none-any.whl").write_bytes(b"dependency")
    (root / "qdev_runner_control_plane-4.5.6-py3-none-any.whl").write_bytes(b"app")
    requirements = tmp_path / "requirements.runtime.txt"
    digest = hashlib.sha256(b"dependency").hexdigest()
    requirements.write_text(f"dependency==1.2.3 --hash=sha256:{digest}\n", encoding="utf-8")
    return root, requirements


def test_build_and_verify_offline_wheelhouse_and_sbom(tmp_path: Path) -> None:
    root, requirements = _fixture(tmp_path)

    manifest = wheelhouse.build(root, requirements)

    assert wheelhouse.verify(root, requirements) == manifest
    assert manifest["sbom"]["spdxVersion"] == "SPDX-2.3"
    assert len(manifest["sbom"]["packages"]) == 2
    assert len(manifest["wheelhouse_digest"]) == 64
    assert json.loads((root / wheelhouse.MANIFEST).read_text(encoding="utf-8")) == manifest


@pytest.mark.parametrize("mutation", ("wheel", "manifest", "extra"))
def test_verify_rejects_tampered_or_undeclared_content(tmp_path: Path, mutation: str) -> None:
    root, requirements = _fixture(tmp_path)
    wheelhouse.build(root, requirements)
    if mutation == "wheel":
        (root / "dependency-1.2.3-py3-none-any.whl").write_bytes(b"changed")
    elif mutation == "manifest":
        manifest = json.loads((root / wheelhouse.MANIFEST).read_text(encoding="utf-8"))
        manifest["sbom_sha256"] = "0" * 64
        (root / wheelhouse.MANIFEST).chmod(0o644)
        (root / wheelhouse.MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")
    else:
        (root / "other-1.0-py3-none-any.whl").write_bytes(b"extra")

    with pytest.raises(wheelhouse.WheelhouseError):
        wheelhouse.verify(root, requirements)


def test_build_requires_exact_pins_application_and_no_extra_distributions(
    tmp_path: Path,
) -> None:
    root, requirements = _fixture(tmp_path)
    requirements.write_text("dependency>=1.2.3\n", encoding="utf-8")
    with pytest.raises(wheelhouse.WheelhouseError, match="exactly pinned"):
        wheelhouse.build(root, requirements)

    root, requirements = _fixture(tmp_path / "missing-app")
    (root / "qdev_runner_control_plane-4.5.6-py3-none-any.whl").unlink()
    with pytest.raises(wheelhouse.WheelhouseError, match="application wheel"):
        wheelhouse.build(root, requirements)
