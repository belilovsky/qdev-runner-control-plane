import sys
from pathlib import Path

import pytest

from qdev_runner import controller_image_candidate as candidate

SHA = "a" * 40
BUNDLE = "b" * 64
IMAGE = "sha256:" + "c" * 64
BASE = "sha256:" + "d" * 64


def receipt() -> dict[str, object]:
    return candidate.create(
        source_revision=SHA,
        bundle_digest=BUNDLE,
        image_digest=IMAGE,
        base_image_digest=BASE,
        wheelhouse_digest="e" * 64,
        requirements_digest="f" * 64,
        sbom_digest="1" * 64,
        run_id="1234",
        run_attempt=2,
        job="controller-image-candidate",
        created_at="2026-09-05T01:02:03Z",
    )


def test_candidate_receipt_binds_exact_source_image_and_attempt() -> None:
    result = receipt()

    assert result["image_ref"] == f"{candidate.REPOSITORY}@{IMAGE}"
    assert result["run_attempt"] == 2
    assert candidate.verify(result) == result


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_revision", "main"),
        ("bundle_digest", "sha256:" + BUNDLE),
        ("image_digest", "c" * 64),
        ("base_image_digest", "d" * 64),
        ("wheelhouse_digest", "sha256:" + "e" * 64),
        ("run_id", "0"),
        ("run_attempt", 0),
        ("job", "other"),
        ("created_at", "2026-09-05T01:02:03+06:00"),
    ],
)
def test_candidate_receipt_rejects_invalid_identity(field: str, value: object) -> None:
    values: dict[str, object] = {
        "source_revision": SHA,
        "bundle_digest": BUNDLE,
        "image_digest": IMAGE,
        "base_image_digest": BASE,
        "wheelhouse_digest": "e" * 64,
        "requirements_digest": "f" * 64,
        "sbom_digest": "1" * 64,
        "run_id": "1234",
        "run_attempt": 2,
        "job": "controller-image-candidate",
        "created_at": "2026-09-05T01:02:03Z",
    }
    values[field] = value

    with pytest.raises((candidate.CandidateReceiptError, TypeError)):
        candidate.create(**values)  # type: ignore[arg-type]


def test_candidate_receipt_rejects_tampering() -> None:
    changed = receipt()
    changed["source_revision"] = "d" * 40

    with pytest.raises(candidate.CandidateReceiptError):
        candidate.verify(changed)


def test_candidate_receipt_cli_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "receipt.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qdev-controller-image-candidate",
            "create",
            "--source-revision",
            SHA,
            "--bundle-digest",
            BUNDLE,
            "--image-digest",
            IMAGE,
            "--base-image-digest",
            BASE,
            "--wheelhouse-digest",
            "e" * 64,
            "--requirements-digest",
            "f" * 64,
            "--sbom-digest",
            "1" * 64,
            "--run-id",
            "1234",
            "--run-attempt",
            "2",
            "--job",
            "controller-image-candidate",
            "--created-at",
            "2026-09-05T01:02:03Z",
            "--output",
            str(target),
        ],
    )
    assert candidate.main() == 0
    assert target.read_text(encoding="utf-8").endswith("\n")
    assert "receipt_digest" in capsys.readouterr().out
