import json
from pathlib import Path

import pytest
import yaml

from qdev_runner.admin_platform_ledger import AdminPlatformLedger, AdminPlatformLedgerError


def _ledger_path() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger.yml"


def _ledger_v2_path() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml"


def test_ledger_keeps_one_active_candidate_and_the_required_order() -> None:
    ledger = AdminPlatformLedger(_ledger_path())

    assert ledger.active_candidate == "avds-admin-shell"
    assert [entry.entry_id for entry in ledger.entries] == [
        "avds-admin-shell",
        "ortcom",
        "cmnt",
        "total",
        "qazposter",
    ]


def test_ledger_rejects_a_nonterminal_predecessor(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_path().read_text(encoding="utf-8"))
    document["active_candidate"] = "ortcom"
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="prior release"):
        AdminPlatformLedger(path)


def test_ledger_admits_only_the_active_exact_source_tuple() -> None:
    ledger = AdminPlatformLedger(_ledger_path())

    assert ledger.classify_admission(
        "avds-admin-shell", "975a725fd96edff73f3f171f155362e97482177e"
    ) == (True, None)
    assert ledger.classify_admission("qazposter", "9ebf6718c2085d1a58f59323f37b1e1dd707225f") == (
        False,
        "admin-platform-candidate-not-active",
    )
    assert ledger.classify_admission("avds-admin-shell", "a" * 40) == (
        False,
        "admin-platform-candidate-tuple-not-admitted",
    )
    assert (
        ledger.validate_admission(
            "avds-admin-shell", "975a725fd96edff73f3f171f155362e97482177e"
        ).project_id
        == "avds-admin-shell"
    )
    with pytest.raises(AdminPlatformLedgerError, match="not active"):
        ledger.validate_admission("ortcom", "a" * 40)
    with pytest.raises(AdminPlatformLedgerError, match="tuple"):
        ledger.validate_admission("avds-admin-shell", "a" * 40)


def test_v2_snapshot_is_json_serializable_when_yaml_resolves_timestamps() -> None:
    ledger = AdminPlatformLedger(_ledger_v2_path())

    encoded = json.dumps(ledger.snapshot(), sort_keys=True)

    assert "2026-09-04T00:00:00Z" in encoded
