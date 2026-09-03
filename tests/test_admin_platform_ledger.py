from pathlib import Path

import pytest
import yaml

from qdev_runner.admin_platform_ledger import AdminPlatformLedger, AdminPlatformLedgerError


def _ledger_path() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger.yml"


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
