from pathlib import Path


def test_provision_archives_exact_legacy_rollout_gate() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert "zzzzzzz-runner-rollout-lock.conf" in script
    assert "/etc/qdev/qdev-runner-worker.rollout-permit" in script
    assert "legacy-gate-$(date -u +%Y%m%dT%H%M%SZ)" in script
    assert 'mv -- "$legacy_path" "$legacy_gate_backup/"' in script

