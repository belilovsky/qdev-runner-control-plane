from pathlib import Path


def test_provision_archives_exact_legacy_rollout_gate() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert "zzzzzzz-runner-rollout-lock.conf" in script
    assert "/etc/qdev/qdev-runner-worker.rollout-permit" in script
    assert "legacy-gate-$(date -u +%Y%m%dT%H%M%SZ)" in script
    assert 'mv -- "$legacy_path" "$legacy_gate_backup/"' in script


def test_provision_capacity_override_is_explicit_and_lower_only() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert 'QDEV_WORKER_PROVISION_MIN_FREE_GIB:-30' in script
    assert 'QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE:-false' in script
    assert 'provision_min_free_gib < 20' in script
    assert 'provision_min_free_gib > 30' in script
    assert 'provision_min_free_gib != 30' in script
    assert 'allow_capacity_override' in script
    assert 'min_free="$provision_min_free_kib"' in script
    assert 'used > 85' in script
    assert 'mem < 4194304' in script
