from pathlib import Path


def test_provision_refuses_to_replace_an_active_worker() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert "systemctl is-active --quiet qdev-runner-worker.service" in script
    assert "refusing to provision while qdev-runner-worker.service is active" in script
    assert "exit 75" in script


def test_provision_archives_exact_legacy_rollout_gate() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert "zzzzzzz-runner-rollout-lock.conf" in script
    assert "/etc/qdev/qdev-runner-worker.rollout-permit" in script
    assert "legacy-gate-$(date -u +%Y%m%dT%H%M%SZ)" in script
    assert 'mv -- "$legacy_path" "$legacy_gate_backup/"' in script


def test_provision_capacity_override_is_explicit_and_lower_only() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert "QDEV_WORKER_PROVISION_MIN_FREE_GIB:-30" in script
    assert "QDEV_WORKER_PROVISION_MAX_DISK_USED_PCT:-85" in script
    assert "QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE:-false" in script
    assert "provision_min_free_gib < 5" in script
    assert "provision_min_free_gib > 30" in script
    assert "provision_max_disk_used_pct < 85" in script
    assert "provision_max_disk_used_pct > 95" in script
    assert "provision_min_free_gib != 30" in script
    assert "provision_max_disk_used_pct != 85" in script
    assert "allow_capacity_override" in script
    assert 'min_free="$provision_min_free_kib"' in script
    assert "used > max_used" in script
    assert "mem < 4194304" in script


def test_provision_archives_a_versioned_virtualenv_link() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert '[[ -L "${install_root}/.venv" ]]' in script
    assert "backups/venv-link-$(date -u +%Y%m%dT%H%M%SZ)" in script
    assert 'mv -- "${install_root}/.venv" "$venv_link_backup/.venv"' in script
    assert 'python3 -m venv "${install_root}/.venv"' in script
