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


def test_provision_capacity_policy_is_sealed_to_a_durable_tier() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    # The published contract has exactly two tiers: 30 GiB/85% for a normal
    # shared worker and 10 GiB/90% for a continuously monitored durable worker.
    assert "QDEV_WORKER_PROVISION_DURABLE:-false" in script
    assert "tier_min_free_gib=10" in script
    assert "tier_max_disk_used_pct=90" in script
    assert "tier_min_free_gib=30" in script
    assert "tier_max_disk_used_pct=85" in script
    assert 'provision_min_free_gib="$tier_min_free_gib"' in script
    assert 'provision_max_disk_used_pct="$tier_max_disk_used_pct"' in script
    assert "QDEV_WORKER_PROVISION_MIN_FREE_GIB \\" in script
    assert "QDEV_WORKER_PROVISION_MAX_DISK_USED_PCT \\" in script
    assert "QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE; do" in script
    assert "is retired; provisioning uses the sealed tier gate" in script
    assert "allow_capacity_override" not in script
    assert 'min_free="$provision_min_free_kib"' in script
    assert "used > max_used" in script
    assert "mem < 4194304" in script


def test_provision_archives_a_versioned_virtualenv_link() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert '[[ -L "${install_root}/.venv" ]]' in script
    assert "backups/venv-link-$(date -u +%Y%m%dT%H%M%SZ)" in script
    assert 'mv -- "${install_root}/.venv" "$venv_link_backup/.venv"' in script
    assert 'python3 -m venv "${install_root}/.venv"' in script


def test_provision_requires_source_bound_buildkit_materialization() -> None:
    script = Path("scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert (
        "buildkit_source_sha256=c365476e1b10e27a2ab809e3a7a6dcd0647a60fa6e8917799b894d4127af7306"
    ) in script
    assert "buildkit_source_revision=dddd5621af04ea57823085c93a063383f71d3173" in script
    assert "QDEV_BUILDKIT_ARTIFACT_ROOT" in script
    assert "QDEV_BUILDKIT_IMAGE_REF" in script
    assert "source-bound BuildKit artifact is required" in script
    assert "source-bound BuildKit artifact failed validation" in script
    assert 'chmod 0711 "$buildkit_stage"' in script
    assert 'mv -- "$buildkit_release_stage" "$buildkit_root"' in script
    assert "buildkit-v${buildkit_version}.linux-amd64.tar.gz" not in script
