from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_lane_unit_uses_separate_config_and_state() -> None:
    unit = (ROOT / "deploy/qdev-runner-worker@.service").read_text(encoding="utf-8")

    assert "EnvironmentFile=/etc/qdev-runner/workers/%i.env" in unit
    assert "ReadWritePaths=/var/lib/qdev-runner-worker/lanes/%i" in unit
    assert "PartOf=qdev-runner-worker.service" in unit
    assert "WantedBy=qdev-runner-worker.service" in unit


def test_lane_resource_drop_ins_enforce_fixed_bounds() -> None:
    expected = {
        "light": ("CPUQuota=200%", "MemoryMax=8G", "TasksMax=1536"),
        "browser": ("CPUQuota=200%", "MemoryMax=6G", "TasksMax=1024"),
        "docker": ("CPUQuota=400%", "MemoryMax=12G", "TasksMax=2048"),
    }
    for lane, values in expected.items():
        drop_in = (
            ROOT / f"deploy/qdev-runner-worker@{lane}.service.d/10-resources.conf"
        ).read_text(encoding="utf-8")
        for value in values:
            assert value in drop_in
        assert "MemorySwapMax=0" in drop_in
        assert "IOWeight=" in drop_in


def test_docker_lane_includes_compose_profile_contract() -> None:
    example = (ROOT / "deploy/worker-lanes.env.example").read_text(encoding="utf-8")

    assert "QDEV_WORKER_PROFILES=qdev-ci-compose,qdev-ci-docker" in example
    assert "QDEV_WORKER_CONCURRENCY=1" in example
