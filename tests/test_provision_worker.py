import os
import shlex
import subprocess
from pathlib import Path

BUILDKIT_REVISION = "dddd5621af04ea57823085c93a063383f71d3173"
BUILDKIT_SHA256 = "c365476e1b10e27a2ab809e3a7a6dcd0647a60fa6e8917799b894d4127af7306"


def _write_gnu_stat_shim(directory: Path) -> None:
    shim = directory / "stat"
    shim.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
[[ \"$1\" == \"-c\" ]] || exit 64
format=\"$2\"
target=\"$3\"
case \"$format\" in
  '%u:%g') printf '%s\\n' \"${QDEV_TEST_STAT_OWNER:-0:0}\" ;;
  '%a')
    case \"$target\" in
      */bin/buildkitd) printf '%s\\n' \"${QDEV_TEST_BUILDKITD_MODE:-555}\" ;;
      */bin/buildctl) printf '%s\\n' \"${QDEV_TEST_BUILDKITCTL_MODE:-555}\" ;;
      */source-revision|*/source-sha256) printf '%s\\n' \"${QDEV_TEST_MARKER_MODE:-444}\" ;;
      *) printf '%s\\n' \"${QDEV_TEST_DIRECTORY_MODE:-755}\" ;;
    esac
    ;;
  *) exit 64 ;;
esac
""",
        encoding="utf-8",
    )
    shim.chmod(0o755)


def _buildkit_root(tmp_path: Path) -> Path:
    root = tmp_path / "buildkit"
    binaries = root / "bin"
    binaries.mkdir(parents=True)
    for name in ("buildkitd", "buildctl"):
        binary = binaries / name
        binary.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        binary.chmod(0o555)
    (root / "source-revision").write_text(f"{BUILDKIT_REVISION}\n", encoding="utf-8")
    (root / "source-sha256").write_text(f"{BUILDKIT_SHA256}\n", encoding="utf-8")
    (root / "source-revision").chmod(0o444)
    (root / "source-sha256").chmod(0o444)
    return root


def _validate_buildkit(
    root: Path, stat_directory: Path, **overrides: str
) -> subprocess.CompletedProcess[str]:
    library = Path("scripts/lib/buildkit_materialization.sh").resolve()
    command = "\n".join(
        (
            "set -euo pipefail",
            f"buildkit_source_revision={shlex.quote(BUILDKIT_REVISION)}",
            f"buildkit_source_sha256={shlex.quote(BUILDKIT_SHA256)}",
            f"source {shlex.quote(str(library))}",
            f"validate_buildkit_materialization {shlex.quote(str(root))}",
        )
    )
    environment = os.environ | {"PATH": f"{stat_directory}:{os.environ['PATH']}"} | overrides
    return subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", command],
        check=False,
        env=environment,
        text=True,
        capture_output=True,
    )


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
    assert 'mv -- "$buildkit_release_stage" "$buildkit_root"' in script
    assert "buildkit-v${buildkit_version}.linux-amd64.tar.gz" not in script
    assert 'source "$(dirname "${BASH_SOURCE[0]}")/lib/buildkit_materialization.sh"' in script


def test_buildkit_materialization_accepts_only_the_pinned_layout(tmp_path: Path) -> None:
    stat_directory = tmp_path / "bin"
    stat_directory.mkdir()
    _write_gnu_stat_shim(stat_directory)

    result = _validate_buildkit(_buildkit_root(tmp_path), stat_directory)

    assert result.returncode == 0, result.stderr


def test_buildkit_materialization_rejects_wrong_source_binding(tmp_path: Path) -> None:
    stat_directory = tmp_path / "bin"
    stat_directory.mkdir()
    _write_gnu_stat_shim(stat_directory)
    root = _buildkit_root(tmp_path)
    revision = root / "source-revision"
    revision.chmod(0o644)
    revision.write_text("different\n", encoding="utf-8")
    revision.chmod(0o444)

    result = _validate_buildkit(root, stat_directory)

    assert result.returncode != 0


def test_buildkit_materialization_rejects_unsafe_permissions(tmp_path: Path) -> None:
    stat_directory = tmp_path / "bin"
    stat_directory.mkdir()
    _write_gnu_stat_shim(stat_directory)

    result = _validate_buildkit(
        _buildkit_root(tmp_path),
        stat_directory,
        QDEV_TEST_BUILDKITD_MODE="700",
    )

    assert result.returncode != 0


def test_buildkit_materialization_rejects_symlinked_marker(tmp_path: Path) -> None:
    stat_directory = tmp_path / "bin"
    stat_directory.mkdir()
    _write_gnu_stat_shim(stat_directory)
    root = _buildkit_root(tmp_path)
    marker = root / "source-sha256"
    replacement = root / "replacement"
    replacement.write_text(f"{BUILDKIT_SHA256}\n", encoding="utf-8")
    marker.unlink()
    marker.symlink_to(replacement)

    result = _validate_buildkit(root, stat_directory)

    assert result.returncode != 0
