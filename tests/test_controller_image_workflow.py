from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_controller_image_candidate_is_main_only_digest_bound_and_qdev_stored() -> None:
    workflow = (ROOT / ".github/workflows/controller-image-candidate.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "qdev-ci-docker" in workflow
    assert "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-controller-image" in workflow
    assert "git rev-parse HEAD" in workflow
    assert "ruff check ." in workflow
    assert "mypy" in workflow
    assert "pytest -q" in workflow
    assert "controller_release_bundle build" in workflow
    assert "bootstrap_wheelhouse build" in workflow
    assert "--require-hashes --no-deps" in workflow
    assert '--wheelhouse "$wheelhouse"' in workflow
    assert "--base-image-digest" in workflow
    assert "--sbom-digest" in workflow
    assert "docker buildx build --push" in workflow
    assert "--metadata-file" in workflow
    assert '"containerimage.digest"' in workflow
    assert "docker buildx imagetools inspect" in workflow
    assert "qdev_runner.controller_image_candidate create" in workflow
    assert "templates/qdev-upload-artifact.sh" in workflow
    assert "actions/upload-artifact@" not in workflow
    assert "ghcr.io" not in workflow
    assert "ubuntu-latest" not in workflow


def test_controller_release_image_is_source_and_bundle_labelled() -> None:
    dockerfile = (ROOT / "deploy/Dockerfile.controller-release").read_text(encoding="utf-8")

    assert 'org.opencontainers.image.revision="${SOURCE_REVISION}"' in dockerfile
    assert 'run.qdev.controller.bundle-digest="${BUNDLE_DIGEST}"' in dockerfile
    assert "python:3.12.11-slim-bookworm@sha256:" in dockerfile
    assert "--no-index --no-deps --require-hashes" in dockerfile
    assert "--find-links wheelhouse -r requirements.runtime.txt" in dockerfile
    assert "USER 9020:9020" in dockerfile
