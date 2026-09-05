from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_setup_prerequisite_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("lsb-release") == 2


def test_native_build_toolchain_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("build-essential") == 2


def test_general_image_supplies_native_postgresql_16_toolchain() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    base, after_general = dockerfile.split("FROM base AS general", maxsplit=1)
    general, after_browser = after_general.split("FROM mcr.microsoft.com/playwright", maxsplit=1)
    browser, docker = after_browser.split("FROM base AS docker", maxsplit=1)
    assert "postgresql-16" not in base
    assert "postgresql-16" in general
    assert "postgresql-16" not in browser
    assert "postgresql-16" not in docker
    assert "for binary in initdb pg_ctl createdb dropdb psql pg_dump pg_restore" in general
    assert 'test -x "/usr/lib/postgresql/16/bin/${binary}"' in general
    assert "/usr/lib/postgresql/16/bin/postgres --version" in general
    assert "grep -Eq ' 16\\.'" in general


def test_general_image_removes_package_generated_snakeoil_tls_material() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    _, after_general = dockerfile.split("FROM base AS general", maxsplit=1)
    general, _ = after_general.split("FROM mcr.microsoft.com/playwright", maxsplit=1)
    assert "rm -f" in general
    assert "/etc/ssl/private/ssl-cert-snakeoil.key" in general
    assert "/etc/ssl/certs/ssl-cert-snakeoil.pem" in general
    assert "test ! -e /etc/ssl/private/ssl-cert-snakeoil.key" in general
    assert "test ! -e /etc/ssl/certs/ssl-cert-snakeoil.pem" in general


def test_browser_image_pins_the_playwright_1_62_1_chromium_bundle() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert "Playwright clients installed by browser jobs must stay in lockstep" in dockerfile
    assert (
        "mcr.microsoft.com/playwright@sha256:"
        "c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac"
    ) in dockerfile


def test_worker_defaults_match_the_immutable_runner_image_release() -> None:
    settings = (ROOT / "src/qdev_runner/settings.py").read_text(encoding="utf-8")
    builder = (ROOT / "scripts/build_runner_images.sh").read_text(encoding="utf-8")
    worker_audit = (ROOT / "scripts/audit_worker_runtime.py").read_text(encoding="utf-8")

    assert "_required_immutable_image" in settings
    assert "@sha256 content-addressed reference" in settings
    assert "image_not_immutable" in worker_audit
    assert 'QDEV_RUNNER_VERSION:-2.337.0-r7' in builder


def test_browser_release_is_flattened_before_publication() -> None:
    builder = (ROOT / "scripts/build_runner_images.sh").read_text(encoding="utf-8")

    assert 'browser_staging_image="${browser_image}-rootfs"' in builder
    assert '"$engine" export --output "${browser_export_root}/rootfs.tar"' in builder
    assert '"$engine" import' in builder
    assert "A Dockerfile whiteout" in builder
    assert 'ENTRYPOINT ["/usr/local/bin/qdev-runner-entrypoint"]' in builder
    assert '"$engine" image rm "${browser_staging_image}"' in builder


def test_actions_runner_release_and_digest_are_current_and_pinned() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert "ARG RUNNER_VERSION=2.337.0" in dockerfile
    assert (
        "ARG RUNNER_SHA256="
        "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"
    ) in dockerfile


def test_embedded_node_runtimes_replace_npm_with_pinned_verified_release() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")
    installer = (ROOT / "images/runner/install-pinned-npm.sh").read_text(encoding="utf-8")

    assert "ARG NPM_VERSION=11.19.1" in dockerfile
    assert (
        "ARG NPM_SHA512="
        "cedb312b1b7f92421a02cfb68b4194e88f8346651dacd6acc5364a25ef5309d4"
        "a32b19616a1ff8aff865e7280c0fa5c0835a99f5cd93368991e2a80ec9da75d2"
    ) in dockerfile
    assert dockerfile.count("install-pinned-npm /home/runner/actions-runner/externals/node20") == 2
    assert dockerfile.count("install-pinned-npm /home/runner/actions-runner/externals/node24") == 2
    assert "sha512sum --check" in installer
    assert 'test "${actual_version}" = "${npm_version}"' in installer


def test_browser_system_npm_is_pinned_hardened_and_cache_free() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")
    installer = (ROOT / "images/runner/install-pinned-node-package.sh").read_text(
        encoding="utf-8"
    )

    _, browser = dockerfile.split("FROM mcr.microsoft.com/playwright", maxsplit=1)
    assert "ARG SYSTEM_NPM_VERSION=12.0.2" in dockerfile
    assert "ARG BRACE_EXPANSION_VERSION=5.0.9" in dockerfile
    assert "ARG IP_ADDRESS_VERSION=10.3.1" in dockerfile
    assert "ARG TAR_VERSION=7.5.21" in dockerfile
    assert 'install-pinned-npm /usr "${SYSTEM_NPM_VERSION}"' in browser
    assert browser.count("install-pinned-node-package /usr/lib/node_modules/npm/node_modules") == 3
    assert "rm -rf /root/.npm" in browser
    assert "test ! -e /root/.npm" in browser
    assert "FROM scratch AS browser" in browser
    assert "COPY --from=browser-build / /" in browser
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in browser
    assert "sha512sum --check" in installer
    assert 'test "${actual_name}" = "${package_name}"' in installer
    assert 'test "${actual_version}" = "${package_version}"' in installer


def test_docker_profile_has_compose_plugin() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert "docker.io docker-buildx docker-compose-v2" in dockerfile


def test_docker_profile_logs_in_with_job_scoped_registry_credentials() -> None:
    entrypoint = (ROOT / "images/runner/entrypoint.sh").read_text(encoding="utf-8")

    assert "QDEV_REGISTRY_PASSWORD" in entrypoint
    assert "--password-stdin" in entrypoint
    assert "QDEV_REGISTRY_URL" in entrypoint
