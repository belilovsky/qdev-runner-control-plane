# QDev runner control plane

This repository is the single control plane for ephemeral self-hosted GitHub
Actions runners used by the active `belilovsky` repositories. GitHub-hosted
compute, GitHub cache/artifact storage and GHCR are not availability
dependencies.

## Contract

- Repository jobs select exactly one of `qdev-ci`, `qdev-ci-browser` or
  `qdev-ci-docker` together with `self-hosted`, `Linux`, `X64`.
- A queued `workflow_job` webhook is accepted only for a repository in
  `inventory/repos.json` and a profile allowed by `.github/qdev-runner.yml`.
- The broker creates a JIT registration. A worker starts one rootless,
  resource-limited container for one job and removes it afterwards.
- `qdev-ci-docker` receives a job-scoped Docker/BuildKit daemon inside a
  disposable privileged sidecar of the rootless worker engine. The runner
  shares only that sidecar's network namespace and socket; the worker's Docker
  socket is never mounted into a job. The broker injects the narrow registry
  credential through the private job env-file, and the runner logs into the
  private registry only inside its disposable container.
  This uses the dedicated `qdev-runner` registry account; the existing `qdev`
  account is not rotated or exposed to jobs.
- Public fork pull requests are rejected. Dedicated release labels remain
  product-specific and are not assigned to the general pool.
- The capacity gate stops claims above 85% disk usage, below 30 GiB free disk,
  below 4 GiB available memory or above load-15 equal to twice the CPU count.
  Worker-specific floors can be raised with `QDEV_WORKER_MIN_FREE_GIB`,
  `QDEV_WORKER_MAX_DISK_USED_PCT`, `QDEV_WORKER_MIN_MEMORY_AVAILABLE_GIB`,
  `QDEV_WORKER_MAX_LOAD_PER_CPU` and `QDEV_WORKER_MAX_CPU_PSI_AVG10`.
- Every registered repository carries the managed root `AGENTS.md` policy,
  `.github/QDEV_RUNNERS.md`, and the local `qdev-runner-contract` check. Future
  agents must install this starter bundle instead of creating a standalone
  runner or a GitHub-hosted fallback.

## Repository onboarding

Start from `templates/qdev-runner.yml` and `templates/runner-smoke.yml`, then
install the managed policy into the repository checkout:

```bash
python3 scripts/apply_repository_policy.py /path/to/checkout
python3 /path/to/checkout/.github/scripts/qdev-runner-policy.py \
  --root /path/to/checkout
```

Register the repository in `inventory/repos.json`, install the GitHub App, and
run `runner-smoke` on its default branch. The installer is idempotent and
preserves repository-specific instructions outside its marked `AGENTS.md`
section.

After the policy workflow is present on the default branch, preserve the
repository's existing classic branch-protection settings and add only the
managed check:

```bash
python3 scripts/configure_required_check.py --repository owner/repository
python3 scripts/configure_required_check.py --apply --repository owner/repository
```

The first command is a dry run. Repositories without classic branch protection
are reported and left unchanged.

## Services

- `https://ci.qdev.run/github/workflow-job` — signed GitHub App webhook.
- `https://ci.qdev.run/health` — public-safe broker health.
- `https://worker.ci.qdev.run/internal/v1/*` — mTLS worker API.
- `https://ci.qdev.run/artifacts/...` — checksum-verified, short-lived artifacts.
- `https://registry.ci.qdev.run/v2/` — private OCI registry.

## Guarded controller release

Stage each revision in its own directory below
`/opt/qdev-runner-control-plane/releases/`. Activate it with the revision's
own script:

```bash
sudo scripts/activate_controller_release.sh \
  /opt/qdev-runner-control-plane/releases/REVISION
```

Activation requires at least 30 GiB free disk, less than 85% disk use, at
least 4 GiB available RAM, and load-15 no greater than twice the CPU count. It
atomically changes `current`, refreshes the repository inventory, and recreates
only `broker-public` and `broker-internal`. It does not restart a worker, stop
the registry, remove Compose or Docker objects, or touch product containers.
If either Compose or the public health check fails, the script restores the
previous release and its inventory.

To select a previously staged revision without rebuilding its cached images:

```bash
sudo scripts/rollback_controller_release.sh REVISION
```

Runner images are built from the pinned definitions in `images/runner` and
published only after the same capacity gate is healthy:

```bash
QDEV_PUSH_IMAGES=true scripts/build_runner_images.sh
```

Record the three resulting registry digests in rollout evidence. Do not reuse
a mutable image from an unverified build.

## Portfolio rollout

Use `scripts/rollout_repository_policy.py` from isolated temporary clones and
merge in bounded waves. Preserve every existing required check and add
`qdev-runner-contract` only after that workflow is present on the default
branch. Run `runner-smoke` on each resulting default SHA and record repository,
SHA, run ID, queue time, and runner name. Deployment workflows and dedicated
release labels are never dispatched as part of this validation.

## Local verification

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
python3 scripts/refresh_inventory.py
python3 scripts/audit_workflows.py --allow-migration
```

Secrets are provisioned only on the broker/worker hosts. GitHub App keys,
webhook secrets, worker tokens, registry passwords and client certificates
must never be committed.
