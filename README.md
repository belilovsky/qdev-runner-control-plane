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
- Public fork pull requests are rejected. Dedicated release labels remain
  product-specific and are not assigned to the general pool.
- The capacity gate stops claims above 85% disk usage, below 30 GiB free disk,
  below 4 GiB available memory or above load-15 equal to twice the CPU count.

## Services

- `https://ci.qdev.run/github/workflow-job` — signed GitHub App webhook.
- `https://ci.qdev.run/health` — public-safe broker health.
- `https://worker.ci.qdev.run/internal/v1/*` — mTLS worker API.
- `https://ci.qdev.run/artifacts/...` — checksum-verified, short-lived artifacts.
- `https://registry.ci.qdev.run/v2/` — private OCI registry.

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

