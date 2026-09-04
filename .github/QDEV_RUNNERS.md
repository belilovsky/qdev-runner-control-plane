# QDev runner control-plane CI

This repository uses the existing centralized, ephemeral `qdev-ci` pool under
the supported `qdev-runner-v1` self-hosted-only contract. The owner authorized
migration of equivalent checks from billing-blocked hosted compute; there is
no GitHub-hosted or dynamic fallback. GitHub remains the workflow orchestrator.

`CI / verify` and `QDev runner contract / qdev-runner-contract` retain their
workflow/job names, triggers, timeouts, permissions, pinned actions and check
steps. Both run on `[self-hosted, Linux, X64, qdev-ci]` with a unique
`qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-<job>` lease label.
Python setup, Ruff, Mypy, the complete pytest suite and the runner-policy check
remain enabled. `qdev-ci` provides the general Python/native-build environment;
neither check needs the browser or Docker profile.

Fork pull requests are excluded at job level before checkout: only non-PR
events or PRs whose head repository equals this repository can execute on the
pool. A skipped fork job is not evidence that the fork's code passed checks.
Deployment credentials and labels remain separate from general CI.

Both workflows use `cancel-in-progress: false` and run/attempt-specific
concurrency groups. This prevents GitHub from replacing an older pending run
in the same group while the controller preserves FIFO. No controller queue,
lease, priority, capacity or pause-owner settings are changed by this migration.
Matrix jobs must additionally include `${{ strategy.job-index }}` in their
lease label.

The shared checker already supports v1; its v2 mode is hosted-primary with
manual-only recovery and cannot represent these automatic self-hosted checks.
Keep `.github/qdev-runner.yml`, these workflows and the local `AGENTS.md` policy
together. Do not overwrite this repository's execution mode with hosted-primary
template defaults without an explicit contract migration. Run the unchanged
local checker with `python3 .github/scripts/qdev-runner-policy.py --root .`.

Acceptance still requires terminal provider results for both checks on the
exact candidate SHA. Dispatch `.github/workflows/runner-smoke.yml` only after
controller, worker, capacity, executor-image and pause-owner gates pass, and
bind its evidence to the same default-branch SHA. Local policy/tests and a smoke
run do not substitute for the two required checks or prove runtime activation.
