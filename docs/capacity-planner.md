# Four-VPS capacity planner

`scripts/qdev_capacity_planner.py` converts aggregate, profile-scoped history
into a review-only capacity recommendation. It accepts only
`qdev-ci-profile-history-v1` JSON and the sealed profiles `qdev-ci`,
`qdev-ci-browser`, and `qdev-ci-docker`.

For complete seven-day history it calculates, independently for every profile:

`ceil(p95 hourly arrivals * p95 duration minutes / 60 / 0.7)`

It then preserves the six active-slot minimum and the two-slot N+1 reserve on
the fourth existing VPS. Missing, incomplete or malformed history does not
invent demand: it returns that fixed `6 + 2` baseline and asks for a reviewed
host audit. A result larger than eight registered slots is explicitly marked
`capacity_review_required`; it never provisions a host, changes a runner
identity, dispatches a job, or reorders FIFO.

```bash
python3.12 scripts/qdev_capacity_planner.py \
  --history /var/lib/qdev-runner/capacity/seven-day-history.json \
  --output /var/lib/qdev-runner/capacity/latest-plan.json
```

The output is an input to the sealed controller admission and four-host audit
process, not admission authority. Only the registered worker identity, signed
host audit, immutable image check and `claim-scope-v2` controller path can
make a slot eligible.
