# Operating Ariadne

Two deployment patterns, documented against verified behavior (exit codes and
timings tested in `ariadne-prove/cmd/ariadne/main_test.go` and
`internal/prove`; see `docs/goal-progress.md` for the verification log).

## Gate a CI pipeline on the verdict

`ariadne verdict --gate` exits `3` when the target grades `reckless`, `0`
otherwise. Exit codes are contract (`docs/cli-contract.md`): `0` success,
`1` runtime error, `2` usage error, `3` reckless (only with `--gate`).

```bash
# Any CI system: fail the job when the repo's agent config is reckless.
ariadne verdict --path . --mode repo --gate
```

```yaml
# GitHub Actions step
- name: Agent-config risk gate
  run: |
    make build
    ./bin/ariadne verdict --path . --mode repo --gate
```

Notes for pipeline authors:

- Output is deterministic: identical input produces identical output apart from
  `run_id` and `generated_at` (enforced by a repeated-run byte-equality test).
  Diffing two `verdict --json` files is meaningful.
- A reckless finding's `where`, `why`, and `fix` name the exact evidence file
  and the same-runtime config to edit. Fix suggestions are printed, never
  applied — Ariadne only reads.
- Self-declared `.ariadne/*.json` files never improve the verdict; only
  enforced configuration counts. Gate results cannot be gamed by adding
  declarations to the repo.
- On failure, drill down in the job log with `ariadne show reckless:1 --path .`
  and `ariadne ls findings --path .`.

## Scan endpoints fleet-wide (MDM / management agent)

`ariadne self` assesses the local home directory in endpoint mode. For endpoint
collection, emit the same machine verdict locally:

```bash
# Per-endpoint collection command (Jamf policy, Munki script, cron, etc.)
ariadne verdict --json > "/var/tmp/ariadne-$(hostname)-$(date +%Y%m%d).json"
```

When endpoint homes or snapshots are available to a collector host, use the
first-party fleet rollup:

```bash
ariadne scan --targets endpoints.txt --mode endpoint --format jsonl --out ariadne-verdicts.jsonl
ariadne scan --targets endpoints.txt --mode endpoint --format json --out ariadne-fleet.json
```

What to expect per run, verified on developer hardware:

- A ~2,000-config-file home directory completes in well under one second of
  pipeline time (benchmark: ~0.5s); whole-command wall time stays comfortably
  under the 5-second product bar.
- Nothing is executed, no packages are installed, no network calls are made,
  and no secret values are read or emitted. Private histories and caches are
  summarized by metadata only. This is safe to run on developer machines
  without a maintenance window.
- The JSONL output is one complete `ariadne.verdict/v1` object per completed
  target. The scan JSON output adds `fleet.verdict_counts`,
  `fleet.reckless_by_family`, and `fleet.worst_first_targets` for one-screen
  CISO posture.
- The JSON's `verdict` word (`reckless` / `tradeoffs_only` / `hardened` /
  `no_agents_found`), `reckless[]` findings, and `default_judgments[]` (labeled
  default opinions with the fact IDs they weighed) are the fields a downstream
  system should consume. Schema: `ariadne.verdict/v1`
  (`ariadne-prove/schema/ariadne-verdict-v1.schema.json`), frozen; changes are
  additive only.
- Fleet ordering is deterministic: reckless targets first, reckless count
  descending, then target path. Self-declared `.ariadne/*.json` controls remain
  attested-only and never improve fleet hardened or protected counts.
