# Fleet Usage

Ariadne can run across a collection of local or mounted targets using `scan`.

## Target File

Create a target file with one target per line:

```text
developer-laptop,/mnt/endpoints/developer-laptop
build-runner,/mnt/endpoints/build-runner
repo-only,/srv/repos/example
```

Relative paths are resolved relative to the target file.

## Run

```bash
ariadne scan --targets endpoints.txt
ariadne scan --targets endpoints.txt --format jsonl --out ariadne-verdicts.jsonl
ariadne scan --targets endpoints.txt --format json --out ariadne-scan.json
ariadne architecture --targets endpoints.txt --format json --out ariadne-architecture.json
ariadne architecture --targets endpoints.txt --format html --out ariadne-fleet-architecture.html
ariadne dashboard --targets endpoints.txt --out ariadne-fleet-dashboard.html
```

`scan --targets` is the CISO fleet verdict surface:

- Default/table output is the fleet summary: verdict-word counts, reckless
  findings grouped by exposure family, and a worst-first target list.
- `--format jsonl` emits one complete `ariadne.verdict/v2` object per completed
  target, one line per target, for SIEM ingestion.
- `--format json` emits `ariadne-scan-v1`: the same `fleet` rollup plus
  `targets[].verdict`. Consolidation: scan JSON no longer publishes the
  redundant embedded `targets[].report` payload; the per-endpoint machine object
  is the reused verdict/v2 schema.

Rollup ordering is deterministic: family keys and affected target paths are
sorted, and worst-first targets are ordered by verdict severity (`reckless`,
`inconclusive`, `tradeoffs_only`, `hardened`, `no_agents_found`), reckless count
descending, then target path.

Fleet rollups count only enforced evidence already represented in the endpoint
verdict. Self-declared `.ariadne/*.json` controls are attested-only: they can be
listed on a reckless finding as `attested_only`, but they never add hardened
counts or protect a target in the fleet summary.
An endpoint with a runtime but zero enforced `hardened[]` entries rolls up as
`inconclusive`; it cannot increment either the hardened verdict count or the
fleet hardened-control count.

Use `architecture --targets` or the focused fleet architecture dashboard when the question is not just "which targets have exposure paths?" but "which Zero Trust agent architecture boundaries are breaking, controlled, unknown, or not observed across the fleet?" The architecture fleet report groups flaw categories by target coverage, emits `boundary_coverage` rows with evidence sources, missing evidence, next collectors, and control evidence needed, includes `evidence_plan` for unknown or not-observed collector gaps, includes `closure_families` for capability-level triage, and includes a `closure_plan` that ranks missing hard barriers across affected targets.

## Collection Pattern

For endpoint fleets:

1. Run Ariadne locally on each machine, or mount endpoint snapshots to a collector host.
2. Store `scan --format jsonl` verdict lines in a central bucket, data lake, or SIEM.
3. Index each verdict's `target`, `verdict`, `reckless[]`, `tradeoffs[]`, `hardened[]`, and `default_judgments[]`; or index `scan --format json` fields `fleet`, `summary`, and `targets[].verdict`.
4. Alert on `verdict=reckless` and route by `reckless[].exposure_id`; route
   `verdict=inconclusive` to evidence repair rather than treating it as healthy.
5. Track Zero Trust closure by querying `evidence_plan[]`, `closure_families[]`, `closure_plan[]`, `boundary_coverage[].missing_evidence`, `boundary_coverage[].next_collectors`, and `boundary_coverage[].control_evidence_needed`.

## Privacy Guidance

- Keep default redaction enabled.
- Do not use `--include-sensitive-paths` unless the output destination is approved for sensitive metadata.
- Treat scan JSON as security telemetry.
- Do not collect raw agent histories or paste caches; Ariadne summarizes those surfaces by default.

## MDM/IT Rollout

Ariadne is a single local binary. IT teams can distribute it with existing endpoint tooling and run scheduled commands such as:

```bash
ariadne inventory --path "$HOME" --mode endpoint --format json --out /var/tmp/ariadne-inventory.json
ariadne prove --path "$HOME" --mode endpoint --format json --out /var/tmp/ariadne-exposure.json
ariadne verdict --path "$HOME" --mode endpoint --json --out /var/tmp/ariadne-verdict.json
```

Use OS-native controls to collect JSONL verdicts or mount endpoint snapshots and
run `ariadne scan --targets endpoints.txt --mode endpoint --format jsonl` from a
collector host.
