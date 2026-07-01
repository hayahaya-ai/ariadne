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
ariadne scan --targets endpoints.txt --format json --out ariadne-scan.json
ariadne architecture --targets endpoints.txt --format json --out ariadne-architecture.json
ariadne architecture --targets endpoints.txt --format html --out ariadne-fleet-architecture.html
ariadne dashboard --targets endpoints.txt --out ariadne-fleet-dashboard.html
```

Use `architecture --targets` or the focused fleet architecture dashboard when the question is not just "which targets have exposure paths?" but "which Zero Trust agent architecture boundaries are breaking, controlled, unknown, or not observed across the fleet?" The architecture fleet report groups flaw categories by target coverage, emits `boundary_coverage` rows with evidence sources, missing evidence, next collectors, and control evidence needed, includes `evidence_plan` for unknown or not-observed collector gaps, includes `closure_families` for capability-level triage, and includes a `closure_plan` that ranks missing hard barriers across affected targets.

## Collection Pattern

For endpoint fleets:

1. Run Ariadne locally on each machine, or mount endpoint snapshots to a collector host.
2. Store JSON output in a central bucket or data lake.
3. Index `summary`, `targets[].report.exposures`, `targets[].report.graph`, `targets[].report.evidence`, `groups`, and `boundary_coverage`.
4. Alert on `status=exposed` for supported exposure families.
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
```

Use OS-native controls to collect the JSON artifacts.
