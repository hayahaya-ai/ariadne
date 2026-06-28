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
```

## Collection Pattern

For endpoint fleets:

1. Run Ariadne locally on each machine, or mount endpoint snapshots to a collector host.
2. Store JSON output in a central bucket or data lake.
3. Index `summary`, `targets[].report.exposures`, `targets[].report.graph`, and `targets[].report.evidence`.
4. Alert on `status=exposed` for supported exposure families.

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
