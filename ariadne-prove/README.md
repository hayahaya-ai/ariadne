# Ariadne

Ariadne is a deterministic exposure analysis tool for local AI agent runtimes and their tool configurations.

It answers a concrete security question:

> Can untrusted instructions plus agent authority create a path to sensitive local boundaries, and do controls break that path?

Ariadne is fact-first. It collects deterministic evidence, builds a graph, and classifies only the exposure paths supported by that graph. It does not execute agents, run MCP servers, install packages, call external services, or read secret values.

## What It Does

- Discovers AI-agent configuration surfaces across repositories and endpoint-style home directories.
- Parses known security-relevant config and instruction files.
- Summarizes private or high-volume agent context without emitting content.
- Builds a graph of trust inputs, runtimes, tools, authorities, controls, and boundaries.
- Reports exposure paths as `exposed`, `protected`, or `inconclusive`.
- Prioritizes graph-backed issues with deterministic rules.
- Supports custom rule policies for organization-specific risky paths.
- Supports optional fact-bound LLM review on top of Ariadne's redacted evidence packet.
- Writes a local HTML dashboard with issues and a facts dive.
- Emits stable JSON for automation, fleet aggregation, and security data pipelines.

## Current Exposure Families

- **Secret boundary access:** untrusted repo or agent instructions can influence a runtime that has file-read authority near secret-like files.
- **Mutable tool launch:** an agent can invoke a tool launched through mutable package-manager or interpreter configuration that grants local execution.
- **Data egress chain:** untrusted influence, private-data reachability, and external communication reachability exist in the same graph.

## Install

Prerequisites:

- Go 1.26 or newer
- macOS or Linux

Build locally:

```bash
make build
./bin/ariadne help
```

Run tests:

```bash
make test
```

## Quick Start

Inspect the current repository:

```bash
./bin/ariadne inventory --path .
./bin/ariadne prove --path .
./bin/ariadne dashboard --path . --out ariadne-dashboard.html
./bin/ariadne prove --path . --llm-request-out llm-request.json
```

Emit JSON:

```bash
./bin/ariadne inventory --path . --format json --out inventory.json
./bin/ariadne prove --path . --format json --out exposure.json
./bin/ariadne scan --targets targets.txt --format json --out scan.json
```

Export the graph for review or visualization:

```bash
./bin/ariadne inventory --path . --format mermaid --out ariadne-graph.mmd
./bin/ariadne prove --path . --format dot --out ariadne-graph.dot
```

Scan multiple local or mounted targets:

```bash
./bin/ariadne scan --targets targets.txt --format json --out scan.json
./bin/ariadne dashboard --targets targets.txt --out fleet-dashboard.html
```

`targets.txt` accepts one target per line:

```text
developer-laptop,/mnt/laptops/alex
build-runner,/mnt/ci/build-runner
repo-only,/srv/repos/example
```

## Commands

| Command | Purpose |
| --- | --- |
| `ariadne inventory --path <dir>` | Collect deterministic facts and graph evidence without exposure classification. |
| `ariadne prove --path <dir>` | Classify supported exposure paths for one target. |
| `ariadne scan --targets <file>` | Run `prove` across many local or mounted targets and aggregate the results. |
| `ariadne dashboard --path <dir>` | Write a local HTML issue dashboard for one target. |
| `ariadne dashboard --targets <file>` | Write a local HTML issue dashboard across many targets. |
| `ariadne stories list` | List validation scenarios. |
| `ariadne prove --story <id>` | Run one validation scenario against its expected oracle. |

Useful flags:

- `--agent all|codex|claude`
- `--mode repo|endpoint`
- `--format table|json|dot|mermaid`
- `--out <file>`
- `--rules <file>`
- `--interpret deterministic|llm`
- `--llm-request-out <file>`
- `--llm-review <file>`
- `--llm-command <command>`
- `--include-sensitive-paths`

Custom deterministic rules can also live at `.ariadne/rules.json`. See [docs/priority-rules.md](docs/priority-rules.md).

## Supported Evidence Surfaces

Current deterministic discovery covers:

- runtime config under `.claude/**` and `.codex/**`
- `CLAUDE.md`, `AGENTS.md`, and nested agent instruction files
- Cursor and Windsurf rule files
- MCP configuration
- plugin/config surfaces
- command files
- project memory
- private context summaries such as paste caches or history directories
- secret-like boundary indicators such as `.env*`, key files, and credential files

Exact vendor names are used only to identify supported adapters and file formats. Public classification is expressed in Ariadne's own exposure taxonomy.

## Output Model

Every run separates facts from classification.

Inventory output includes:

- discovered surfaces
- parsed facts
- modeled authorities, controls, and boundaries
- graph nodes and edges
- redaction metadata
- warnings and limitations
- graph exports with `--format dot` or `--format mermaid`

Prove output adds:

- exposure path ID and title
- status: `exposed`, `protected`, or `inconclusive`
- proof mode: `inferred`, `simulated`, or `live_lab`
- graph path edges
- controls that break the path
- deterministic interpretation with issue priority, severity, disposition, evidence signals, and actions
- optional LLM review interpretation when `--interpret llm` is used
- limitations

Dashboard output adds:

- issue summary
- prioritized issue table
- exposure paths
- facts dive with graph edges and evidence rows
- warnings and limitations

Schema docs live in [docs/json-schema.md](docs/json-schema.md). Machine-readable draft schemas live in [schema/](schema/).

## Validation Scenarios

`testdata/storylab/` contains controlled scenarios that act as the correctness oracle. Ariadne is expected to pass these before broader feature work is accepted.

Current scenario families:

- local agent secret exposure
- protected secret access
- unknown runtime authority
- endpoint broad authority
- mutable tool launch
- data egress chain

Run all scenarios through tests:

```bash
make test
```

Run one scenario:

```bash
./bin/ariadne prove --story data-egress-chain-exposed
```

## Privacy And Safety

Ariadne is local-first and deterministic by default.

- It does not execute agent runtimes.
- It does not execute MCP/tool servers.
- It does not install or resolve packages.
- It does not call network services.
- It does not emit secret values.
- Sensitive exact paths are redacted by default when outside the scanned root.
- Private histories, transcripts, paste caches, and file histories are summarized by metadata only.

See [docs/threat-model.md](docs/threat-model.md) and [docs/deterministic-scan.md](docs/deterministic-scan.md).

## Fleet Usage

For teams, run Ariadne on each endpoint or against mounted endpoint snapshots and collect JSON centrally:

```bash
ariadne scan --targets endpoints.txt --format json --out ariadne-scan.json
```

See [docs/fleet.md](docs/fleet.md).

## Project Status

This repository currently focuses on deterministic evidence, graph-backed exposure, deterministic priority interpretation, and optional fact-bound LLM review. The deterministic layer remains useful on its own and is the evidence source for LLM review.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports should follow [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
