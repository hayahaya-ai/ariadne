# Ariadne

Ariadne is a deterministic exposure analysis tool for local AI agent runtimes and their tool configurations.

It answers a concrete security question:

> Can untrusted instructions plus agent authority create a path to sensitive local boundaries, and do controls break that path?

Ariadne is fact-first. It collects deterministic evidence, builds a graph, and classifies only the exposure paths supported by that graph. It does not execute agents, run MCP servers, install packages, call external services, or read secret values.

The active implementation is in [`ariadne-prove/`](ariadne-prove/).

## Quick Start

```bash
make build
./ariadne-prove/bin/ariadne inventory --path ariadne-prove/testdata/realpath/messy-ai-surfaces
./ariadne-prove/bin/ariadne prove --path ariadne-prove/testdata/realpath/combined-risk
./ariadne-prove/bin/ariadne scan --targets ariadne-prove/testdata/realpath/targets.txt
./ariadne-prove/bin/ariadne dashboard --path ariadne-prove/testdata/realpath/combined-risk --out ariadne-dashboard.html
./ariadne-prove/bin/ariadne prove --path ariadne-prove/testdata/realpath/combined-risk --format mermaid --out ariadne-graph.mmd
```

## What It Does

- Discovers AI-agent configuration surfaces across repositories and endpoint-style home directories.
- Parses known security-relevant config and instruction files.
- Summarizes private or high-volume agent context without emitting content, including count-only credential-like filename indicators.
- Builds a graph of trust inputs, runtimes, tools, authorities, controls, and boundaries.
- Exports graph evidence as JSON, Graphviz DOT, or Mermaid for review and visualization.
- Reports exposure paths as `exposed`, `protected`, or `inconclusive`.
- Maps exposure evidence to Zero Trust agent architecture boundaries as `breaking`, `controlled`, `unknown`, or `not_observed`.
- Prioritizes graph-backed issues with deterministic rules.
- Supports custom rule policies for organization-specific risky paths.
- Detects declared Zero Trust agent controls such as approval, sandbox, output filtering, continuous authorization, resource limits, credential-helper, audit, retention, memory integrity, provenance, and credential-isolation posture.
- Detects AI supply-chain evidence such as AI-BOM or ML-BOM surfaces, model provenance, dependency health, provider review, signing, and runtime validation declarations.
- Flags inline credential field indicators in agent configuration without emitting values.
- Supports optional fact-bound LLM review on top of Ariadne's redacted evidence packet.
- Writes local HTML dashboards with issue and facts-dive views.
- Emits JSON for automation, fleet aggregation, and security data pipelines.

## Exposure Families

- **Secret boundary access:** untrusted repo or agent instructions can influence a runtime that has file-read authority near secret-like files.
- **Mutable tool launch:** an agent can invoke a tool launched through mutable package-manager or interpreter configuration that grants local execution.
- **Data egress chain:** untrusted influence, private-data reachability, and external communication reachability exist in the same graph.

## Zero Trust Architecture

Ariadne reports where agent architecture is breaking across influence, authority, sensitive data, external egress, output controls, tool/MCP, AI supply chain, memory/context, identity, workload authorization, continuous authorization, human approval, resource exhaustion, observability, response, governance, configuration integrity, and control-strength boundaries.

The model is fact-first: `breaking` requires graph evidence, `controlled` requires a control edge, and unsupported identity or audit claims remain `unknown`.

See [Zero Trust agent architecture](ariadne-prove/docs/zero-trust-agent-architecture.md).

## Commands

From the repository root:

```bash
make test
make build
make scan
```

From `ariadne-prove/`:

```bash
./bin/ariadne inventory --path .
./bin/ariadne prove --path .
./bin/ariadne scan --targets targets.txt --format json --out scan.json
./bin/ariadne dashboard --path . --out ariadne-dashboard.html
./bin/ariadne prove --path . --rules .ariadne/rules.json
./bin/ariadne prove --path . --llm-request-out llm-request.json
./bin/ariadne prove --path . --interpret llm --llm-review llm-review.json
./bin/ariadne stories list
./bin/ariadne prove --story data-egress-chain-exposed
```

## Documentation

- [Install](ariadne-prove/INSTALL.md)
- [Deterministic scan model](ariadne-prove/docs/deterministic-scan.md)
- [Zero Trust agent architecture](ariadne-prove/docs/zero-trust-agent-architecture.md)
- [Priority rules](ariadne-prove/docs/priority-rules.md)
- [Threat model](ariadne-prove/docs/threat-model.md)
- [Fleet usage](ariadne-prove/docs/fleet.md)
- [JSON and graph contract](ariadne-prove/docs/json-schema.md)
- [Contributing](ariadne-prove/CONTRIBUTING.md)
- [Security policy](ariadne-prove/SECURITY.md)

## Privacy And Safety

Ariadne is local-first and deterministic by default.

- It does not execute agent runtimes.
- It does not execute MCP/tool servers.
- It does not install or resolve packages.
- It does not call network services.
- It does not emit secret values.
- Private histories, transcripts, paste caches, and file histories are summarized by metadata only.

## License

Apache License 2.0. See [LICENSE](LICENSE).
