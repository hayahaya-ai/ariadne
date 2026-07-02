# Ariadne

Ariadne is a deterministic exposure analysis tool for local AI agent runtimes and their tool configurations.

It answers a concrete security question:

> Can untrusted instructions plus agent authority create a path to sensitive local boundaries, and do controls break that path?

Ariadne is fact-first. It collects deterministic evidence, builds a graph, and classifies only the exposure paths supported by that graph. It does not execute agents, run MCP servers, install packages, call external services, or read secret values.

The active implementation is in [`ariadne-prove/`](ariadne-prove/).

## Quick Start

```bash
make build
make verify-first-run
./bin/ariadne self
./bin/ariadne self --bundle-dir /tmp/ariadne-self
./bin/ariadne self --format html --out /tmp/ariadne-self.html
./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk
./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk --format operator
./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk --format html --out /tmp/ariadne-assess.html
```

The first command builds the CLI. The second command runs the product verification loop against known fixtures. `ariadne self` is the local developer-machine assessment: it inspects the current `HOME` in endpoint mode and returns the first operator action. Add `--bundle-dir` when you want a durable first-run folder containing `assessment.txt`, `operator-packet.txt`, `operator-packet.json`, `dashboard.html`, `inventory.json`, `cases.json`, `proof-action.txt`, `proof-plan.json`, `README.md`, and `manifest.json` with byte size and SHA-256 metadata for generated payload files. `operator-packet.txt` is the small ticket-style handoff: start case, source refs, graph path, missing controls, proof artifacts, commands, and done criteria. `operator-packet.json` is the same compact packet with run metadata for ticketing and workflow automation. The HTML dashboard includes a Source Reference Workbench near the top: exact files, line numbers, facts, copyable paths, and inspect commands; assessment JSON exposes the same rows under `source_reference_workbench`. Private/history/cache surfaces use metadata-safe commands instead of content reads. `ariadne assess --path ...` is the repo or mounted-path assessment. Both tell you what Ariadne inspected, what facts it collected, which operator case is first, what evidence supports it, what is normal agent capability, what is real risk, what hard barrier is missing, and how to prove the fix worked. Use `--format operator` or `--format operator-json` when you want the same handoff outside a bundle. The `Signal quality` section is the signal/noise boundary: capability alone is not exposure; Ariadne marks action only when graph evidence connects influence, authority, boundary reachability, and missing hard-barrier evidence. The `Lethal trifecta` section names the data-egress chain: untrusted content, private-data access, and external communication in the same supported agent graph. Use `--format table` when you want the full terminal audit trail.

## First-Run Triage Loop

Ariadne is meant to be used as an operator workflow, not just a scanner.

```bash
# 1. Get the first action.
./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk

# 2. Focus the prioritized case.
./bin/ariadne cases --path ariadne-prove/testdata/realpath/combined-risk --case case:egress-output-boundary

# 3. Save the baseline proof state.
./bin/ariadne proofs --path ariadne-prove/testdata/realpath/combined-risk --case case:egress-output-boundary --format json --out before-proof.json

# 4. See the proof evidence Ariadne expects.
./bin/ariadne proofs --path ariadne-prove/testdata/realpath/combined-risk --case case:egress-output-boundary

# 5. Export suggested proof files for review.
./bin/ariadne proofs --path ariadne-prove/testdata/realpath/combined-risk --case case:egress-output-boundary --patch-dir proof-patches

# 6. Rerun after applying real control evidence.
./bin/ariadne proofs --path ariadne-prove/testdata/realpath/combined-risk --case case:egress-output-boundary --format json --out after-proof.json

# 7. Compare before and after.
./bin/ariadne compare --before before-proof.json --after after-proof.json
```

On the `combined-risk` fixture, the first action currently starts with `case:egress-output-boundary` because Ariadne connected these facts:

- repo instructions can influence local agent runtimes
- Claude/Codex configuration grants broad or file-read authority
- a secret-like boundary exists
- external communication or tool-mediated egress is reachable
- no hard egress or output barrier is proven

The HTML version includes clickable local evidence links and copy-path buttons:

```bash
./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk --format html --out /tmp/ariadne-assess.html
```

## Endpoint Mode

Use endpoint mode when the target looks like a developer home directory or mounted endpoint snapshot:

```bash
./bin/ariadne self
./bin/ariadne self --bundle-dir ariadne-self
./bin/ariadne self --format html --out /tmp/ariadne-self.html
./bin/ariadne assess --path ariadne-prove/testdata/realpath/messy-ai-surfaces --mode endpoint --format action
./bin/ariadne inventory --path ariadne-prove/testdata/realpath/messy-ai-surfaces --mode endpoint --format json
```

Endpoint mode discovers local AI surfaces such as Claude, Codex, GitHub Copilot in VS Code, Cursor, Windsurf, Continue, Aider, Gemini CLI, OpenCode, Cline, Roo Code, MCP, and Ariadne proof policy files. Repo assessment also discovers managed-agent workflow surfaces such as GitHub Actions. It parses known security-relevant files, summarizes private context surfaces, models authorities and boundaries, and then ranks operator cases. For managed workflows, Ariadne separates the trigger, workflow tool invocation, repository-write permission, OIDC/cloud identity permission, CI secret reference, external communication, and approval gate as separate facts. The self-assessment bundle is the recommended handoff artifact when you need to inspect results later, attach evidence to a ticket, or share the readout with another operator.

## Fact Contract

Ariadne separates facts from interpretation:

- **Observed fact:** a file, config, instruction, cache, MCP, tool, authority, control, or boundary was discovered.
- **Declared fact:** a config or policy says a control exists.
- **Inferred fact:** Ariadne can model authority or reachability from deterministic evidence.
- **Classification:** Ariadne connects facts into a graph path and labels the path `exposed`, `protected`, or `inconclusive`.
- **Operator case:** Ariadne ranks missing hard barriers that would break a supported path.

If Ariadne cannot cite facts, evidence references, graph edges, controls, and limitations, it should not present a conclusion as more than unknown or inconclusive.

## What It Does

- Discovers AI-agent configuration surfaces across repositories and endpoint-style home directories.
- Parses known security-relevant config and instruction files.
- Summarizes private or high-volume agent context without emitting content, including count-only credential-like filename indicators.
- Builds a graph of trust inputs, runtimes, tools, authorities, controls, and boundaries.
- Models managed workflow agent paths such as pull-request-triggered AI reviews with repository token, OIDC, CI secret, and egress facts.
- Exports graph evidence as JSON, Graphviz DOT, or Mermaid for review and visualization.
- Reports exposure paths as `exposed`, `protected`, or `inconclusive`.
- Maps exposure evidence to Zero Trust agent architecture boundaries as `breaking`, `controlled`, `unknown`, or `not_observed`.
- Aggregates Zero Trust boundary coverage across target lists, including evidence anchors, missing evidence, next collectors, and the control evidence needed to close gaps.
- Prioritizes graph-backed issues with deterministic rules.
- Supports custom rule policies for organization-specific risky paths.
- Detects declared Zero Trust agent controls such as approval, sandbox, output filtering, continuous authorization, resource limits, credential-helper, request-to-action traceability, retention, memory integrity, provenance, and credential-isolation posture.
- Detects AI supply-chain evidence such as AI-BOM or ML-BOM surfaces, model provenance, dependency health, provider review, signing, and runtime validation declarations.
- Flags inline credential field indicators in agent configuration without emitting values.
- Creates fact-bound review packets for optional human or LLM review, including follow-up packets over Ariadne exposure IDs and inventory-blind packets for lower-bias hypothesis review.
- Writes local HTML operator dashboards with first action, evidence links, proof bundles, case boards, and Zero Trust boundary coverage views.
- Emits JSON for automation, fleet aggregation, and security data pipelines.

## Exposure Families

- **Secret boundary access:** untrusted repo or agent instructions can influence a runtime that has file-read authority near secret-like files.
- **Mutable tool launch:** an agent can invoke a tool launched through mutable package-manager or interpreter configuration that grants local execution.
- **Data egress chain:** untrusted influence, private-data reachability, and external communication reachability exist in the same graph.

## Zero Trust Architecture

Ariadne reports where agent architecture is breaking across influence, authority, sensitive data, external egress, output controls, tool/MCP, AI supply chain, memory/context, identity, workload authorization, continuous authorization, human approval, resource exhaustion, observability, response, governance, configuration integrity, and control-strength boundaries.

The product readout starts with `zero_trust.architecture_flaws`: user-centered architecture flaw categories such as untrusted instructions steering privileged tools, weak agent identity, arbitrary external egress, missing observability, and unsafe persistent memory. Each flaw cites the underlying check IDs, evidence sources, graph edges, observed controls, control evidence needed to break the flaw, evidence surfaces Ariadne can collect, and next actions.

The model is fact-first: `breaking` requires graph evidence, `controlled` requires a control edge, and unsupported identity or observability claims remain `unknown`. For influence, risky untrusted instructions reaching high-risk authority are `breaking` even when a specific data boundary is not yet proven. For egress, risky agent influence or authority reaching arbitrary external communication is `breaking` without hard destination or network-scope controls. For identity, high-risk inherited local authority without strong scoped agent identity is `breaking`; helper-only evidence is partial. For workload authorization, sandboxing is containment, not authorization. For observability, audit logs alone are partial; the stronger boundary needs action logging plus request or trace propagation.

See [Zero Trust agent architecture](ariadne-prove/docs/zero-trust-agent-architecture.md).

## Commands

From the repository root:

```bash
make test
make build
make verify-first-run
./bin/ariadne help
./bin/ariadne self
./bin/ariadne self --bundle-dir ariadne-self
./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk
make scan
```

From `ariadne-prove/`:

```bash
./bin/ariadne self
./bin/ariadne self --bundle-dir ariadne-self
./bin/ariadne self --format html --out ariadne-self.html
./bin/ariadne architecture --path .
./bin/ariadne architecture --targets targets.txt
./bin/ariadne architecture --path . --mode endpoint --include-sensitive-paths
./bin/ariadne architecture --path . --status all --format json
./bin/ariadne inventory --path .
./bin/ariadne prove --path .
./bin/ariadne scan --targets targets.txt --format json --out scan.json
./bin/ariadne dashboard --path . --out ariadne-dashboard.html
./bin/ariadne dashboard --path . --view exposure --out exposure-dashboard.html
./bin/ariadne dashboard --targets targets.txt --out fleet-dashboard.html
./bin/ariadne prove --path . --rules .ariadne/rules.json
./bin/ariadne review-packet --path . --profile follow-up --packet-out llm-request.json
./bin/ariadne review-check --packet llm-request.json --review llm-review.json
./bin/ariadne review-run --path . --command ./security-reviewer --dir ariadne-review
./bin/ariadne review-packet --path . --profile inventory-blind --format json --out llm-request.json
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
