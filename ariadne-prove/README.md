# Ariadne

Ariadne is a deterministic exposure analysis tool for local AI agent runtimes and their tool configurations.

It answers a concrete security question:

> Can untrusted instructions plus agent authority create a path to sensitive local boundaries, and do controls break that path?

Ariadne is fact-first. It collects deterministic evidence, builds a graph, and classifies only the exposure paths supported by that graph. It does not execute agents, run MCP servers, install packages, call external services, or read secret values.

## What It Does

- Discovers AI-agent configuration surfaces across repositories and endpoint-style home directories.
- Parses known security-relevant config and instruction files.
- Summarizes private or high-volume agent context without emitting content.
- Samples structured transcript/log metadata for audit event shape without emitting prompts, tool inputs, or outputs.
- Builds a graph of trust inputs, runtimes, tools, authorities, controls, and boundaries.
- Reports exposure paths as `exposed`, `protected`, or `inconclusive`.
- Maps those paths to Zero Trust agent architecture boundaries as `breaking`, `controlled`, `unknown`, or `not_observed`.
- Shows whether observed controls are hard barriers, missing hard barriers, partial/friction controls, or evidence gaps.
- Scores Foundation Zero Trust agent requirements from observed and declared evidence.
- Emits focused architecture JSON for single targets and fleets, including framework coverage, boundary coverage, evidence anchors, evidence plans, missing evidence, next collectors, closure families, and a ranked closure plan for missing hard barriers.
- Prioritizes graph-backed issues with deterministic rules.
- Supports custom rule policies for organization-specific risky paths.
- Supports optional fact-bound LLM review on top of Ariadne's redacted evidence packet.
- Writes a local HTML operator dashboard with first action, evidence links, proof bundles, case boards, and Zero Trust boundary coverage views.
- Emits stable JSON for automation, fleet aggregation, and security data pipelines.

## Current Exposure Families

- **Secret boundary access:** untrusted repo or agent instructions can influence a runtime that has file-read authority near secret-like files.
- **Mutable tool launch:** an agent can invoke a tool launched through mutable package-manager or interpreter configuration that grants local execution.
- **Data egress chain:** untrusted influence, private-data reachability, and external communication reachability exist in the same graph unless hard egress controls break the external path.

## Zero Trust Architecture Readout

Ariadne emits a `zero_trust` object in `prove` JSON and renders the same model in the dashboard.

Current checks cover:

- influence boundary
- authority boundary
- sensitive data boundary
- external egress boundary
- tool and MCP boundary
- tool integrity boundary
- agent delegation boundary
- memory and context boundary
- agent identity boundary
- workload authorization boundary
- observability boundary
- response and containment boundary
- deployment governance boundary
- configuration integrity boundary
- control strength: impossible versus tedious

The same `zero_trust` object also includes a Foundation maturity evidence readout. It maps the raised Foundation bar from Zero Trust agent architecture guidance into deterministic requirements:

- per-agent, hardware-bound, or cryptographically rooted identity evidence
- short-lived, JIT, or token-limited identity-provider-issued credentials
- deny-by-default least-agency permissions
- tool allowlisting, provenance, and invocation validation
- identity-based workload isolation with ABAC, named callers, segmentation, or tool scope
- comprehensive action logs with request context
- input isolation, trusted-source gating, and validation for untrusted agent context
- approval escalation with audit evidence
- context retention controls
- automated first-pass investigation and containment for agent alerts
- registered, owned, approved, risk-assessed, and reviewed agent deployments

Each requirement reports a status, control quality such as `hard_barrier`, `friction_only`, or `evidence_gap`, evidence references, missing evidence, and next actions.

Statuses are evidence-bound:

- `breaking`: graph evidence shows an unbroken exposure path or missing break-path control.
- `controlled`: graph evidence shows a control edge that breaks a supported path.
- `unknown`: relevant surfaces exist, but Ariadne lacks enough evidence to prove or clear the boundary.
- `not_observed`: supported collectors did not observe that boundary.

See [docs/zero-trust-agent-architecture.md](docs/zero-trust-agent-architecture.md).

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
./bin/ariadne self
./bin/ariadne self --bundle-dir ariadne-self
./bin/ariadne self --format html --out ariadne-self.html
./bin/ariadne assess --path .
./bin/ariadne assess --path . --format runbook
./bin/ariadne assess --path . --format html --out ariadne-assessment.html
./bin/ariadne inventory --path .
./bin/ariadne inventory --path . --format html --out inventory-dashboard.html
./bin/ariadne prove --path .
./bin/ariadne architecture --path . --format html --out architecture-dashboard.html
./bin/ariadne cases --path .
./bin/ariadne cases --path . --case case:input-trust-boundary
./bin/ariadne cases --path . --format html --out cases-dashboard.html
./bin/ariadne closure --path . --dir ariadne-closure
./bin/ariadne controls --path .
./bin/ariadne controls --path . --format html --out controls-dashboard.html
./bin/ariadne dashboard --path . --out ariadne-dashboard.html
./bin/ariadne dashboard --path . --view exposure --out exposure-dashboard.html
./bin/ariadne review-packet --path . --profile follow-up --packet-out llm-request.json
./bin/ariadne review-check --packet llm-request.json --review llm-review.json
./bin/ariadne review-run --path . --command ./security-reviewer --dir ariadne-review
./bin/ariadne review-packet --path . --profile inventory-blind --format json --out llm-request.json
```

Emit JSON:

```bash
./bin/ariadne assess --path . --format json --out assessment.json
./bin/ariadne inventory --path . --format json --out inventory.json
./bin/ariadne prove --path . --format json --out exposure.json
./bin/ariadne cases --path . --format json --out cases.json
./bin/ariadne controls --path . --format json --out controls.json
./bin/ariadne scan --targets targets.txt --format json --out scan.json
```

Run the focused proof loop for one case:

```bash
./bin/ariadne closure --path . --case case:input-trust-boundary --dir ariadne-closure

# Or run the lower-level commands directly:
./bin/ariadne proofs --path . --case case:input-trust-boundary --format json --out before-proof.json
./bin/ariadne proofs --path . --case case:input-trust-boundary --patch-dir proof-patches
# Review the suggested files under proof-patches/surfaces/, add or verify real control evidence, then rerun:
./bin/ariadne proofs --path . --case case:input-trust-boundary --format json --out after-proof.json
./bin/ariadne compare --before before-proof.json --after after-proof.json --format receipt --out closure-receipt.txt
./bin/ariadne compare --before before-proof.json --after after-proof.json --format html --out case-compare.html
```

Export the graph for review or visualization:

```bash
./bin/ariadne inventory --path . --format mermaid --out ariadne-graph.mmd
./bin/ariadne prove --path . --format dot --out ariadne-graph.dot
```

Scan multiple local or mounted targets:

```bash
./bin/ariadne assess --targets targets.txt --format html --out fleet-assessment.html
./bin/ariadne scan --targets targets.txt --format json --out scan.json
./bin/ariadne architecture --targets targets.txt --format html --out fleet-architecture.html
./bin/ariadne cases --targets targets.txt --format html --out fleet-cases.html
./bin/ariadne dashboard --targets targets.txt --out fleet-dashboard.html
```

`targets.txt` accepts one target per line:

```text
developer-laptop,/mnt/laptops/alex
build-runner,/mnt/ci/build-runner
repo-only,/srv/repos/example
```

For endpoint scans, a target path can be a mounted home snapshot such as `/mnt/laptops/alex` containing `.claude`, `.codex`, `.cursor`, `.continue`, `.gemini`, `.aider.conf.yml`, or similar home-level AI surfaces. If the supplied endpoint path does not look like a mounted endpoint home, Ariadne falls back to the current machine's `HOME` so `--mode endpoint` still works for local self-assessment.

Fleet JSON and next-step readouts preserve the concrete `targets_file` path when `--targets` is used, so follow-up `assess`, `cases`, `proofs`, `controls`, and `architecture` commands can be rerun directly.

## Commands

| Command | Purpose |
| --- | --- |
| `ariadne self` | Primary local developer-machine readout. Inspects the current `HOME` in endpoint mode and shows the first operator action. Use `--bundle-dir ariadne-self` to save the durable first-run folder with summary, `runbook.txt`, `runbook.json`, `operator-packet.txt`, `operator-packet.json`, dashboard, inventory, LLM follow-up and inventory-blind review packets, cases, proof action, proof plan, README, and manifest with byte size and SHA-256 metadata for generated payload files. The follow-up packet can be reviewed and then validated with `ariadne review-check`; the inventory-blind packet is request-only until hypotheses are mapped back to deterministic facts, source refs, and graph edges. The bundle dashboard includes an Optional Reviewer Handoff with packet links, validation commands, ingestion guardrails, and done criteria. Use `--format html --out ariadne-self.html` for only the local dashboard; the dashboard includes an Operator Runbook plus a Source Reference Workbench with exact files, lines, facts, copyable paths, and metadata-safe commands for private/history/cache surfaces. |
| `ariadne assess --path <dir>` | Primary first-run readout: inspected surfaces, exposure posture, Zero Trust architecture breaks, top operator cases, evidence refs, and next commands. Use `--format runbook` for the action-first operator runbook, `--format runbook-json` for the same runbook with run metadata, `--format operator` for the compact ticket-style handoff, `--format operator-json` for the same packet with run metadata, `--format action` for the fuller current-action workflow, and `--format table` for the full terminal audit trail. |
| `ariadne assess --targets <file>` | Fleet first-run readout across local or mounted targets, with recurring break paths grouped into operator cases. |
| `ariadne inventory --path <dir>` | Collect deterministic facts and graph evidence without exposure classification. |
| `ariadne review-packet --path <dir>` | Create a redacted, fact-bound packet for human or LLM review. Use `--profile follow-up --packet-out llm-request.json` for ingestible review over Ariadne exposure IDs, or `--profile inventory-blind --format json --out llm-request.json` for lower-bias hypothesis and collector-gap review. |
| `ariadne review-check --packet <json> --review <json>` | Validate a reviewer response against the exact follow-up packet Ariadne generated before treating it as accepted interpretation. |
| `ariadne review-run --path <dir> --command <reviewer>` | Run a local reviewer command end to end: generate the follow-up packet, send it on stdin, save reviewer JSON, validate it, and write durable review artifacts. |
| `ariadne prove --path <dir>` | Classify supported exposure paths for one target. |
| `ariadne architecture --path <dir>` | Show focused Zero Trust architecture flaws for one target and the case-board commands to investigate them. |
| `ariadne architecture --targets <file>` | Group Zero Trust architecture flaws across many targets and route recurring break paths to fleet cases. |
| `ariadne cases --path <dir>` | Show the operator case board for architecture break paths and what proof closes them. Use `--case <case-id>` to focus one case. |
| `ariadne cases --targets <file>` | Group operator cases across many targets. |
| `ariadne closure --path <dir>` | Create a local before/change/after/compare closure workspace for the top ranked case or `--case <case-id>`. The workspace includes `runbook.txt`, `before-proof.json`, `proof-action.txt`, `proof-plan.html`, `proof-patches/`, README, manifest, and after/receipt/compare commands. |
| `ariadne proofs --path <dir> --case <case-id>` | Show the focused proof patches, evidence refs, rerun commands, compare-loop commands, and success criteria for one closure case. Use `--patch-dir <dir>` to export suggested proof evidence files plus a manifest. |
| `ariadne compare --before <json> --after <json>` | Compare two Ariadne proof, case, or assessment JSON reports and show case state changes across reruns. Use `--format receipt` for a pasteable closure receipt with before/after artifact hashes. |
| `ariadne controls --path <dir>` | Show missing hard-barrier controls, proof surfaces, and the flaws they close. Use `--format html` for the focused operator dashboard. |
| `ariadne controls --targets <file>` | Group missing hard-barrier controls across many targets. |
| `ariadne scan --targets <file>` | Run `prove` across many local or mounted targets and aggregate the results. |
| `ariadne dashboard --path <dir>` | Write the primary local HTML operator dashboard for one target. Use `--view exposure` for the lower-level exposure/facts view. |
| `ariadne dashboard --targets <file>` | Write the primary local HTML fleet operator dashboard across many targets. Use `--view exposure` for the lower-level fleet exposure view. |
| `ariadne stories list` | List validation scenarios. |
| `ariadne prove --story <id>` | Run one validation scenario against its expected oracle. |

Useful flags:

- `--agent all|claude|codex|cursor|windsurf|continue|aider|gemini|opencode|github-actions|gitlab-ci`
- `--mode repo|endpoint`
- `--format table|json|dot|mermaid`
- `--out <file>`
- `--rules <file>`
- `--interpret deterministic|llm`
- `--llm-request-out <file>`
- `--llm-review-profile follow-up|inventory-blind`
- `--llm-review <file>`
- `--llm-command <command>`
- `--include-sensitive-paths`

Custom deterministic rules can also live at `.ariadne/rules.json`. See [docs/priority-rules.md](docs/priority-rules.md).

## Supported Evidence Surfaces

Current deterministic discovery covers:

- runtime config under `.claude/**`, `.codex/**`, `.cursor/**`, `.windsurf/**`, `.continue/**`, `.gemini/**`, `.opencode/**`, `.vscode/**`, and supported Aider config files
- `CLAUDE.md`, `AGENTS.md`, and nested agent instruction files
- Cursor, Windsurf, Continue, Gemini, GitHub Copilot, Cline, and Roo instruction or rule files
- GitHub Actions workflows under `.github/workflows/*.yml` and `.github/workflows/*.yaml` plus GitLab CI pipelines under `.gitlab-ci.yml`, `.gitlab-ci.yaml`, and `.gitlab/ci/*.yml|*.yaml` as managed/CI agent execution surfaces
- managed workflow facts for trigger trust, agent-like workflow steps, repository-write token authority, OIDC/cloud identity token authority, CI secret references, external communication, and approval gates
- MCP configuration, including VS Code `.vscode/mcp.json`, Cline `.cline/mcp.json`, and Roo `.roo/mcp.json`
- plugin, skill, extension, and config surfaces
- command files and command-like workflow surfaces
- Claude subagent definitions under `.claude/agents/*.md`
- project memory
- private context summaries such as paste caches, chat histories, session directories, file histories, indexes, and agent cache directories
- bounded endpoint discovery for known AI-agent home roots and exact home-level config files, without walking the whole home directory
- secret-like boundary indicators such as `.env*`, key files, and credential files
- `.ariadne/agent-policy.json` declarations for approval, sandbox, credential, audit, and retention controls
- `.ariadne/agent-policy.json` declarations for cryptographic identity, least agency, identity-based isolation, traceability, input validation, and automated triage controls
- `.ariadne/tool-policy.json` declarations for approved tools, MCP review and pinning, descriptor integrity, argument validation, tool authentication, signed artifacts, deployment verification, sandboxed tool execution, and circuit breakers
- `.ariadne/delegation-policy.json` declarations for delegation scope, delegate allowlists, agent-to-agent authorization, original-intent verification, delegated credential scoping, subagent context isolation, and delegation audit controls
- `.ariadne/input-policy.json` declarations for input isolation, trusted instruction sources, instruction provenance, untrusted-content delimiting, and prompt-injection filtering
- `.ariadne/identity-policy.json` declarations for credential isolation, credential helpers, JIT access, token lifetime, hardware-bound credentials, and identity lifecycle controls
- `.ariadne/workload-policy.json` declarations for ABAC, named callers, network segmentation, and tool-scope controls
- `.ariadne/egress-policy.json` declarations for destination allowlists, webhook allowlists, per-tool network scope, output filtering, and egress audit controls
- `.ariadne/memory-policy.json` declarations for context retention, memory isolation, integrity validation, and provenance metadata
- `.ariadne/integrity-policy.json` declarations for reviewed config, signed config, managed settings enforcement, immutable runtime, and rollback controls
- `.ariadne/observability-policy.json` declarations for audit, trace, telemetry export, and immutable log controls
- `.ariadne/response-policy.json` declarations for behavioral monitoring, automated triage, session termination, credential revocation, quarantine, dynamic access reduction, and response escalation controls
- `.ariadne/governance-policy.json` declarations for agent inventory, accountable owner, deployment approval, risk assessment, governance review, and Shadow AI discovery controls
- OpenTelemetry collector config such as `.ariadne/otel-collector.yaml`
- scoped runtime permission evidence such as deny-by-default mode, scoped Claude `Read(...)` / `Bash(...)` entries, and Codex read-only or workspace-write sandbox posture
- structured `.jsonl` transcript or history metadata for tool-call, approval, action-log, request, and trace evidence
- inline credential field indicators in agent configuration without emitting values

Exact vendor names are used only to identify supported adapters and file formats. Public classification is expressed in Ariadne's own exposure taxonomy.

## Output Model

Every run separates facts from classification.

Inventory output includes:

- a runtime surface map with source refs, handling counts, modeled authorities, tools, controls, and limitations
- discovered surfaces
- parsed facts
- modeled authorities, controls, and boundaries
- graph nodes and edges
- redaction metadata
- warnings and limitations
- graph exports with `--format dot` or `--format mermaid`

Assess output is the recommended first-run product view. It composes inventory, exposure, Zero Trust architecture, closure evidence, and the operator case board into one readout: what was inspected, how many exposure paths were found, which architecture boundaries are breaking, which controls already closed or partially closed a path, which case to start with, the evidence references behind that case, proof surfaces to update, proof patches Ariadne can parse, and the exact commands to create a closure workspace and rerun/compare before/after proof artifacts. The `triage` section separates hard risk signal from normal/expected agent capability, missing hard barriers, partial/friction controls, present hard barriers, and unknown evidence gaps. The `source_reference_workbench` section is the structured evidence-opening contract: ranked source refs, exact files, line labels, facts, local paths, metadata-only flags, inspect commands, and a `source_action_board` that groups files or proof surfaces into inspect/verify tasks. The `signal_quality` section is the explicit signal/noise boundary: capability alone is not exposure, and action required needs graph evidence connecting influence, authority, boundary reachability, and missing hard-barrier evidence. The `lethal_trifecta` section names the data-egress chain by ingredient: untrusted content, private-data access, and external communication in the same supported graph, plus the controls that would break one ingredient. It also emits structured `signal_details` so the UX and JSON contract can show each signal's category, disposition, summary, graph edges, why it matters, related controls, evidence references, and limitations instead of relying only on prose. The `closure_plan` section reduces the larger missing-control set into a small ranked proof queue: the next control, the case it closes, why it is first, the evidence refs behind it, the proof surface, rerun command, compare command, and done criteria. Use `--case <case-id>` or `--control <control-id>` to keep the same first-run assessment command but collapse the operator queue, first action, proof plan, and closure plan to one remediation path. The first action also carries affected targets/flaws, an ordered evidence -> proof -> rerun -> compare workflow, and a compact current-action pointer to the active proof patch and rerun/compare commands. `operator_workbench.closure_loop` makes that workflow a stable client contract: save baseline proof, add or verify evidence, rerun the case, save after proof, compare state, and make the closure decision from deterministic artifacts. `operator_workbench.runbook` is the compact action-first JSON projection over that loop: open-first evidence, current step, next step, files, artifacts, commands, done criteria, closure workspace command, and closure workflow. `--format runbook` renders that action-first operator runbook directly in the terminal. `--format runbook-json` emits the same runbook in a standalone JSON wrapper with run metadata, source-reference workbench rows and actions, redaction metadata, warnings, and limitations. `--format operator` renders the compact ticket-style handoff: start case, actionable facts, normal context, source refs, graph path, missing and target controls, proof-state checkpoint, exact proof/rerun/compare commands, and done criteria. `--format operator-json` emits the same compact packet in a standalone JSON wrapper with run metadata, source-reference workbench rows and actions, redaction metadata, warnings, and limitations. `--format action` renders a fuller workflow packet with signal quality, lethal trifecta, signal triage, and closure plan context. HTML assessment output starts with an Operator Console for the active case, open/verify source tasks, proof loop, and commands, then adds an Operator Runbook with a top-level Closure Workflow table, Source Reference Workbench, Source Action Board, Operator Packet section, case navigation, and an active case workbench with current state, evidence to inspect, controls to start with, a control proof recipe, proof patches, accepted evidence examples, a Closure Loop table, closure workspace command, focused proof-plan commands, compare-loop commands, rerun commands, and done criteria. JSON emits the same contract with `summary`, optional `case_filter` and `control_filter`, `source_reference_workbench`, `operator_packet`, `operator_workbench`, `signal_quality`, `lethal_trifecta`, `triage`, `inventory`, `exposure`, `closure_evidence`, `closure_plan`, `architecture` or `architecture_scan`, `case_board`, `top_cases`, `top_case_proof_plan`, and `next_commands`.

Prove output adds:

- exposure path ID and title
- status: `exposed`, `protected`, or `inconclusive`
- proof mode: `inferred`, `simulated`, or `live_lab`
- graph path edges
- controls that break the path
- Zero Trust architecture checks with evidence, graph edges, controls, actions, and limitations
- Zero Trust architecture flaw categories with control-test result, control evidence needed, and evidence surfaces
- Zero Trust framework coverage rows that map source guidance areas to Ariadne checks, evidence anchors, missing evidence, next collectors, and limitations
- Zero Trust boundary coverage rows with status by target, evidence anchors, missing evidence, next collectors, and control evidence needed
- Zero Trust evidence plan rows that group unknown or not-observed boundary gaps by the next collector needed
- Zero Trust closure family rows that group missing hard barriers into capability areas such as identity, least agency, input trust, tool integrity, observability, response, and governance
- Zero Trust closure plan rows that rank missing hard barriers by affected flaws and targets, with structured evidence references for the files and facts that caused the proof request
- Zero Trust Foundation maturity requirements with control quality, evidence, missing evidence, and actions
- Zero Trust coverage gaps that name missing evidence and the next collector needed
- deterministic interpretation with issue priority, severity, disposition, evidence signals, and actions
- optional LLM review interpretation when `--interpret llm` is used
- limitations

Cases output is the case-first operator view of the architecture closure plan. It starts with the few architecture break paths an operator can act on, then shows rank, priority reason, state, state reason, next step, evidence refs, starting controls, proof surfaces, proof patches, evidence examples, rerun commands, compare-loop commands, and success criteria for each case. Case rank follows deterministic closure priority from severity and affected flaws, targets, and missing hard barriers. Case state and next step are derived from missing hard-barrier controls and parser-recognized proof tasks. Use `--case case:input-trust-boundary` or the unprefixed case id to focus the table, JSON, or HTML output on one case and its supporting evidence.

Closure output is the primary proof-loop workspace. Use `ariadne closure --path . --case case:input-trust-boundary --dir ariadne-closure` to create a local folder with the focused runbook, baseline `before-proof.json`, proof action, proof-plan dashboard, suggested proof files, README, manifest, and exact after-proof and compare commands. It does not mutate the scanned target; it gives the operator one place to review evidence, apply or verify controls, rerun, and compare.

Proofs output is the narrower closure-loop action view. Use `ariadne proofs --path . --case case:input-trust-boundary` when the operator already knows which case to work and needs only the evidence references, proof patches, parser-recognized fields, rerun commands, compare-loop commands, success criteria, and limitations. Use `--format html` for a focused proof-plan dashboard with an evidence workbench: inspect facts, add or verify parser-recognized evidence, rerun, compare before/after proof JSON, and confirm the break path is closed. Use `--patch-dir proof-patches` to export suggested proof evidence files under `proof-patches/surfaces/` plus `manifest.json` and `README.md`; the manifest records each suggested destination path, review/apply command, and exact rerun/compare commands. The export is still review-first and does not mutate the scanned repo. If the requested case is no longer in the missing-hard-barrier board but Ariadne observes controlled architecture evidence for that case family, the focused output returns `state: closed`, observed hard barriers, evidence references, and zero proof patches instead of failing with "case not found." Proof patches are evidence plans, not automatic remediation or proof of live enforcement.

Compare output is the rerun readout. Use `ariadne compare --before before-proof.json --after after-proof.json` after saving JSON from `proofs`, `cases`, or `assess`. It starts with an outcome block showing how many cases are open, closed, or absent in the after artifact, how many material changes were observed, which cases still require action, and the next deterministic action. It then emits `closure_receipts`: ticket-ready proof summaries with case ID, before/after state, proof status, control evidence, evidence sources, exact evidence references, artifact sources, before/after SHA-256 artifact hashes, remaining action, rerun commands, compare commands, decision rules, and limitations. Use `--format receipt` to render only those pasteable receipts for a ticket or audit note. Each detailed case row also reports whether the case closed, reopened, stayed open, stayed closed, changed, was added, or was removed, plus a `proof_verdict` that names the deterministic closure status, control evidence, evidence sources, remaining action, rerun commands, compare commands, decision rules, and limitations. The same case row also includes before/after control evidence, proof patch counts, evidence reference counts, source-backed evidence-reference details, evidence deltas, next steps, rerun commands, and compare-loop commands.

Architecture output includes an operator case workflow section so the readout does not stop at "what is breaking." It prints the case-board command and focused `--case` commands for the top closure families.

Controls output is the deeper proof catalog behind the case board. It answers which hard barriers are missing, which flaws each one closes, which evidence references caused the proof request, where evidence should be supplied, which parser-recognized indicators Ariadne understands for that control, and what an accepted evidence shape can look like. It also groups controls into break-path workstreams so operators can start with a few architecture decisions instead of treating every missing control as equal. Verification tasks provide the lower-level proof loop so operators can add evidence, rerun Ariadne, and confirm the missing hard barrier is no longer reported. Recognized indicators, proof patches, and examples are deterministic evidence hints; they do not prove live enforcement unless Ariadne also observes runtime enforcement evidence.

Dashboard output adds:

- issue summary
- Zero Trust boundary coverage map
- prioritized issue table
- copyable local evidence paths and copyable rerun/proof/compare commands
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

This repository currently focuses on deterministic evidence, graph-backed exposure, deterministic priority interpretation, and optional fact-bound LLM review. The deterministic layer remains useful on its own and is the evidence source for LLM review. LLM review packets have two profiles: `follow-up` for ingestible reviews over Ariadne exposure IDs and graph edges, and `inventory-blind` for lower-bias exploration that omits Ariadne's exposure ranking until a hypothesis is mapped back to deterministic evidence.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports should follow [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
