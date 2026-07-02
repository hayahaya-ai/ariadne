# JSON And Graph Contract

The current schema version is `ariadne.report/v1`.

## Core Objects

### Surface

A discovered AI-agent surface.

- `runtime`: supported runtime or `generic`
- `scope`: `repo` or `endpoint`
- `category`: surface category
- `kind`: concrete surface kind
- `handling_mode`: `parse`, `summarize`, `boundary_indicator`, `skip`, or `ignore`
- `source`: redacted or target-relative source

### Fact

A deterministic fact derived from a surface.

- `evidence_grade`: `observed`, `declared`, `inferred`, or `skipped`
- `redaction`: output handling applied to the source/content
- `summary`: human-readable fact summary

### Graph

Graph nodes and edges represent the exposure model.

Node types:

- `trust_input`
- `runtime`
- `config`
- `tool`
- `authority`
- `boundary`
- `control`
- surface categories such as `runtime-config`, `mcp-tool-config`, and `history-cache`

Edge types:

- `configures`
- `influences`
- `can_call`
- `grants`
- `has_authority`
- `reaches`
- `restricts`
- `filters`
- `requires_approval`
- `limits`
- `authorizes`
- `identifies`
- `scopes_credentials`
- `observes`
- `traces`
- `governs`
- `verifies`

### Interpretation

`prove`, `scan`, and `dashboard` include deterministic interpretation on top of exposure paths.

Interpretation includes:

- `mode`: currently `deterministic`
- `engine`: interpreter name
- `available_modes`: supported modes such as `deterministic` and `llm_review`
- `summary`: issue counts by severity and disposition
- `issues`: prioritized issue records
- `policy_source`: `built_in` or `built_in+custom`
- `review_source`: source of an ingested LLM review, when applicable
- `request_digest`: SHA-256 digest of the LLM review request packet, when applicable
- `limitations`

Each issue includes:

- `priority`: `p0`, `p1`, `p2`, `p3`, or `p4`
- `severity`: `critical`, `high`, `medium`, `low`, or `info`
- `disposition`: `fix_now`, `review`, `monitor`, `controlled`, or `expected_capability`
- `rule_source`: `built_in` or `custom`
- `signals`: facts or graph predicates that caused the rule to match
- `graph_edges`: path evidence cited by the issue
- `actions`: concrete next steps

Custom deterministic policies are documented in [priority-rules.md](priority-rules.md).

### Zero Trust

`prove` output includes `zero_trust`, an architecture-boundary assessment derived from the same deterministic facts, graph edges, controls, and limitations.

Each check includes:

- `principle`: Zero Trust principle such as least agency, assume breach, or never trust and always verify
- `boundary`: architecture boundary under review
- `status`: `breaking`, `controlled`, `unknown`, or `not_observed`
- `design_test`: the capability-removal test Ariadne applies
- `finding`: fact-backed result text
- `evidence`: source references and summaries
- `graph_edges`: graph evidence supporting the check
- `controls`: controls that break or restrict the path
- `actions`: concrete next steps
- `limitations`

Architecture closure rows and control catalog rows also include `evidence_refs`. Each reference preserves the affected `target`, evidence `id`, evidence `kind`, redacted or target-relative `source`, and fact `summary` so an operator can trace a missing-control request back to the file or modeled fact that caused it.

`zero_trust.coverage` converts unknown and not-observed checks into explicit evidence gaps:

- `known`: checks classified as `breaking` or `controlled`
- `gaps`: number of unknown or not-observed coverage gaps
- `gap_details`: missing evidence, why it matters, and the next collector needed

`zero_trust.maturity` maps the current run against Ariadne's Foundation Zero Trust agent requirements:

- `target_tier`: currently `foundation`
- `summary`: total requirements, requirements with enough deterministic evidence to be treated as met, relevant gaps, breaking requirements, unknowns, not-observed requirements, hard barriers, and friction-only controls
- `requirements`: each requirement's capability, principle, status, control quality, evidence, controls, missing evidence, and actions

Control quality separates hard barriers from partial or friction-only evidence. This prevents approval prompts, warnings, filtering, delimiting, sandboxing, network restriction, or generic policy text from being treated as equivalent to input isolation, cryptographic identity, short-lived credentials, deny-by-default permissions, identity-aware workload authorization, or audited traceability.

`breaking` is reserved for graph-backed paths or missing break-path controls. Missing input isolation, identity, credential, workload authorization, or telemetry evidence is reported as `unknown` until Ariadne collects deterministic facts that prove the boundary.

`ariadne architecture --format json` emits a focused architecture contract with:

- `summary` and `overall_summary`
- `evidence_coverage`
- `evidence_plan`, where unknown or not-observed boundary gaps are grouped by next collector
- `framework_coverage`, where Zero Trust for AI Agents source areas are mapped to Ariadne checks, evidence anchors, missing evidence, and limitations
- `maturity`
- `boundary_coverage`
- `flaws`, where each flaw includes a `control_test` result for the impossible-vs-tedious design test
- `closure_families`, where missing hard barriers are grouped into Zero Trust capability areas with evidence anchors and structured evidence references
- `closure_plan`, where missing hard barriers are ranked by affected flaws and targets with evidence anchors and structured evidence references

`ariadne assess --format json` emits the primary first-run assessment contract with:

- `summary`, combining inspected-surface counts, exposure path counts, architecture flaw counts, missing hard-barrier controls, and the top case
- `inventory`, summarizing discovered AI surfaces, typed facts, graph size, runtime/tool/authority/control/boundary counts, surface categories, and handling modes
- `exposure`, summarizing exposed, protected, and inconclusive paths with a bounded list of top path records
- `architecture` for single-target assessment, or `architecture_scan` for target-list assessment
- `case_board`, the same operator case-board contract emitted by `ariadne cases`
- `top_cases`, a bounded case-first queue for humans
- `next_commands`, including the exact `assess`, focused `cases`, `controls`, and `architecture` commands to rerun

The assessment contract is a composition layer. It does not create a separate classification engine; classifications remain derived from deterministic facts, graph edges, architecture flaws, and missing hard-barrier controls.

`ariadne architecture --targets ... --format json` emits a fleet architecture contract with:

- `summary`
- `evidence_plan`, aggregated across targets
- `framework_coverage`, aggregated across targets
- `boundary_coverage`
- `groups`, including aggregated `control_test_results`
- `closure_families`, aggregated across targets
- `closure_plan`, aggregated across targets
- `targets`

`ariadne controls --format json` emits a focused control evidence catalog with:

- `summary`, counting missing hard-barrier controls by severity, affected targets, and affected flaws
- `controls`, where each missing hard barrier includes the flaws it closes, target coverage, evidence anchors, structured evidence references, proof surfaces, and concrete actions
- `families`, where related controls are grouped into Zero Trust capability areas such as identity, least agency, egress, observability, response, and governance
- `operator_cases`, where each architecture break-path workstream becomes an actionable case with rank, priority reason, state, state reason, next step, evidence references, starting controls, proof surfaces, evidence examples, rerun commands, and success criteria
- `workstreams`, where related controls become break-path workstreams with starting tasks, evidence references, proof surfaces, rationale, and success criteria
- `proof_specs`, where each missing hard barrier maps to the evidence kind, proof surfaces, parser-recognized indicators, notes, and limitations Ariadne uses when looking for deterministic proof
- `verification_tasks`, where each missing hard barrier becomes an operator task with evidence references, proof surfaces, recognized indicators, evidence examples, rerun commands, success criteria, and limitations

This catalog is derived from the architecture closure plan. It does not create a separate classification; it makes the proof request easier to act on. Recognized indicators and evidence examples are evidence hints, not a claim of live runtime enforcement unless paired with observed enforcement evidence.

`ariadne cases --format json` emits the same evidence contract with `run_kind` set to `case_board` or `case_board_scan`. The table and HTML renderers are case-first: they lead with `operator_cases` and keep controls, workstreams, proof specs, and verification tasks as supporting evidence for automation and deeper review. When `--case <case-id>` is supplied, `case_filter` records the selected case and the arrays are narrowed to that case's supporting evidence.

`ariadne controls --format html` renders the same contract as a focused operator dashboard: summary metrics, operator cases, break-path workstreams, verification tasks, control families, and control rows with the missing hard barrier, affected flaws, evidence anchors, proof surfaces, recognized indicators, evidence examples, and actions.

`ariadne cases --format html` renders the same contract as an operator case board: summary metrics, prioritized cases, evidence references, starting controls, proof surfaces, example evidence, rerun commands, done criteria, and a compact evidence model.

LLM review mode uses two JSON payloads:

- request packet: `ariadne.llm_review_request/v1`
- review response: `ariadne.llm_review/v1`

The request packet contains only Ariadne's redacted collection facts, graph evidence, exposure paths, deterministic interpretation, redaction metadata, and limitations. The response is accepted only when every issue cites an existing exposure and supported graph edges.

## Graph Export Formats

The JSON graph is the canonical machine contract. Ariadne can also render the
same nodes and edges directly for visualization:

```bash
ariadne inventory --path . --format mermaid --out ariadne-graph.mmd
ariadne prove --path . --format dot --out ariadne-graph.dot
ariadne scan --targets targets.txt --format mermaid --out fleet-graph.mmd
ariadne dashboard --path . --out ariadne-dashboard.html
```

`dot` output is Graphviz-compatible. `mermaid` output uses `flowchart LR`.

### Exposure

An exposure path includes:

- `id`
- `status`
- `proof_mode`
- `path_nodes`
- `path_edges`
- `observation`
- `controls_break_path`
- `limitations`

## Machine-Readable Draft Schemas

Draft schemas are available in:

- [schema/ariadne-report-v1.schema.json](../schema/ariadne-report-v1.schema.json)
- [schema/ariadne-scan-v1.schema.json](../schema/ariadne-scan-v1.schema.json)
- [schema/ariadne-architecture-v1.schema.json](../schema/ariadne-architecture-v1.schema.json)
- [schema/ariadne-architecture-scan-v1.schema.json](../schema/ariadne-architecture-scan-v1.schema.json)
- [schema/ariadne-control-catalog-v1.schema.json](../schema/ariadne-control-catalog-v1.schema.json)
