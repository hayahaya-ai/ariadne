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

`breaking` is reserved for graph-backed paths or missing break-path controls. Missing identity, credential, ABAC, JIT, or telemetry evidence is reported as `unknown` until Ariadne has collectors that can prove the boundary.

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
