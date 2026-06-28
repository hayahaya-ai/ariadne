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
