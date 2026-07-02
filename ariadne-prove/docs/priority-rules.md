# Priority Rules

Ariadne separates three layers:

1. **Facts:** deterministic evidence collected from AI surfaces, configs, files, and safe summaries.
2. **Exposure paths:** graph-backed paths from influence or tool authority to a sensitive boundary.
3. **Interpretation:** priority, severity, disposition, and recommended action for paths that matter.

Inventory stays fact-only. `prove`, `scan`, and `dashboard` include deterministic interpretation.

## Built-In Interpretation

The current interpretation mode is `deterministic`.

Built-in rules prioritize supported high-risk pathways:

- secret boundary access from untrusted instructions plus file-read or broad local authority
- mutable MCP/tool launch paths that grant local code execution
- data egress chains that combine untrusted influence, private-data reachability, and external communication
- unusually large private context surfaces
- unusually large MCP/tool surfaces

These rules do not inspect secret values and do not execute agents, tools, package managers, or network calls.

## Priority Model

| Priority | Meaning |
| --- | --- |
| `p0` | Fix now. Complete high-impact path with strong graph evidence. |
| `p1` | High priority. Exposure reaches a sensitive boundary without a breaking control. |
| `p2` | Review soon. Risky surface or protected path that still needs owner attention. |
| `p3` | Monitor. Lower urgency or controlled condition. |
| `p4` | Informational. Incomplete or inconclusive evidence. |

Severity uses `critical`, `high`, `medium`, `low`, and `info`.

Disposition explains what the user should do with the issue:

- `fix_now`
- `review`
- `monitor`
- `controlled`
- `expected_capability`

## Custom Rules

Teams can add custom deterministic rules with `--rules <file>`.

If no explicit rules file is provided, Ariadne also looks for:

```text
.ariadne/rules.json
```

Example:

```json
{
  "version": "ariadne.rules/v1",
  "rules": [
    {
      "id": "org-critical-mutable-tool",
      "title": "Org critical mutable tool path",
      "category": "org-policy",
      "severity": "critical",
      "priority": "p0",
      "disposition": "fix_now",
      "when": {
        "mode": "repo",
        "exposure_id": "mutable-tool-launch-execution",
        "exposure_status": "exposed",
        "has_edges": [
          "tool:mcp-package-launch|grants|authority:local-code-execution"
        ],
        "missing_controls": [
          "control:mcp-reviewed-pinned"
        ]
      },
      "rationale": "Organization policy requires mutable tool launch paths to be treated as critical.",
      "actions": [
        "Pin MCP packages.",
        "Require reviewed MCP server definitions."
      ]
    }
  ]
}
```

Supported match conditions:

- `mode`
- `exposure_id`
- `exposure_status`
- `has_nodes`
- `has_edges`
- `has_controls`
- `missing_controls`
- `min_surface_count_by_category`

Rules match graph evidence and exposure results. They do not match arbitrary raw content.

## Commands

```bash
ariadne prove --path . --rules .ariadne/rules.json
ariadne scan --targets targets.txt --rules .ariadne/rules.json --format json
ariadne dashboard --path . --rules .ariadne/rules.json --out ariadne-dashboard.html
ariadne dashboard --path . --view exposure --rules .ariadne/rules.json --out exposure-dashboard.html
ariadne dashboard --targets targets.txt --out fleet-dashboard.html
```

`dashboard` defaults to the operator assessment view with first action, operator cases, evidence links, and proof-loop commands. Use `--view exposure` when you want the lower-level exposure/facts dashboard with:

- issue summary
- prioritized issue table
- exposure paths
- facts dive with graph edges and evidence rows
- warnings and limitations

## LLM Review Mode

Ariadne also supports `llm_review` as an optional interpretation mode.

The LLM does not collect facts. Ariadne collects and redacts the facts first, then sends only a review packet containing:

- redacted surfaces and facts
- graph nodes and edges
- a reviewer task list
- a citation catalog of fact IDs, source refs, graph edges, controls, authorities, and boundaries
- a review contract that states allowed claims, forbidden claims, required citations, and response rules
- exposure paths and deterministic interpretation as an anchor in the default `follow-up` profile
- limitations and redaction metadata

Generate an ingestible follow-up review packet:

```bash
ariadne prove --path . --llm-request-out llm-request.json
```

Generate a lower-bias inventory-blind packet:

```bash
ariadne prove --path . --llm-request-out llm-request.json --llm-review-profile inventory-blind
```

Inventory-blind packets omit Ariadne's exposure paths and deterministic issue ranking. They are for exploratory review and collector-gap discovery; Ariadne does not ingest them as findings until the hypothesis is mapped back to deterministic exposure evidence.

Have an LLM reviewer produce JSON with schema version `ariadne.llm_review/v1`, then ingest it:

```bash
ariadne prove --path . --interpret llm --llm-review llm-review.json
ariadne dashboard --path . --interpret llm --llm-review llm-review.json --out ariadne-dashboard.html
```

You can also plug in a local reviewer command. Ariadne writes the review packet to stdin and expects review JSON on stdout:

```bash
ariadne prove --path . --interpret llm --llm-command ./security-reviewer
```

The command is executed directly, not through a shell. Use a wrapper executable if the reviewer needs complex arguments.

Example review response:

```json
{
  "schema_version": "ariadne.llm_review/v1",
  "reviewer": "internal-security-reviewer",
  "model": "team-approved-model",
  "summary": "The data egress chain is the highest-risk path.",
  "issues": [
    {
      "id": "data-egress-critical",
      "title": "LLM-reviewed data egress path",
      "severity": "critical",
      "priority": "p0",
      "disposition": "fix_now",
      "category": "data-egress",
      "exposure_id": "data-egress-chain",
      "exposure_status": "exposed",
      "rationale": "The packet contains untrusted influence, private-data reachability, and external communication reachability.",
      "signals": [
        "Graph contains the data egress chain."
      ],
      "graph_edges": [
        "trustinput:repo-instruction|influences|runtime:codex"
      ],
      "actions": [
        "Restrict external communication for agent runtimes."
      ],
      "confidence": "medium"
    }
  ]
}
```

LLM output is fact-bound:

- every issue must cite an existing `exposure_id`
- `exposure_status` must match Ariadne's exposure status
- every `graph_edges` entry must exactly match an Ariadne graph edge
- unsupported severity, priority, or disposition values are rejected
- LLM output is stored as interpretation, not as raw evidence
- `inventory-blind` packets are request-only and cannot be ingested directly as Ariadne findings

This keeps Ariadne fact-first while allowing non-deterministic review for ambiguous or organization-specific judgment.
