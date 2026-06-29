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
ariadne dashboard --targets targets.txt --out fleet-dashboard.html
```

`dashboard` writes a local static HTML report with:

- issue summary
- prioritized issue table
- exposure paths
- facts dive with graph edges and evidence rows
- warnings and limitations

## Future LLM Review

The JSON output advertises `future_modes: ["llm_review"]`.

That mode is intentionally not implemented yet. The intended shape is:

- deterministic collector and graph remain the source of truth
- LLM review receives redacted facts and graph evidence
- LLM judgment is stored as an interpretation layer, not as raw fact
- deterministic and LLM interpretations can be compared

This keeps Ariadne fact-first while allowing a future non-deterministic review mode for ambiguous or organization-specific judgment.
