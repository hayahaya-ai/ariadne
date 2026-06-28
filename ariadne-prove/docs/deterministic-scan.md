# Deterministic Scan Model

Ariadne's default mode is deterministic. It observes local files and config, emits facts, builds a graph, and classifies only supported exposure paths.

## What Ariadne Does

- walks supported AI-agent surfaces
- parses known configuration and instruction files
- summarizes private/high-volume surfaces by metadata
- models authorities, boundaries, and controls
- builds graph edges between facts
- classifies supported exposure paths

## What Ariadne Does Not Do

- execute agent runtimes
- run shell commands discovered in configs
- execute MCP or tool servers
- install or resolve packages
- call external network services
- read or emit secret values
- infer safety from missing evidence

## Evidence Grades

| Grade | Meaning |
| --- | --- |
| `observed` | Ariadne observed a file, surface, or boundary indicator. |
| `declared` | Ariadne parsed a config or instruction declaration. |
| `inferred` | Ariadne modeled a fact from deterministic evidence. |
| `skipped` | Ariadne intentionally skipped a noisy or private surface. |

## Status Semantics

| Status | Meaning |
| --- | --- |
| `exposed` | Ariadne found a supported graph path from influence or tool authority to a sensitive boundary without a breaking control. |
| `protected` | Ariadne found a supported path attempt and a control that breaks it. |
| `inconclusive` | Ariadne did not collect enough evidence to prove exposure or protection. |

## Redaction

Secret values are never emitted. Private context surfaces are summarized by file count, size, source, and category. Exact sensitive paths outside the scan root are redacted by default.
