# Privacy Contract

Ariadne is local-first and deterministic by default.

## Collected

- AI-agent configuration surfaces
- declared sandbox, approval, permission, network, MCP, and policy settings
- repository and endpoint instruction surfaces
- command, plugin, memory, and private-context surface metadata
- sensitive boundary indicators such as secret-like paths

## Not Collected

- secret values
- full private histories, transcripts, paste caches, or session contents
- network traffic
- browser state contents
- package registry contents
- runtime process memory

## Execution Safety

Ariadne must not execute:

- agent runtimes
- MCP or tool servers
- package managers
- shell scripts
- repository commands

## Redaction

Reports are redacted by default. Sensitive values are never emitted. Private
context surfaces are summarized by source, category, size, count, and redaction
metadata.

## Report Handling

Reports are still security artifacts. They may reveal repository names, agent
configuration posture, tool inventory, and modeled exposure paths.

See [`ariadne-prove/docs/threat-model.md`](../ariadne-prove/docs/threat-model.md)
and [`ariadne-prove/docs/deterministic-scan.md`](../ariadne-prove/docs/deterministic-scan.md)
for the detailed model.
