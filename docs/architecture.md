# Architecture

The active Ariadne implementation lives in [`ariadne-prove/`](../ariadne-prove/).
The root command delegates to that implementation when run from a source checkout.

## Deterministic Pipeline

1. **Discover surfaces**

   Walk supported AI-agent surfaces for Claude Code, Codex, generic repository
   instructions, MCP configuration, command files, plugin surfaces, memories,
   histories, and sensitive boundary indicators.

2. **Parse or summarize**

   Parse known security-relevant configuration. Summarize private or high-volume
   context such as histories, paste caches, and session state without emitting
   content.

3. **Normalize facts**

   Convert observed files and declarations into typed facts with source,
   handling mode, evidence grade, redaction status, summary, and limitations.

4. **Build the graph**

   Connect trust inputs, runtimes, configs, tools, authorities, boundaries, and
   controls with explicit graph edges.

5. **Evaluate exposure**

   Classify only supported graph-backed exposure paths as `exposed`,
   `protected`, or `inconclusive`.

6. **Report**

   Emit fact-first terminal output, JSON, Graphviz DOT, or Mermaid. Scan mode
   aggregates the same reports across many local or mounted targets.

## Main Packages

- `surface`: AI surface registry and bounded discovery.
- `adapter`: deterministic collection and runtime-specific parsing.
- `prove`: graph construction, exposure evaluation, Story Lab, and scan runs.
- `report`: terminal, JSON, DOT, and Mermaid rendering.
- `model`: stable report, graph, evidence, and scan types.

## Non-Goals For This Layer

- executing agents, MCP servers, package managers, or shell commands
- reading or reporting secret values
- live exploit proof
- non-deterministic LLM review
- cloud control-plane collection
- runtime enforcement

Those can be future layers. The deterministic layer is intentionally useful on
its own.
