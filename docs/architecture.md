# Architecture

Ariadne is intentionally scanner-first. It does not provision agent config,
enforce runtime policy, or upload endpoint inventory.

## Pipeline

1. **Collect**

   Read bounded local files for Codex, Claude Code, MCP, repository instructions,
   package scripts, Makefiles, and devcontainer/devbox indicators.

2. **Normalize**

   Convert local files into facts with evidence source, scan mode, platform,
   confidence, and runtime limitations.

3. **Evaluate Rules**

   Run built-in Go rules for high-signal local posture issues such as bypass mode,
   network enablement, missing managed policy evidence, risky MCP launchers, broad
   filesystem roots, and risky devcontainer settings.

4. **Synthesize Attack Paths**

   Combine facts and findings into credible abuse paths, for example prompt
   injection to secret exposure or MCP supply-chain execution.

5. **Report**

   Emit table, JSON, Markdown, or SARIF with redaction enabled by default.

## Non-Goals For V1

- Runtime enforcement.
- Fleet dashboard.
- Uploads.
- Automatic remediation.
- Native Windows scanning.
- Executing MCP servers to inspect tools.

## Extension Points

- More precise parsers for Codex, Claude Code, and MCP config.
- Optional custom policy rules.
- Enterprise repo tier inventory.
- Signed release artifacts and SBOMs.
- Future control-plane integration that consumes local reports without weakening
  the local-first safety model.
