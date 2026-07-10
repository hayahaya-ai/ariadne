---
name: ariadne-posture
description: Assess and fix the security posture of AI coding-agent configuration (Claude Code, Codex, Cursor, Copilot, Gemini, MCP) using the Ariadne CLI. Use before or after editing agent config files (.claude/settings.json, .codex/config.toml, mcp.json, GEMINI.md, devcontainers), when the user asks whether their agent setup is safe or reckless, when auditing a repo or machine for AI-agent risk, or to verify that a config fix actually reduced exposure.
---

# Consuming Ariadne — the contract for agents

Ariadne (`ariadne` on PATH, or `./bin/ariadne` in its repo) reads AI-agent
configuration deterministically — nothing executed, no secret values read — and
prints a graded risk readout. **You are its user.** It hands you facts and
default judgments; you decide, act with your own tools, and re-verify.

If `ariadne` is not installed, do not improvise a substitute analysis and present
it as Ariadne's; say it is unavailable and offer a manual review instead.

## The two layers — never confuse them

- **Facts are deterministic**: which files exist, what they grant, where the
  evidence line is, whether a control is `enforced` (a runtime actually applies
  it) or `attested` (a self-declared `.ariadne/*.json` flag). Facts are not
  yours to override.
- **Judgments are defaults**: the reckless/trade-off/hardened grading is
  Ariadne's deterministic default opinion. If context you hold (the user's own
  statements, provenance you can verify) contradicts a default judgment, you may
  depart from it — but say explicitly that you are overriding Ariadne's default
  and why. Never present your override as Ariadne's output.

## Commands

```bash
ariadne self                      # one-screen readout of this machine (endpoint mode)
ariadne assess --path <repo>      # same for a repo or mounted path
ariadne verdict --json            # machine verdict (schema ariadne.verdict/v1)
ariadne verdict --gate            # exit 3 if reckless — CI/pipeline gate
ariadne ls findings|facts|controls|cases|agents|surfaces
ariadne show <id>                 # drill into reckless:1, fact:*, control:*, case:*, or a file path
```

Exit codes: 0 success, 1 runtime error, 2 usage error, 3 reckless (only with
`--gate`). Prefer `verdict --json` when deciding programmatically; `self` when
showing a human.

## Reading the verdict

- `verdict` word: `reckless` (act), `tradeoffs_only` (acknowledged normal cost —
  do not nag the user about these), `hardened`, or `no_agents_found`.
- Each `reckless` finding carries `where` (source file + line), `why`, `fix`,
  and `attested_only`. **Verify before acting**: open the cited file yourself
  and confirm the line supports the claim. If the anchor is line 0 or the fix
  names a different product than the evidence file, treat the finding as
  directionally useful but re-derive the exact edit from the evidence via
  `ariadne show <id>`.
- `attested_only` entries are visible but non-closing: a self-declared policy
  file never counts as protection.

## Fix protocol (the loop that matters)

1. Capture the baseline: `ariadne verdict --json > /tmp/ariadne-before.json`.
2. Apply the fix **with your own edit tools** to the enforced surface the
   evidence points at (e.g. deny rules or `defaultMode` in
   `.claude/settings.json`, `network_access`/`deny_read` in codex requirements,
   pinning an MCP launcher to an exact version). Ariadne never writes files,
   and neither should you write to configs the user hasn't asked you to touch —
   show the diff or ask, per your session's norms.
3. Re-run `ariadne verdict --json` and compare. A finding is fixed only when
   the verdict changes; an edit that "looks right" but leaves the verdict
   unchanged is not done.

## Hard rules

- **Never create or edit `.ariadne/*.json` files to make findings close.** They
  are attested-only by design; using them to green the screen is gaming the
  verdict and will be reported as such.
- Never disable, weaken, or delete a config control just to simplify a fix.
- Quote Ariadne's actual output when reporting to the user, not a paraphrase of
  what you expected it to say.
- Inconclusive paths (`ariadne ls cases`) are honest unknowns — report them as
  unknowns, not as passes or failures.
