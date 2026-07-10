# Ariadne

[![CI](https://github.com/hayahaya-ai/ariadne/actions/workflows/ci.yml/badge.svg)](https://github.com/hayahaya-ai/ariadne/actions/workflows/ci.yml)

**One command that tells you if your AI coding setup is dangerous.**

Your AI assistants — Claude Code, Codex, Cursor, Gemini CLI, Copilot, and their
MCP tools — can read your files, run programs, and reach the internet. Ariadne
reads their configuration and answers one question, deterministically:

> Can untrusted instructions plus agent authority create a path to sensitive
> local boundaries — and do enforced controls break that path?

Nothing is executed, no packages are installed, no network calls are made, and
secret values are never read. Ariadne inspects your setup the way an auditor
reads blueprints, without touching the wiring.

## The 60-second readout

```text
$ ariadne self

Ariadne · AI agent risk readout
Scanned your machine · 4 agent runtimes found · 1,887 config files read ·
nothing executed, no secret values read

  VERDICT: RECKLESS — 1 finding needs action.

  RECKLESS ── fix these ──
  1. A mutable tool launcher can run unreviewed code on your machine
       where  .cursor/mcp.json:2
       why    it downloads and runs whatever the package registry serves
              today, with your permissions
       fix    pin the package to an exact version in .cursor/mcp.json

  TRADE-OFFS ── normal cost of using agents ──
  •  agents read your workspace — that is what a coding agent is for

  HARDENED ── working in your favor ──
  ✓  approval prompts are enforced in .claude/settings.json
```

The verdict is a word, not a score: `reckless`, `tradeoffs_only`, `hardened`,
or `no_agents_found`. Every finding carries the exact file and line, why it
matters in one sentence, and a one-line fix for the same surface the evidence
came from.

## How it decides

Every conclusion lands in exactly one of three buckets:

- **Reckless** — the dangerous combination exists (untrusted influence +
  private-data reach + external egress, or a mutable tool launcher) and no
  enforced barrier breaks it.
- **Trade-offs** — real capabilities, honestly named, that are simply the cost
  of agents being useful. Acknowledged, never nagged about.
- **Hardened** — enforced protections already working for you: deny rules,
  sandboxes, pinned launchers, approval gates, CI secret isolation.

Two design rules keep the word trustworthy:

- **Facts are deterministic; opinions are labeled.** What exists, what it
  grants, and which line are facts — the same scan gives byte-identical
  answers. Where grading requires judgment (your own home config is not
  "untrusted input" by default; a plain `pull_request` workflow benefits from
  GitHub's fork-PR secret isolation), the verdict JSON carries that judgment's
  name and the fact IDs it weighed in `default_judgments`, so a person or an
  agent can overrule it.
- **The verdict cannot be gamed.** A self-declared `.ariadne/*.json` policy
  file is `attested` evidence and never improves the grade. Only enforced
  configuration counts.

## Quick start

```bash
make build                 # builds ./bin/ariadne (Go, zero dependencies)
./bin/ariadne self         # assess this machine (endpoint mode)
./bin/ariadne assess --path <repo>   # assess a repository
```

Fix suggestions are printed, never applied — Ariadne only reads. Apply the fix
with your own tools, rerun, and watch the verdict drop.

## Built to be driven by agents

The primary user may be an AI agent deciding what to do next. Every line has a
stable ID and the CLI is a navigable resource tree:

```bash
ariadne verdict --json             # machine verdict (schema: ariadne.verdict/v1)
ariadne ls findings                # findings | agents | surfaces | controls | facts | cases
ariadne show reckless:1            # drill into one finding: evidence, why, fix
ariadne show .claude/settings.json # everything concluded from one file
```

A Claude Code plugin ships in this repo — the `ariadne-posture` skill teaches
any agent the consumption contract (verify evidence, fix with your own tools,
re-verify, never fake a passing grade) and the read-only `ariadne-audit`
subagent handles side-thread audits:

```bash
claude plugin marketplace add hayahaya-ai/ariadne
claude plugin install ariadne@ariadne
```

## Gate a pipeline, see a fleet

```bash
# CI gate: exit 3 when reckless — this repository gates itself with this line.
ariadne verdict --path . --mode repo --gate

# Fleet rollup: one verdict/v1 JSON line per endpoint, plus a worst-first
# summary with findings grouped by family — SIEM-ready.
ariadne scan --targets endpoints.txt --mode endpoint --format jsonl --out verdicts.jsonl
ariadne scan --targets endpoints.txt --mode endpoint --format json  --out fleet.json
```

Fleet numbers obey the same rule as the readout: attested declarations never
improve a tally. See [Operating Ariadne](docs/operations.md) for CI and
MDM/fleet deployment patterns documented against verified behavior.

## Why you can trust the answer

- **Scored against 29 fixture worlds** with known-correct expected verdicts —
  including adversarial twins built to catch lazy shortcuts (keyword-in-string,
  deny-vs-allow, commented-out config, self-declared policies, nested test
  corpora, `pull_request_target` vs plain `pull_request`) — at 100%
  verdict-word accuracy and 100% per-family precision/recall (`make eval`).
- **Proven deterministic**: repeated runs are byte-identical modulo run ID and
  timestamp, enforced by tests.
- **Fast**: ~2,000 config files in about half a second (benchmarked).
- **Calibrated on real machines**: every false alarm found in the wild became a
  permanent regression fixture.
- **Exit codes are contract**: 0 success · 1 runtime error · 2 usage error ·
  3 reckless (with `--gate`) — each tested.
- **Self-gated**: CI runs the full scorecard plus `ariadne verdict --gate` on
  this repository itself.

## What it deliberately does not do

No agent execution, no MCP server launches, no package installs, no live
network tests, no secret values in output, no compliance-framework theater.
Private histories, transcripts, and caches are summarized by metadata only.
Ariadne answers "am I being reckless?", not "am I ISO-aligned?"

## Deeper workflows

Behind the one-screen readout, Ariadne keeps a full evidence trail: graph
exports (JSON/DOT/Mermaid), Zero Trust boundary mapping, operator case boards
with proof loops and closure receipts, self-assessment bundles
(`ariadne self --bundle-dir <dir>`, verified with `ariadne bundle verify`),
and a fact-bound LLM review path (`review-packet` → `review-check`) where
analyst output must cite existing fact IDs and can never alter the verdict.
These remain available behind explicit flags and `--format` options:

```bash
ariadne self --format summary|table|json|html
ariadne assess --path <repo> --format operator
ariadne stories list           # Story Lab fixture worlds
make verify-first-run          # product verification loop
make eval                      # verdict eval scorecard (exits 0 only when clean)
```

## Documentation

- [Install](ariadne-prove/INSTALL.md)
- [Operating Ariadne: CI gate and fleet scans](docs/operations.md)
- [North star and quality bar](docs/northstar.md)
- [CLI contract](docs/cli-contract.md)
- [Deterministic scan model](ariadne-prove/docs/deterministic-scan.md)
- [Zero Trust agent architecture](ariadne-prove/docs/zero-trust-agent-architecture.md)
- [Threat model](ariadne-prove/docs/threat-model.md)
- [Fleet usage](ariadne-prove/docs/fleet.md)
- [JSON and graph contract](ariadne-prove/docs/json-schema.md)
- [Contributing](ariadne-prove/CONTRIBUTING.md) · [Security policy](ariadne-prove/SECURITY.md)

## License

Apache License 2.0. See [LICENSE](LICENSE).
