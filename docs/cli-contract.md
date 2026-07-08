# Ariadne CLI contract — agent-native front door

Spec for the one-screen readout, verdict JSON, and `ls`/`show` drill-down.
Read `docs/northstar.md` first. House rules in `CLAUDE.md` apply (zero external
dependencies, fixtures with every detection change, no gameable verdicts).

## Command grammar

```
ariadne self [--path P] [--format readout|summary|table|json|html] [--bundle-dir D]
ariadne assess --path P [--format readout|...]        # readout becomes default
ariadne verdict [--path P] [--mode M] [--json] [--gate]
ariadne ls <findings|agents|surfaces|controls|facts|cases> [--path P] [--mode M] [--json]
ariadne show <id> [--path P] [--mode M] [--json]
```

- `self` and `assess` default format changes to `readout` (the one-screen).
  The previous default moves to `--format summary`. All other formats unchanged.
- `verdict` prints the compact verdict (text by default, JSON with `--json`).
  With `--gate`, exit code 3 when verdict is `reckless` (0 otherwise). Without
  `--gate`, always exit 0 on success. `self`/`assess` always exit 0 on success.
- `ls` prints one resource per line: `<id>\t<one-line summary>`.
- `show` resolves any ID the run knows: `reckless:N`, `tradeoff:N`, `hardened:N`,
  `case:*`, `control:*`, `fact:*` (fact IDs from the collection), runtime IDs
  (`runtime:claude`), or a surface source path (`.claude/settings.json`).
  Unknown ID: exit 1 with a one-line error listing valid prefixes.
- Exit codes everywhere: 0 success, 1 runtime error, 2 usage error, 3 reckless
  (only with `--gate`).
- **Fix suggestions print; Ariadne never writes to scanned files.**

## Grading rules (deterministic, in this order)

Inputs: the same data `assess` already computes — `model.Report` (Exposures,
ZeroTrust.ArchitectureFlaws, Graph, Evidence) and the inventory collection
(Controls with `Enforcement`, Authorities, Boundaries, TrustInputs, Surfaces,
Runtimes).

**RECKLESS** — one finding per `ExposureResult` with `Status == exposed`, ordered:
data-egress-chain first, then prompt-injection-to-secret-canary, then
mutable-tool-launch-execution. Each finding carries:
- `id`: `reckless:1`, `reckless:2`, … (screen handle) plus `exposure_id` (stable).
- `title`: one sentence naming the concrete risk (derive from exposure title,
  rewritten in second person, e.g. "Untrusted repo text can steer an agent that
  reads your secrets and can reach the internet").
- `where`: the highest-signal evidence reference (source + line) from
  `EvidenceReferences`; include up to 3 additional refs in JSON.
- `why`: one sentence from `WhyItMatters`.
- `fix`: one-line enforced-surface fix. NEVER suggest `.ariadne/*` declarations.
  Canonical fixes per family:
  - secret family → `set "defaultMode": "default" and add deny rules for secret paths in .claude/settings.json (or codex requirements deny_read)`
  - mcp family → `pin the MCP package to an exact version in <mcp source>`
  - egress family → `restrict network: codex requirements network_access = false, or deny WebFetch/WebSearch in .claude/settings.json`
- Attested-only controls related to the finding are listed as
  `attested_only` (visible, non-closing).

**TRADE-OFFS** — capabilities observed but not part of any exposed path (i.e. the
matching exposure family is not `exposed`):
- `authority:external-communication` → "an agent can reach the network — normal
  for installs and web lookups".
- `authority:file-read` → "agents read your workspace — that is what a coding
  agent is for".
- `boundary:agent-private-context` → "agent chat/history is stored locally".
- `tool:mcp-package-launch` present with enforced `control:mcp-reviewed-pinned` →
  "MCP tools configured and pinned".
One line each, id `tradeoff:N`, with `source` in JSON.

**HARDENED** — enforced controls (`Enforcement == "enforced"`), deduped by control
ID, id `hardened:N`, rendered `✓ <control summary> (enforced) — <source>`.
Cap at 6 on screen; full list in JSON.

**Verdict word**: any reckless → `reckless`; else any tradeoffs → `tradeoffs_only`;
else any hardened or any runtime found → `hardened`; no runtimes discovered →
`no_agents_found`. Inconclusive exposures add one line under the readout:
"Couldn't verify: <n> path(s) lacked evidence — see ariadne ls cases."

## Verdict JSON (`schema/ariadne-verdict-v1.schema.json`)

```json
{
  "schema_version": "ariadne.verdict/v1",
  "generated_at": "...",
  "target": "/abs/path",
  "mode": "endpoint",
  "verdict": "reckless",
  "scanned": { "runtimes": ["claude", "codex"], "surfaces": 14, "executed": false },
  "reckless": [
    {
      "id": "reckless:1",
      "exposure_id": "data-egress-chain",
      "title": "...",
      "where": { "source": ".claude/settings.json", "line": 4 },
      "evidence_refs": [ { "source": "...", "line_start": 1, "summary": "..." } ],
      "why": "...",
      "fix": "...",
      "attested_only": ["control:egress-destination-allowlist"]
    }
  ],
  "tradeoffs": [ { "id": "tradeoff:1", "summary": "...", "source": "..." } ],
  "hardened": [ { "id": "hardened:1", "control": "control:...", "summary": "...", "source": "..." } ],
  "inconclusive": 0,
  "next_action": "fix reckless:1, then rerun ariadne self",
  "limitations": [ "Verdict is derived from configuration evidence only; nothing was executed." ]
}
```

## One-screen readout template

Faithful to the approved mockup (docs/northstar.md). Layout:

```
Ariadne · AI agent risk readout
Scanned <target> in <t>s · <n> agent runtimes found (<names>) · <m> config files read ·
nothing executed, no secret values read

  VERDICT: <WORD> — <counts sentence>.

  RECKLESS ── fix these ──
  1. <title>
       where  <source>:<line>  <snippet-free indicator>
       why    <one sentence>
       fix    <one line>            (~<estimate>)

  TRADE-OFFS ── normal cost of using agents ──
  •  <one line each>

  HARDENED ── working in your favor ──
  ✓  <one line each, max 6>

  Next: <next_action>
  More: ariadne show reckless:1 · ariadne ls findings · --format json
```

Hard cap: the readout must not exceed 40 lines for ≤3 reckless findings. Sections
with zero entries are omitted (except a HARDENED/TRADE-OFFS empty state one-liner
when the verdict is reckless).

## Implementation constraints

- New logic in `internal/verdict` (build) and small renderers; wire in
  `cmd/ariadne/main.go`. Do not grow `internal/report/report.go`.
- Reuse `prove.RunPath` / inventory data; no new collection passes.
- Every grading rule ships with a fixture under `ariadne-prove/testdata/` and a
  test that fails without it.
- `verdict`, `ls`, `show` must work in both repo and endpoint modes.
- Update `scripts/verify-first-run.sh` expectations for the new default format
  (coordinator handles this).
