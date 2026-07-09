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
ariadne scan --targets T [--format table|json|jsonl|dot|mermaid|html]
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
- `scan --targets` defaults to the fleet verdict summary table. `--format jsonl`
  emits one complete `ariadne.verdict/v1` object per completed target, one line
  per target, for SIEM ingestion. `--format json` emits the consolidated
  `ariadne-scan-v1` rollup with `fleet` and `targets[].verdict`.
- Exit codes everywhere: 0 success, 1 runtime error, 2 usage error, 3 reckless
  (only with `--gate`).
- **Fix suggestions print; Ariadne never writes to scanned files.**

## Grading rules (deterministic, in this order)

Inputs: the same data `assess` already computes — `model.Report` (Exposures,
ZeroTrust.ArchitectureFlaws, Graph, Evidence) and the inventory collection
(Controls with `Enforcement`, Authorities, Boundaries, TrustInputs, Surfaces,
Runtimes).

Declared contract change from `docs/goal-ciso-grade.md`, Phase 1 "Influence
provenance": each trust input carries deterministic provenance (`home_scope`,
`repo_checkout`, `third_party`, or `unknown`) derived from surface scope/arrival
path. For exposed influence families, home-scope influence alone is a labeled
default judgment, not a fact claim that the file is safe or user-authored.

**RECKLESS** — one finding per effectively exposed `ExposureResult`, ordered:
data-egress-chain first, then prompt-injection-to-secret-canary, then
mutable-tool-launch-execution. An exposed data-egress-chain or
prompt-injection-to-secret-canary path is not effectively exposed when every
risky trust-input leg has provenance `home_scope`; that default judgment is
recorded in verdict JSON and the capability is rendered under TRADE-OFFS
instead. Mixed provenance, `repo_checkout`, `third_party`, `unknown`, or no
risky trust-input leg keeps the exposed path reckless. Each finding carries:
- `id`: `reckless:1`, `reckless:2`, … (screen handle) plus `exposure_id` (stable).
- `title`: one sentence naming the concrete risk (derive from exposure title,
  rewritten in second person, e.g. "Untrusted repo text can steer an agent that
  reads your secrets and can reach the internet").
- `where`: the highest-signal evidence reference from `EvidenceReferences`.
  Parsed surfaces carry `source` + positive `line`. Metadata-only surfaces
  Ariadne deliberately does not read carry `anchor: "file"` and no line.
  Prefer parsed positive-line refs for `where`; use a file-level `where` only
  when no parsed positive-line ref exists. Include up to 3 additional refs in
  JSON.
- `why`: one sentence from `WhyItMatters`.
- `fix`: one-line enforced-surface fix. NEVER suggest `.ariadne/*` declarations.
  Evidence-derived fixes replace the former canonical-per-family strings,
  implementing the Phase 1 contract change declared in `docs/goal-ciso-grade.md`:
  resolve the finding's own first evidence reference (the same source used for
  `where`) to its surface metadata, use that runtime/kind to choose the
  same-runtime enforced config surface, and render one deterministic fix line for
  that `(family, runtime)` pair. Claude evidence names Claude settings, Codex
  evidence names Codex config/requirements, Gemini evidence names Gemini
  settings, and MCP package-launch findings name the actual MCP source file. If
  the evidence runtime has no known enforced fix surface, render a family-generic
  line that names the evidence source; never name another runtime's config and
  never suggest `.ariadne/*` declarations.
- `related_capabilities`: observed trade-off candidates consumed by this finding's
  exposed path. Each entry carries the capability `id`, `kind`, `runtime` when
  known, `source`, and deterministic `summary`.
- Attested-only controls related to the finding are listed as
  `attested_only` (visible, non-closing).

Declared contract change from `docs/goal-ciso-grade.md`, Phase 1 "Bucket
completeness": every observed trade-off candidate lands in exactly one readout
bucket. A candidate is either owned by one reckless finding as
`related_capabilities`, or it renders as a TRADE-OFF line. It is never both, and
it is not dropped merely because a matching exposure family is reckless.

Consumption is graph/evidence-derived, not family-name-derived. Capability
candidates are keyed by `kind`, stable capability `id`, `runtime` when the
inventory has one, and `source`. A capability is consumed only when a reckless
finding's exposed path actually uses that exact candidate:
- Authority candidates are consumed by a matching evidence ref, or by a path
  edge `runtime:<runtime>|has_authority|authority:<id>` for the same runtime.
  Generic reachability edges such as
  `authority:file-read|reaches|boundary:secret-like-file` do not consume a
  different file-read authority instance from another source.
- Tool and boundary candidates are consumed when a path evidence ref, path node,
  or path edge names the same tool or boundary ID.
- If multiple reckless findings consume the same candidate, the first finding in
  reckless readout order owns it; later findings do not repeat it.

**TRADE-OFFS** — observed candidates not consumed by any reckless finding's
exposed path:
- Home-scope-only influence default judgments → a trade-off line naming the
  affected exposure family:
  - data egress: "your own home config can steer agents that reach the network
    — held as a trade-off by default; see default_judgments to override".
  - secret/file access: "your own home config can steer agents that read local
    files — held as a trade-off by default; see default_judgments to override".
- `authority:external-communication` → "an agent can reach the network — normal
  for installs and web lookups".
- `authority:file-read` → "agents read your workspace — that is what a coding
  agent is for".
- `boundary:agent-private-context` → "agent chat/history is stored locally".
- `tool:mcp-package-launch` present with enforced `control:mcp-reviewed-pinned` →
  "MCP tools configured and pinned".
One line per distinct rendered capability statement, id `tradeoff:N`, with
`source` in JSON. If multiple observed candidates render the same trade-off line,
the readout shows it once and `source` keeps every contributing source as a
deterministic `; `-separated list.

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
  "influence_provenance": [
    {
      "id": "fact:gemini:gemini-md:...",
      "trust_input_id": "trustinput:repo-instruction",
      "provenance": "repo_checkout",
      "source": "checkout/GEMINI.md",
      "summary": "Trust input provenance derived from deterministic surface scope and arrival path."
    }
  ],
  "default_judgments": [],
  "reckless": [
    {
      "id": "reckless:1",
      "exposure_id": "data-egress-chain",
      "title": "...",
      "where": { "source": ".claude/settings.json", "line": 4 },
      "evidence_refs": [
        { "source": ".claude/settings.json", "line_start": 4, "line_end": 4, "summary": "..." },
        { "source": ".env", "anchor": "file", "summary": "Secret-like boundary exists; values are not included in reports." }
      ],
      "why": "...",
      "fix": "...",
      "related_capabilities": [
        {
          "id": "authority:external-communication",
          "kind": "authority",
          "runtime": "claude",
          "source": ".claude/settings.json",
          "summary": "Claude Code settings allow web, shell, or external communication posture."
        }
      ],
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

When the home-scope influence default applies, `default_judgments` contains one
entry per affected exposure family with `rule:
home_scope_influence_not_untrusted_by_default`, `label: default_judgment`,
`trust_input_ids`, and `basis` refs for the weighed `fact` and `trust_input` IDs.

## Fleet scan output (`schema/ariadne-scan-v1.schema.json`)

`scan --targets` aggregates the per-target verdicts; it does not introduce a
second endpoint report format.

- `--format jsonl`: newline-delimited `ariadne.verdict/v1`, exactly one complete
  verdict object per completed target. If any target failed and lacks a verdict,
  JSONL rendering fails instead of silently dropping the target.
- `--format json`: one `ariadne.report/v1` scan document with `fleet` plus
  `targets[].verdict` objects. Consolidation: the previous public
  `targets[].report` duplication is removed from scan JSON/schema; full reports
  remain internal to the scan run for graph, architecture, and dashboard
  renderers.
- `--format table`: the human fleet summary: verdict-word counts, reckless
  findings grouped by exposure family, and the worst-first target list.

Fleet ordering is deterministic. Verdict counts render in
`reckless`, `tradeoffs_only`, `hardened`, `no_agents_found` order. Reckless
family groups are sorted by family key; each group's affected targets are sorted
by target path. The worst-first target list puts targets with reckless findings
first, orders those by reckless count descending, and breaks all ties by target
path.

Fleet non-gameability is inherited from the endpoint verdict: `hardened` counts
come only from enforced controls already present in `ariadne.verdict/v1`.
Self-declared `.ariadne/*.json` controls may appear under a finding's
`attested_only`, but they never improve verdict counts, hardened counts, family
counts, or worst-first ordering.

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

File-level `where` or evidence refs render as `<source>` without a line suffix;
rendered output must never print `<source>:0`.

Hard cap: the readout must not exceed 40 lines for ≤3 reckless findings. Sections
with zero entries are omitted (except a HARDENED/TRADE-OFFS empty state one-liner
when the verdict is reckless).

## Implementation constraints

- Endpoint verdict logic lives in `internal/verdict`; the fleet rollup also
  aggregates `verdict.Verdict` objects there. Renderers only present already
  built verdicts and rollups.
- Reuse `prove.RunPath` / inventory data; no new collection passes.
- Every grading rule ships with a fixture under `ariadne-prove/testdata/` and a
  test that fails without it.
- `verdict`, `ls`, `show` must work in both repo and endpoint modes.
- Update `scripts/verify-first-run.sh` expectations for the new default format
  (coordinator handles this).
