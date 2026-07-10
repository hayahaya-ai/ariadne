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
ariadne review-packet --path P [--profile follow-up|inventory-blind] [--packet-out request.json]
ariadne review-check --packet request.json --review review.json [--format summary|json]
ariadne review-run --path P --command "reviewer-command" [--dir D] [--format summary|json]
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
Each trust input also carries deterministic `instruction_scope`: `root` for a
file at the assessment root or in a runtime-owned root config location (such as
`.claude/`, `.codex/`, or `.gemini/`), `nested` for a subtree instruction, and
`unknown` only when the assessment-relative location cannot be derived. Runtime
config locations count as root because the runtime loads them independently of
working inside a matching subtree. Scope classification never skips collection.
Authority-bearing local agent and MCP config surfaces carry the parallel
deterministic `authority_scope` fact (`root`, `nested`, or `unknown`) plus
`scope_subtree`, the first assessment-relative path component for nested
surfaces. The same fields are copied onto authorities emitted from those
surfaces. This is structural location only: it does not claim that a nested
config is safe, and managed CI workflow execution is not relabeled as local
agent-config authority.

**RECKLESS** — one finding per effectively exposed `ExposureResult`, ordered:
data-egress-chain first, then prompt-injection-to-secret-canary, then
mutable-tool-launch-execution. An exposed data-egress-chain or
prompt-injection-to-secret-canary path is not effectively exposed when every
risky trust-input leg has provenance `home_scope`; that default judgment is
recorded in verdict JSON and the capability is rendered under TRADE-OFFS
instead. Otherwise, when every risky non-home influence leg has
`instruction_scope: nested`, the path is held as a trade-off by the labeled
`nested_instructions_scoped_by_default` judgment. Nested instructions become
live influence for agents that work inside those directories. Any root or
unknown-scope non-home leg, or no risky trust-input leg, keeps the exposed path
reckless unless the complete authority context needed by that exposed family
exists only in nested local-agent/MCP config scope outside the active influence
subtree. That case uses the labeled
`nested_authority_scoped_by_default` judgment and cites both the influence facts
and authority-surface facts. A complete root or unknown-scope authority context
keeps the path reckless. Boundary location never triggers this downgrade: root
influence plus root authority plus a nested `.env` remains reckless because a
root agent can read the workspace. Each finding carries:
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
- Nested-instruction scoped default judgments → a trade-off line naming the
  affected exposure family and stating that the instructions become live
  influence when agents work inside those directories.
- Nested-authority scoped default judgments → a trade-off line naming the
  affected authority leg and stating that nested agent configs become live when
  an agent runs inside that directory.
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
else any runtime found → `hardened` (with or without enforced controls); else →
`no_agents_found`. Enforced controls observed without a runtime remain listed under
HARDENED but do not supply the verdict word. Inconclusive exposures add one line
under the readout:
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
      "instruction_scope": "root",
      "scope_subtree": "",
      "source": "checkout/GEMINI.md",
      "summary": "Trust input provenance and instruction scope derived from deterministic surface location and arrival path."
    }
  ],
  "authority_scope": [
    {
      "id": "fact:mcp:mcp-config:...",
      "authority_ids": ["authority:broad-local", "authority:file-read"],
      "runtime": "",
      "authority_scope": "nested",
      "scope_subtree": "fixtures",
      "source": "fixtures/world/mcp.json",
      "summary": "Authority scope derived from deterministic agent-config surface location."
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
When the nested-instruction default applies, the same shape uses `rule:
nested_instructions_scoped_by_default`; its basis cites only the risky non-home
trust inputs and their deterministic provenance/scope facts, and its summary
states that the instructions become live for agents working in those
directories.
When the scoped-authority default applies, the rule is
`nested_authority_scoped_by_default`; its basis additionally cites entries from
`authority_scope`, and its summary and TRADE-OFF line state that nested agent
configs become live when an agent runs inside that directory. Root authority
and boundary nesting are deliberately asymmetric: root authority prevents this
judgment, while a nested boundary alone never causes it.

## Verdict-aware analyst review

LLM or agent analysis is an interpretation layer, never evidence. The ingestible
path is the existing `review-packet` -> reviewer -> `review-check` path. The
`follow-up` profile is verdict-aware; no third profile is added.

Workflow:

```
ariadne review-run --path <target> --command "your-reviewer" --dir ariadne-review
```

`review-run` writes `llm-request.json`, sends exactly that JSON to the supplied
local command on stdin, saves the raw `llm-review.json`, and runs
`review-check`. Ariadne does not call remote LLM services by itself. Teams that
run their own reviewer manually can use:

```
ariadne review-packet --path <target> --profile follow-up --packet-out request.json
your-reviewer < request.json > review.json
ariadne review-check --packet request.json --review review.json
ariadne prove --path <target> --interpret llm --llm-review review.json --format json
```

The follow-up packet (`schema/ariadne-llm-review-request-v1.schema.json`) includes
the deterministic graph/exposure facts plus a compact verdict context:
`verdict.reckless[]` (`id`, `exposure_id`, `where`, evidence ref IDs, why/fix),
`default_judgments[]` (`id`, `rule`, `exposure_id`, `basis`),
`influence_provenance[]`, `tradeoffs[]`, and a citation catalog with valid fact,
finding, default-judgment, evidence-ref, graph-edge, and trade-off IDs.

The accepted review response (`schema/ariadne-llm-review-v1.schema.json`) may
only contain:

- `finding_explanations[]`: explain each existing reckless finding in operator
  context, citing packet fact IDs, evidence ref IDs, or graph edges.
- `finding_ranking[]`: rank each existing reckless finding exactly once with a
  one-line rationale and citations.
- `default_judgment_overrides[]`: optionally propose overriding an existing
  `default_judgments[].rule` for an existing `exposure_id`, citing that
  judgment's basis fact IDs and giving a reason.

`review-check` rejects unsupported IDs, unsupported graph edges, missing coverage
of reckless findings, non-basis facts in an override, `issues[]`/new findings,
attempts to close/remove/suppress findings, and any attempt to set or flip the
deterministic verdict word.

When a review passes, `prove --interpret llm --llm-review <file>` carries the
validated content only under `interpretation.analyst` with `source_type:
llm_review`, `derived_by: llm`, `review_source`, and `request_digest`. It does not
change `verdict`, `reckless`, `tradeoffs`, `hardened`, issue summaries, exposure
facts, buckets, fleet counts, or any closure state.

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
