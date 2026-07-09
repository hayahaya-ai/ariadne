# Goal: CISO-grade Ariadne

Operating brief for autonomous work sessions (`/goal`, `/loop`, or plain prompts).
Read `docs/northstar.md` first; it defines the product. `CLAUDE.md` house rules apply
verbatim and are not restated here. This doc adds the destination, the loop-specific
guardrails, and the measurable bar for "done."

## The goal (destination, not next step)

A CISO can deploy Ariadne across a developer fleet and trust the verdict enough to
act on it: page someone on `reckless`, gate CI on it, report posture to the board
from it. That trust is earned bottom-up — a verdict is fleet-trustworthy only if
every single-endpoint finding is undeniable to the developer who owns the machine.

Work is phase-gated. **Do not start a phase until the previous phase's bar passes.**

## Facts vs judgment (binding design principle, 2026-07-08)

Ariadne's primary user is an agent deciding what to do next. Serve that user by
keeping the two layers separate:

- **Facts are deterministic, always.** Discovery, parsing, anchors, provenance,
  enforcement status. A fact bug (wrong line, wrong surface) is fixed with
  deterministic code, full stop.
- **Judgments are layered.** Where a call is mechanical (an exposed path with no
  enforced barrier), determinism decides. Where a call is interpretative (does
  home-scope influence count as untrusted?), determinism supplies the *facts* plus
  a **labeled default judgment**, and the verdict JSON carries the judgment's basis
  (the fact IDs it weighed) so a consuming agent can re-derive or override it.
  Interpretative opinions must never be buried in detection code as if they were
  facts — in either direction.
- The gateable verdict word stays deterministic (a CI gate cannot be stochastic);
  the agentic layer (Phase 4) adds interpretation on top, fact-bound as always.

## Contract changes this brief declares

Two Phase 1 bars intentionally supersede the current `docs/cli-contract.md`
(verified against code, 2026-07-08):

1. **Evidence-derived fixes** replace the contract's "canonical fixes per family"
   (`cli-contract.md`, Grading rules). Today `recklessFix` in
   `internal/verdict/verdict.go` switches on exposure family and ignores the
   evidence surface, so a gemini-evidenced finding gets a Claude/Codex fix.
2. **Bucket completeness** replaces the contract's trade-off suppression rule.
   Today `buildTradeoffs` drops any capability whose exposure family is exposed,
   so a fully-exposed machine renders an empty TRADE-OFFS section.

Whichever change lands first must update `docs/cli-contract.md` in the same commit
(house rule 6 applies to contract docs, not just schemas). Until then, the contract
text is the documented status quo, not a defense against these bars.

## Phase 0 — Build the measuring instrument (`make eval`)

The current verification (`scripts/verify-first-run.sh`, 1,412 lines) is mostly
`grep -F` contains/not-contains assertions plus line-count, ordering, file-existence,
and exit-code checks. It protects existing output shapes; it never parses verdict
JSON to check that a finding's `where.source`/`where.line` is correct, that the fix
targets the evidence surface, or that a hardened profile stays green. A loop pointed
at a string bar optimizes string matching. So first, build the eval:

- **Extend Story Lab; do not build a parallel harness.** The repo already has
  deterministic fixture worlds and expectation comparison
  (`ariadne-prove/internal/storylab`, story runs in `internal/prove`). Add verdict
  expectations to that machinery: expected verdict word and, per expected finding,
  exposure family, evidence source file, exact line, and the surface the fix must
  target. A separate `testdata/eval/` tree with its own runner is a house-rule-5
  violation.
- **Adversarial negatives are first-class.** Seeds already exist — the
  keyword-in-string, deny-not-allow, commented-network, and secret-in-allow fixtures
  and their tests in `internal/prove/prove_test.go` — but they assert graph/parser
  behavior, not verdict output. Lift them into verdict-level expectations and add
  the missing ones (user-authored home instructions, hardened profiles) asserting
  what must NOT fire.
- **Scorer and exit semantics.** `make eval` prints a scorecard — per-family
  precision and recall, verdict-word accuracy, every mismatch with fixture path —
  and exits 0 only when the scorecard is clean. **A non-zero exit with a printed
  scorecard is the loop's work queue, not a blocked run**; a non-zero exit without
  a scorecard is a harness bug. Zero external dependencies, like everything else.
- Calibration profiles: at minimum `conservative-dev`, `typical-dev`, `reckless-dev`
  endpoint fixtures. `typical-dev` must grade `tradeoffs_only`. If a typical machine
  grades reckless, the word stops changing behavior.

Phase 0 is done when `make eval` runs and honestly reports today's failures — the
first clean run before any Phase 1 work means the benchmark is too soft, because
the known defects below are confirmed in code and must be encoded as committed
failing expectations (they are anecdotes until then):

- line-0 anchors: `buildRecklessFinding` copies `LineStart` unchecked
  (`internal/verdict/verdict.go`), `withEvidenceLocation` can return line 0
  (`internal/prove/prove.go`);
- family-canonical fixes that contradict the evidence surface (`recklessFix`);
- empty TRADE-OFFS on exposed targets (`buildTradeoffs`);
- user-authored home config counted as the untrusted-influence leg (no provenance
  on `TrustInput` in `internal/model/model.go`; `collectInstruction` labels all
  instruction surfaces alike in `internal/adapter/adapter.go`).

## Phase 1 — Undeniable findings (single endpoint)

The bar, measured by `make eval`:

1. **Anchor correctness.** Every reckless finding cites a real file and a real line
   (never `:0`), and the line actually contains the config that creates the risk.
2. **Surface-matched fixes** (contract change, declared above). `where`, `why`, and
   `fix` refer to the same runtime and surface that produced the evidence. A
   gemini-evidenced finding never prescribes a codex fix.
3. **Influence provenance** (facts-vs-judgment split applies). The deterministic
   layer emits a provenance *fact* per trust input — home-scope config vs repo
   checkout content vs third-party package/MCP description. The *default judgment*
   (labeled as such in verdict JSON, citing the provenance fact) is: home-scope
   influence alone does not satisfy the trifecta's "untrusted" leg and appears as a
   trade-off instead. Do not hard-code "user files are safe" as a fact — determinism
   cannot know who wrote a file, only where it lives and how it arrived.
4. **No empty buckets by accident** (contract change, declared above). Every
   observed capability lands in exactly one bucket. If reckless findings exist,
   related capabilities appear inside them; unrelated capabilities still show as
   trade-offs.
5. **Zero false reckless** across all adversarial negatives and the `typical-dev`
   calibration profile.

Done when: `make eval` scores 100% on the benchmark, all existing checks pass
(`make build`, `go test ./...`, `make verify-first-run`), and a human has reviewed
`ariadne self` output on a real machine and found no finding they could laugh off.
That last check is a release gate, not a loop-iteration gate.

## Phase 2 — A verdict you can gate on

- **Determinism:** two consecutive runs on the same target produce byte-identical
  output modulo timestamps. Add a test that proves it.
- **Performance:** endpoint scan of ~2,000 config files completes in under 5 seconds
  on developer hardware; add a benchmark so regressions are visible.
- **Schema stability:** `ariadne.verdict/v1` is frozen; additive changes only, with
  schema + docs in the same commit (house rule 6). Exit codes are contract
  (`docs/cli-contract.md`) and get a test per code.
- **Operational docs:** one page for deploying `ariadne verdict --gate` in CI and one
  for running `self` fleet-wide via MDM — written against real behavior, no promises.

## Phase 3 — Fleet view (the CISO surface)

Only now. Aggregate per-endpoint verdict JSON into one fleet readout: verdict counts,
reckless findings grouped by family across machines, worst-first endpoint list,
SIEM-friendly JSONL. Constraints:

- **Reuse `ariadne.verdict/v1` as the input.** The fleet layer aggregates verdicts;
  it does not invent a new collection pass or a new per-endpoint format.
- Same non-gameability: fleet rollups count only enforced evidence.
- One new output at most, and per house rule 5, consolidate or remove one existing
  artifact in the same change.

## Phase 4 — Agentic analyst

Already scoped by `docs/northstar.md`: LLM triage and explanation on top, fact-bound
through `review-check`, citing fact IDs and graph edges. Nothing new here until
phases 0–3 hold.

## Loop guardrails (beyond CLAUDE.md)

1. **Never special-case the eval.** No detection code may branch on fixture names,
   paths, or any signature of the benchmark. Passing the eval by recognizing the
   eval is a failure, full stop.
2. **Every new expectation ships with an adversarial twin** — a negative fixture the
   naive implementation of the same detector would misfire on.
3. **The scorecard is the bar; string asserts are legacy.** Do not grow
   `verify-first-run.sh` with new `expect_contains` lines for new behavior; encode
   new behavior in `make eval` expectations or Go tests instead.
4. **Builder is not judge.** The agent that wrote the change does not grade it. The
   verification commands are the source of truth (the `verify-ariadne` skill wraps
   them for Claude sessions; agents without that skill run them directly):
   `make build`; `cd ariadne-prove && GOCACHE=/private/tmp/ariadne-prove-gocache
   go test ./...`; `make verify-first-run`; `make eval` once it exists. Report the
   actual scorecard output, not a summary of it. If a step required judgment, quote
   the output that grounded the judgment.
5. **Fixing a scorecard miss by weakening the expectation requires stating so
   explicitly** in the report, with the reason the expectation was wrong. Silent
   expectation edits are gaming.
6. **Decide alone / surface to the user:** parser details, fixture design, ranking
   tweaks, refactors — decide alone. Changing what the verdict word means, adding a
   schema, touching northstar or this doc's bars — surface first.

## Loop protocol

The `/goal-iteration` command (`.claude/skills/goal-iteration/SKILL.md`) runs one iteration: run
`make eval` → pick the top mismatch (false reckless beats missed reckless;
anchor/fix wrongness beats ranking) → write the failing fixture or expectation
first → implement (delegated to the workhorse model) → the judge independently runs
the full verification bar plus `make eval` → append one line to
`docs/goal-progress.md` (date, what moved, scorecard delta).
Stop the loop and report when a phase bar passes or when two consecutive iterations
produce no scorecard improvement.
