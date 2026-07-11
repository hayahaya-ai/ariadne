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

## Phase 5 — Correctness hardening (composition, target integrity, unknowns)

Phase 5 exists because the Phase 0–4 benchmark passed while a load-bearing false
negative remained: one pinned MCP launcher anywhere in a target could protect an
unrelated unpinned launcher. The existing eval measured the worlds its builders
expected; it did not measure mixed safe/unsafe composition. **A green pre-Phase-5
`make eval` is the baseline, not this phase's stop condition.**

Work is ordered. Do not implement the composition fix until the new benchmark has
demonstrated the current failure.

### Gate A — Grow the benchmark and prove red

Add the mixed-world fixtures and expectations first, run them against the current
implementation, and record the mismatches in `docs/goal-progress.md`. The required
unsafe worlds are:

1. **One pinned plus one unpinned MCP launcher in one target.** The unpinned
   occurrence keeps `mutable-tool-launch-execution` exposed and the target reckless;
   a pin attached to another server, source, runtime, or subtree cannot protect it.
2. **Root-risky plus nested-safe.** A control in a nested fixture/example/runtime
   config cannot close a root-scoped exposure path it does not govern.
3. **Safe Claude plus unsafe Codex authority.** A Claude control cannot protect a
   Codex authority path merely because both normalize to the same family-level
   control or authority ID.

Every unsafe composition world ships with a minimal inverse of the same shape:

- all MCP launcher occurrences are genuinely pinned;
- the relevant control is attached to the same root/runtime/scope path it protects;
- both runtime paths are genuinely safe.

The inverse must retain the irrelevant noise and differ only in the relationship
being tested. It prevents a false-negative fix from overcorrecting into a false
positive. Expected inverse verdicts follow the facts (`tradeoffs_only`, `hardened`,
or another explicitly justified non-reckless word); do not hard-code one universal
"safe" word.

The first Phase 5 eval is required to be red in the unsafe worlds and green in their
already-safe inverses. A clean run before the current false negative is observed
means the new expectations are too weak. The red run may occur within the same
branch/PR as the eventual fix, but it must be captured before implementation; main
and release tags do not intentionally ship a broken benchmark.

### Gate B — Make protection occurrence- and path-aware

The load-bearing architecture rule is:

> Every trust input, runtime/config, authority, tool, control, and boundary that can
> participate in an exposure carries occurrence-level identity (at minimum source,
> runtime, and structural scope; server/workflow/config identity where applicable).
> Protection counts only when it lies on the same connected path as the occurrence
> it restricts.

Consequences:

- Family IDs classify results; they are never join keys for deciding that a control
  protects a path.
- `any control with this ID exists` is not a valid hard-barrier test.
- One pinned launcher does not protect another launcher. One deny rule does not
  protect another runtime or scope. One network restriction does not break an
  unrelated egress path.
- Collection must not collapse distinct occurrences before evaluation. Reports may
  group them only after path decisions are complete and must preserve their source
  identities as evidence.
- No fixture-name/path detection, new per-family exception, family-ID matching, or
  post-hoc verdict downgrade may substitute for connected-path evaluation.
- Existing scope judgments remain labeled judgments. They cannot repair missing
  occurrence identity in the deterministic graph.

Done when every unsafe/inverse pair from Gate A passes and a direct regression test
proves that adding an unrelated safe occurrence cannot improve an existing unsafe
occurrence's exposure status or verdict.

### Gate C — Make explicit and fleet targets trustworthy

Target resolution is part of the security result, not CLI plumbing:

- An explicit target that is missing, not a directory, or cannot be enumerated is a
  runtime error for single-target commands. It never becomes `no_agents_found`.
- A bad fleet target is recorded as an error, not completed, and is excluded from
  verdict counts. Fleet output must expose the error count and target identity;
  JSONL continues to fail rather than silently omit errored targets.
- Explicit endpoint targets are scanned exactly as supplied. They never fall back
  to the collector's `HOME`. Home fallback is allowed only for `ariadne self` (or an
  equivalent endpoint command) when the user supplied no path.
- A readable target with genuinely no supported runtime evidence may still be
  `no_agents_found`; target failure and absence of agents are distinct states.

These behaviors require CLI and fleet contract tests in addition to Story Lab
worlds. `make eval` does not absorb tests that belong in Go/CLI contracts merely to
create one convenient stop command.

### Gate D — Represent inconclusive posture honestly

Missing or unparseable evidence cannot produce `hardened`, and a run with unresolved
exposure evidence cannot say `no action needed`.

- Add a first-class `inconclusive` verdict for a scanned target whose runtime exists
  but whose supported posture cannot be determined safely (including load-bearing
  parse failure or incomplete evidence needed by the verdict).
- `inconclusive` is distinct from `no_agents_found`, `tradeoffs_only`, `hardened`,
  `reckless`, and target/runtime error.
- `--gate` fails closed on `inconclusive` with documented non-zero behavior; fleet
  rollups count it explicitly and rank it ahead of clean/non-agent states but below
  confirmed reckless targets.
- `next_action` names the evidence or parse gap to resolve. It never says
  `no action needed` while `inconclusive > 0` or a load-bearing parser failed.
- Parser success/failure and relevant limitations are deterministic facts carried
  into the verdict; absence of parsed authority is not treated as evidence that the
  authority is absent.

`ariadne.verdict/v1` was declared frozen in Phase 2. Do not silently widen its enum
or change gate semantics under the same contract. Phase 5 must define and document
a versioned verdict migration (normally `ariadne.verdict/v2`), update schemas and
fleet consumers together, and make compatibility behavior explicit before the new
word becomes the default.

Required unknown/error worlds and contract tests:

- malformed supported runtime config;
- recognized but unreadable load-bearing config;
- missing explicit repository target;
- missing/unreadable fleet target;
- explicit endpoint snapshot with no recognized marker (scan it exactly; do not
  scan the collector home);
- genuinely readable target with no agents (inverse: remains `no_agents_found`).

### Phase 5 completion bar

Phase 5 passes only when all of the following are true:

1. The pre-fix red run is recorded, including the pinned-plus-unpinned reproduction.
2. Every required unsafe composition fixture and its inverse passes.
3. Missing/unreadable explicit and fleet targets follow Gate C.
4. Inconclusive configuration follows Gate D and cannot render `hardened` or
   `no action needed`.
5. `make eval` exits 0 on the expanded benchmark with 100% verdict-word accuracy
   and 100% precision/recall for every measured exposure family.
6. `make check`, `make verify-first-run`, and the race-enabled Go suite pass; schema
   and CLI/fleet contract tests pass for the versioned verdict migration.
7. A repository-level regression proves that controls from testdata, examples, or
   a disjoint subtree cannot protect unrelated production/root paths.

Do not start Phase 6/product expansion from a merely green legacy eval. The Phase 5
fixture matrix and contract tests are the new measuring instrument.

## Phase 5.1 — Release-candidate field calibration closure

**Status: passed on 2026-07-10.** Required RED was recorded at 50/57 before
production changes; GREEN is 57/57 with 100% precision/recall for every
supported family. The exact eight-repository resweep completed 8/8 with no
errors, parser failures, reckless verdicts, or inaccurate egress remedies. See
`docs/calibration/v0.2.0-rc.2-candidate-public-sweep.md`.

The first `v0.2.0-rc.1` public sweep scanned eight pinned public repositories
(18,494 tracked files) without executing their code. The deterministic fleet run
completed 8/8 targets, but source review found correctness worlds absent from the
50-fixture benchmark. Stable `v0.2.0` and Phase 6 remain blocked until these worlds
are represented red-first and corrected.

The source-of-truth audit is
`docs/calibration/v0.2.0-rc.1-public-sweep.md`. Public repository results are
calibration evidence, not vulnerability claims about those projects.

### Gate E — Runtime discovery must be evidence-sensitive

A generic editor file is not an agent runtime merely because its path can host
agent settings.

- `.vscode/settings.json` creates Copilot runtime evidence only when a supported
  Copilot/chat-agent key is present.
- Dedicated Copilot instruction and MCP surfaces remain runtime evidence.
- The paired worlds are generic VS Code settings (no Copilot runtime) and an
  actual supported Copilot setting (Copilot runtime remains discoverable).
- Parser status may retain the discovered surface, but must not falsely name a
  runtime whose supported keys were absent.

### Gate F — Valid supported syntax is not malformed

Fail-closed parsing applies to malformed configuration, not to valid syntax the
collector happened not to anticipate.

- GitHub workflow YAML accepts balanced flow lists/maps that span lines.
- Unterminated or structurally invalid flow collections remain malformed and
  produce `inconclusive`.
- The valid and invalid documents ship as a paired inverse and as parser unit
  tests; merely weakening validation for every bracket is not acceptable.

### Gate G — Influence, authority, and boundary semantics stay connected

- `CLAUDE.md` influence applies to Claude; `AGENTS.md` applies to Codex-compatible
  agent execution; Copilot instructions apply to Copilot. These instruction
  surfaces do not influence ordinary GitHub Actions or GitLab CI merely because a
  workflow reads repository files.
- A managed workflow trigger enters the prompt-injection family only when that
  same workflow is actually agent-like. Deterministic issue/label automation is
  not an LLM prompt path.
- Repository/PR/issue write authority is an integrity boundary, not private-data
  read authority. It cannot satisfy the private-data leg of the data-egress family.
- Secret/OIDC/credential access plus same-workflow external communication remains
  a valid unsafe inverse and must stay reckless.
- Mutable privileged action/workflow references are a supply-chain posture. If
  Ariadne cannot yet grade them under an accurate family and pinning remedy, it
  must not mislabel them as proven private-data exfiltration.

### Gate H — `hardened` requires enforced evidence

Approved product rule:

- `hardened` requires at least one observed enforced control in `hardened[]`.
- If a supported runtime exists, no reckless or trade-off evidence exists, no
  enforced hardened control exists, and posture evidence remains unresolved, the
  verdict is `inconclusive`; `--gate` exits 3.
- If no supported runtime exists, the verdict remains `no_agents_found`.
- A runtime with a real enforced control remains the paired `hardened` inverse.
- No renderer, fleet rollup, or JSON contract may emit `hardened` with
  `hardened.length == 0`.

### Phase 5.1 paired matrix

The complete matrix is added before production changes:

1. generic VS Code settings / supported Copilot settings;
2. valid multiline workflow flow-sequence / unterminated flow-sequence;
3. risky AGENTS plus ordinary CI / matching agent runtime with the same risky
   instructions and authority;
4. deterministic managed workflow with issue/PR write authority / agent-like
   workflow with same-source secret access;
5. repository-integrity write authority / credential-access plus egress;
6. runtime with unresolved posture and zero controls / runtime with an enforced
   control.

Every safe world must avoid a reckless finding; every unsafe inverse must retain
the intended family, source, and line. Existing Phase 5 inverses may satisfy a pair
only when their contract asserts the same semantic distinction explicitly.

### Phase 5.1 completion bar

Phase 5.1 passes only when:

1. The expanded matrix is recorded red before production changes.
2. All paired worlds pass without weakening the Phase 5 unsafe composition cases.
3. `hardened` is impossible with zero hardened controls in unit, CLI, fleet, and
   real release-binary output.
4. Valid multiline GitHub workflow YAML parses while its malformed inverse fails
   closed.
5. Agent instructions cannot borrow ordinary CI authority, and deterministic
   managed workflows cannot enter the prompt-injection family without agent-like
   execution evidence.
6. Repository-write authority cannot satisfy the private-data leg; explicit
   credential/OIDC/secret access remains detectable.
7. `make eval` returns 100% verdict accuracy and per-family precision/recall on
   the expanded benchmark; `make check`, `make verify-first-run`, race tests,
   schema validation, CI self-gate, and fleet contracts pass.
8. The exact eight pinned public targets are rescanned. Every confirmed false
   positive/inconclusive from the first sweep is gone, the two mutable privileged
   workflow references receive no inaccurate data-egress remedy, and no audited
   unsafe inverse regresses.

## Loop guardrails (beyond CLAUDE.md)

1. **Never special-case the eval.** No detection code may branch on fixture names,
   paths, or any signature of the benchmark. Passing the eval by recognizing the
   eval is a failure, full stop.
2. **Every new expectation ships with an adversarial twin.** For composition work,
   this is a paired inverse: safe-hides-unsafe must remain unsafe, while the same
   world with every occurrence genuinely controlled must remain non-reckless. For a
   new detector, include the negative fixture the naive implementation would
   misfire on.
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

**Phase 5 bootstrap override:** its first iteration adds the complete Gate A paired
fixture matrix before changing evaluation code, then runs and records the required
red scorecard. Subsequent iterations fix the top mismatch in the declared phase
order: occurrence/path composition first, target integrity second, inconclusive
semantics and versioned contract migration third. A green scorecard before Gate A
has visibly failed is a harness failure, not phase completion.
