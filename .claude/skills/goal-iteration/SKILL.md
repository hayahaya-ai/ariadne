---
name: goal-iteration
description: Run one iteration of the CISO-grade goal loop from docs/goal-ciso-grade.md — pick the top gap, delegate implementation to Codex (GPT-5.5 xhigh), independently verify with the full Ariadne bar, and log progress. Use when the user runs /goal-iteration (or a built-in /goal loop drives iterations) or asks to advance the CISO-grade roadmap. Optional argument — a focus hint (e.g. "phase 0" or a specific scorecard mismatch).
---

# /goal-iteration — one iteration of the CISO-grade loop

Two roles, never merged: **Codex** (GPT-5.5 at xhigh reasoning, via `codex exec`)
is the implementation workhorse. **You (Claude)** are the planner and the judge.
The workhorse never grades its own work; you never skip the judging step.

Read `docs/goal-ciso-grade.md` first — its phase bars and loop guardrails govern
every step below. `CLAUDE.md` house rules apply throughout.

## 1. Orient

- Read `docs/goal-ciso-grade.md` and `docs/goal-progress.md` (create the latter
  with a `# Goal progress` header if missing).
- Determine the active phase. If a `make eval` target exists, run it and capture
  the scorecard (non-zero exit with a printed scorecard is the work queue, not an
  error). If it does not exist, the work item is Phase 0 — building it by
  extending Story Lab (`ariadne-prove/internal/storylab`), never a parallel
  harness.
- Pick **exactly one** work item: the user's focus argument if given; else the top
  scorecard mismatch (false reckless > missed reckless > anchor/fix wrongness >
  ranking); else the next unmet item of the current phase bar.

## 2. Delegate to the workhorse

- Write a self-contained work packet to the scratchpad containing: the one work
  item; the phase bar it serves (quoted from the brief); relevant file paths; the
  loop guardrails 1–5 from the brief quoted verbatim plus a pointer to `CLAUDE.md`
  house rules; and the iteration's definition of done (failing fixture or
  expectation first, then the implementation that makes it pass). Forbid edits to
  `docs/goal-*.md`, and require any change to existing test expectations to be
  called out explicitly in the final summary with the reason.
- Launch from the repo root as a background Bash task and monitor it:

  ```bash
  codex exec --sandbox workspace-write -m gpt-5.6-sol -c model_reasoning_effort=xhigh \
    "$(cat <packet-path>)" > <scratchpad>/goal-iter-<n>.log 2>&1
  ```

  Pin the model and effort explicitly as above (user-chosen 2026-07-09; needs
  codex-cli ≥ 0.144.0) — `~/.codex/config.toml` drifts (apps rewrite it) and has
  already broken a run once (unsupported model, silent effort downgrade to
  medium). Change the pin only deliberately, never by inheriting config drift.
  This Bash call needs the harness sandbox disabled
  (Codex manages its own workspace-write sandbox and needs network for its API);
  the final answer is at the end of the log after `codex` output markers.

## 3. Judge (never skip, never delegate)

- Read the actual diff (`git status` + `git diff`), not the workhorse's summary.
- Guardrail sweep: no fixture-name/path special-casing in detection code; no
  silently weakened expectations; no new `expect_contains` lines in
  `verify-first-run.sh` for new behavior; no `strings.Contains` security checks;
  fixture present for every detection change; schema + docs updated in the same
  change for output-shape changes; zero new external dependencies.
- Run the full bar yourself, in order, quoting real output in your report:
  1. `make build`
  2. `cd ariadne-prove && GOCACHE=/private/tmp/ariadne-prove-gocache go test ./...`
  3. `make verify-first-run`
  4. `make eval` (once it exists)
  Use the `verify-ariadne` skill where available — it wraps this same bar.
- On failure: send Codex exactly one repair round with the verbatim failing
  output. If it fails again, revert the working tree (`git checkout -- .` plus
  removing new untracked files from the attempt), and record the dead end in the
  progress log so the next iteration doesn't repeat it.

## 4. Log and report

- Append one line to `docs/goal-progress.md`:
  `YYYY-MM-DD · <work item> · <scorecard delta or "harness: N expectations, M mismatches"> · <verified|reverted>`.
- Report to the user: what moved, the real verification output (not a paraphrase),
  the scorecard delta, and the next top gap.
- Stop and say so plainly when a phase bar passes, or after two consecutive
  iterations with no scorecard improvement — do not keep looping past either.
