---
name: verify-ariadne
description: Verify any Ariadne change end-to-end before declaring it done. Use after every code change to ariadne-prove, before reporting completion, committing, or ending a /goal iteration.
---

# Verifying Ariadne changes

Never report a change as complete based on a successful edit or build alone. Run the
full deterministic bar:

1. **Build**: `make build` from the repo root. Zero errors.
2. **Tests**: `cd ariadne-prove && GOCACHE=/private/tmp/ariadne-prove-gocache go test ./...`
   All packages pass. If you changed adapter/zerotrust/report/surface code that has no
   test coverage, add the test first — untested detection logic fails this check.
3. **Product loop**: `make verify-first-run`. Must pass.
4. **Fixture truth check**: run the binary against the golden fixtures and confirm
   classifications did not silently drift:
   - `./bin/ariadne assess --path ariadne-prove/testdata/realpath/combined-risk` →
     verdict must remain "action required" with exposed paths > 0.
   - `./bin/ariadne assess --path ariadne-prove/testdata/realpath/messy-ai-surfaces --mode endpoint --format action` → must complete without error.
   If your change intentionally alters a fixture verdict, update the story-lab
   expectation in the same change and say so explicitly in your report.
5. **Anti-gaming check** (for any change touching controls, closure, proofs, or cases):
   confirm that applying only a self-declared `.ariadne/*.json` proof patch does NOT
   move a control from missing to `proven`. Declared flags may satisfy `attested` at
   most. If this check cannot pass yet because the enforced/attested split is not
   implemented, state that limitation — do not claim closure semantics are sound.
6. **Schema check** (for any output-shape change): the corresponding schema in
   `ariadne-prove/schema/` and any affected docs were updated in the same change.

If any step fails, fix it and rerun from step 1. Do not hand back partially verified
work, and report the actual command output for any step that required judgment.
