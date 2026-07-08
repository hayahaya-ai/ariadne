# Ariadne — agent instructions

Deterministic exposure analysis for local AI agent runtimes. Active implementation is in
`ariadne-prove/`. Product direction and the quality bar live in `docs/northstar.md` —
read it before making product decisions.

## Build and verify

```bash
make build                 # builds ./bin/ariadne
make verify-first-run      # product verification loop against fixtures
cd ariadne-prove && GOCACHE=/private/tmp/ariadne-prove-gocache go test ./...
```

Every change must pass all three before it is reported as done.

## House rules (non-negotiable)

1. **No gameable verdicts.** A self-declared `.ariadne/*.json` flag is `attested`
   evidence, never `proven`. Do not add code paths that let a declaration close a case
   as if it were an enforced control.
2. **No substring security checks.** New control/authority detection must parse the
   actual config structure of the surface (JSON/TOML/YAML semantics), not
   `strings.Contains`. When touching existing substring checks, upgrade them.
3. **Every detection change ships with a fixture** under `ariadne-prove/testdata/` and a
   story-lab expectation or unit test that would fail without the change.
4. **Fact-bound agentic layer.** LLM-derived content may only enter reports through the
   `review-check` validation path, referencing existing fact IDs and graph edges.
5. **Fight sprawl.** No new bundle artifact, report section, or output format without
   consolidating or removing one. Prefer sharpening an existing output.
6. **Schema discipline.** Output shape changes require updating the JSON schema in
   `ariadne-prove/schema/` and the docs in the same commit.
7. **Match existing style.** Zero external dependencies stays zero. Follow existing
   package layout: surface → adapter → prove → zerotrust → report.

## Self-verification

Use the `verify-ariadne` skill before declaring any task complete.
