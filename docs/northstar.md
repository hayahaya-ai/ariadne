# Ariadne North Star

## The product in one sentence

A CISO, IT admin, or developer runs one command and immediately sees how much risk
their AI coding-agent setup (Claude Code, Codex, Cursor, Copilot, MCP, …) is carrying —
with an honest distinction between **reckless** configurations, **normal trade-offs**,
and **hardened** posture.

## The 60-second experience (the front door)

`ariadne self` (or `ariadne assess --path <repo>`) prints **one screen**:

1. What was found: which agents, how many configs read, nothing executed.
2. **Reckless** — the 0–3 things that are genuinely dangerous outliers, each with the
   exact file:line, why it matters in one sentence, and the one-line fix.
3. **Trade-offs** — capabilities that carry risk but are the normal cost of using
   agents (network on for installs, workspace read). Acknowledged, not nagged.
4. **Hardened** — enforced controls working in the user's favor.
5. One next action, and how to rerun.

If the screen doesn't fit in one terminal view, it's wrong. Detail lives behind
`--format table/json/html`, never in the default readout.

## The grading rule (what makes Ariadne opinionated)

Every finding lands in exactly one bucket:

- **Reckless**: high-authority posture + sensitive boundary + no enforced barrier,
  where a safer default exists at near-zero workflow cost (e.g. `bypassPermissions`
  with secrets present; unpinned MCP launcher with home access).
- **Trade-off**: risk that is inherent to the agent being useful. Named, quantified,
  accepted — resurfaced only if the surrounding posture makes it compounding.
- **Hardened**: enforced controls observed (runtime permission semantics, sandbox
  modes, pinned launchers, managed settings).

"Capability alone is not exposure" stays; this adds "exposure alone is not
recklessness — recklessness is exposure a reasonable person would not accept."

## What stays load-bearing under the hood

- Deterministic discovery across all supported runtimes; nothing executed, no secrets read.
- The trifecta chain (untrusted influence + private data + egress) as the risk engine
  behind the verdict.
- **Enforced vs attested evidence** (implemented 2026-07): self-declared `.ariadne/*.json`
  flags can never close a finding; only enforced configuration counts. This is what
  makes the simple screen trustworthy.
- Fact-bound agentic layer: LLM-derived content only via `review-check`, citing fact IDs.

## What is deliberately demoted (frozen, not deleted)

The zero-trust 20-boundary framework, operator case boards, proof plans, closure
receipts, compare loops, multi-artifact bundles, and the three dashboards remain
available behind explicit flags for the enterprise workflow, but receive **no new
investment** until the front door is world-class. No new artifacts, sections, or
policy file types. The `.ariadne/*` policy vocabulary is legacy-attested input, not a
product surface to extend.

## Roadmap

1. **The one-screen readout** — the reckless/trade-off/hardened verdict, mockup-first.
2. **Semantic parsers** — replace keyword matching for Claude/Codex permission
   semantics so the grading is precise (house rule #2).
3. **Fleet view for CISOs** — the same one-screen verdict aggregated across endpoints,
   SIEM-friendly JSON.
4. **Agentic analyst** — LLM triage/explanation on top, fact-bound as always.

## Non-goals

- Executing agents, exploits, or live network tests.
- Compliance-framework sprawl. Ariadne answers "am I being reckless?", not "am I
  ISO-aligned?"
- Any verdict a self-declaration can game.
