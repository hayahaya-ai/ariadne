# Zero Trust Agent Architecture

Ariadne maps local agent setups against a Zero Trust architecture model for AI agents.

The goal is not to certify that an environment is safe. The goal is to expose where the architecture is breaking, controlled, unknown, or not observed from deterministic evidence.

## Core Question

> Where can untrusted influence, agent authority, sensitive boundaries, missing controls, weak identity, persistent context, or missing observability combine into exposure?

## Status Vocabulary

- `breaking`: Ariadne found a graph-backed path or missing break-path control.
- `controlled`: Ariadne found a control edge that breaks a supported path.
- `unknown`: Ariadne found relevant surfaces, but not enough evidence to prove or clear the architecture boundary.
- `not_observed`: Ariadne did not observe supported evidence for that boundary.

## Architecture Boundaries

Ariadne currently evaluates these Zero Trust checks:

- Influence boundary: whether untrusted instructions can steer an agent runtime.
- Authority boundary: whether agent authority is scoped to least agency.
- Sensitive data boundary: whether authority reaches secrets, private context, or external destinations.
- Tool and MCP boundary: whether model-callable tools can expand capability through mutable launch paths.
- Memory and context boundary: whether persisted context can be reached or needs isolation evidence.
- Agent identity boundary: whether Ariadne observed evidence for scoped agent identity, short-lived credentials, or JIT access.
- Observability boundary: whether Ariadne observed enough evidence to reconstruct agent actions and approvals.
- Control boundary: whether controls remove a path or only add friction.

## Design Test

Every check uses the same design test:

> Does the control remove the capability or path, or does it merely make the attack tedious?

Examples of controls Ariadne can model today:

- deny-read rules for secret-like paths
- network restrictions for external destinations
- reviewed or pinned MCP server launchers
- managed runtime settings surfaces
- approval-required posture
- sandbox or filesystem isolation posture
- credential helper or vault-backed credential retrieval
- short-lived or federated credential posture
- audit, tool-call, approval, or telemetry logging declarations
- memory, transcript, or context retention declarations

Examples Ariadne reports as `unknown` today:

- JIT access
- ABAC
- tamper-resistant audit logs
- live behavioral telemetry

Examples Ariadne reports as `breaking` when observed:

- inline credential field indicators in agent configuration
- authority paths that reach private context without an observed break-path control

## Local Policy File

Repositories can declare Zero Trust agent controls in `.ariadne/agent-policy.json`.

Example:

```json
{
  "approval_required": true,
  "sandbox_required": true,
  "credential_helper": "vault",
  "short_lived_credentials": true,
  "audit_logging": true,
  "tool_call_logging": true,
  "context_retention": {
    "retention_days": 7
  }
}
```

The policy is treated as declared evidence. Ariadne does not execute the policy or prove live enforcement.

## Evidence Contract

Zero Trust checks are emitted under `zero_trust` in `prove` JSON and rendered in the local dashboard.

Each check includes:

- Zero Trust principle
- architecture boundary
- status
- design test
- finding
- evidence references
- graph edges
- controls
- actions
- limitations

The `coverage` object turns unknowns into a collector roadmap:

- `known`: checks with `breaking` or `controlled` status
- `gaps`: checks that are `unknown` or `not_observed`
- `gap_details`: missing evidence, why it matters, and the next collector Ariadne needs

Ariadne should only call a boundary `breaking` when facts and graph edges support the claim.
