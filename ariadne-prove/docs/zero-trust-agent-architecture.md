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
- scoped runtime permission controls from Claude or Codex settings
- deny-by-default runtime permission posture
- network restrictions for external destinations
- reviewed or pinned MCP server launchers
- managed runtime settings surfaces
- approval-required posture
- sandbox or filesystem isolation posture
- credential helper or vault-backed credential retrieval
- short-lived or federated credential posture
- audit, tool-call, approval, or telemetry logging declarations
- observed structured transcript metadata for tool-call events, approval decisions, request IDs, trace IDs, and timestamped action records
- telemetry export and immutable audit log declarations from observability policy or OpenTelemetry collector config
- memory, transcript, or context retention declarations
- memory isolation, context integrity, and context provenance declarations

Examples Ariadne reports as `unknown` today:

- JIT access
- ABAC
- tamper-resistant audit logs
- live behavioral telemetry

Examples Ariadne reports as `breaking` when observed:

- inline credential field indicators in agent configuration
- authority paths that reach private context without an observed break-path control

## Foundation Maturity

Ariadne also emits a Foundation maturity evidence readout under `zero_trust.maturity`.

This is not a compliance attestation. It is an evidence map for the raised Foundation bar described in Zero Trust agent architecture guidance. Each requirement has a status, control quality, evidence, missing evidence, and next actions.

Foundation requirements currently modeled:

- Cryptographically rooted agent identity.
- Short-lived identity-provider-issued credentials.
- Deny-by-default least-agency permissions.
- Identity-based workload isolation.
- Comprehensive logs of agent actions with request context.
- Input validation for untrusted agent context.
- Approval escalation for high-risk actions.
- Context retention policy for persisted agent memory.
- Automated first-pass investigation for agent alerts.

Control quality values are intentionally blunt:

- `hard_barrier`: Ariadne observed evidence for a control that removes or cryptographically constrains a capability.
- `friction_only`: Ariadne observed a prompt or approval-like control without enough evidence that it creates a reconstructable, enforceable boundary.
- `partial_declared`: Ariadne observed part of the required control family, but not enough to call the requirement met.
- `partial_observed`: Ariadne observed part of the runtime evidence, such as action-log shape without request or trace propagation.
- `evidence_gap`: relevant agent surfaces exist, but Ariadne lacks the evidence needed to judge the requirement.
- `missing_hard_barrier`: relevant risky authority exists without observed control evidence.
- `conflicting_broad_authority`: broad local authority was observed, so least-agency evidence is not satisfied until that authority is removed or replaced with scoped permissions.
- `broken_static_credential`: inline credential material indicators were observed in agent configuration.
- `not_applicable`: Ariadne did not observe a supported surface for this requirement in the current run.

## Local Policy File

Repositories can declare Zero Trust agent controls in `.ariadne/agent-policy.json`.

Example:

```json
{
  "cryptographic_identity": "spiffe",
  "least_agency": true,
  "deny_by_default": true,
  "identity_based_isolation": true,
  "network_segmentation": true,
  "approval_required": true,
  "sandbox_required": true,
  "credential_helper": "vault",
  "short_lived_credentials": true,
  "audit_logging": true,
  "tool_call_logging": true,
  "request_id": true,
  "trace_id": true,
  "input_validation": true,
  "schema_validation": true,
  "automated_triage": true,
  "context_retention": {
    "retention_days": 7
  }
}
```

The policy is treated as declared evidence. Ariadne does not execute the policy or prove live enforcement.

Repositories can also declare observability controls in `.ariadne/observability-policy.json`, or provide OpenTelemetry collector config such as `.ariadne/otel-collector.yaml`.

Transcript and history JSONL files are handled differently from policy files. Ariadne samples bounded structured metadata to identify whether event-shape evidence exists for tool calls, approval decisions, request IDs, trace IDs, correlation IDs, session IDs, and timestamps. It does not emit prompt text, tool arguments, tool outputs, or transcript content.

Repositories can declare persisted-context controls in `.ariadne/memory-policy.json`:

```json
{
  "context_retention": { "retention_days": 7 },
  "memory_isolation": { "session_isolation": true },
  "context_integrity": { "content_hash": true },
  "context_provenance": { "source_attribution": true }
}
```

Memory isolation is modeled as a graph control for the private-context boundary. Retention, integrity, and provenance are reported as evidence for the context-retention requirement, but Ariadne still does not inspect or emit private memory content.

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
It should only call a Foundation requirement `controlled` when the required evidence is present in the deterministic collection.
