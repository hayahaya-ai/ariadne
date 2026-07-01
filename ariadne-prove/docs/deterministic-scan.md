# Deterministic Scan Model

Ariadne's default mode is deterministic. It observes local files and config, emits facts, builds a graph, and classifies only supported exposure paths.

## What Ariadne Does

- walks supported AI-agent surfaces
- parses known configuration and instruction files
- summarizes private/high-volume surfaces by metadata
- models authorities, boundaries, and controls
- builds graph edges between facts
- classifies supported exposure paths
- maps exposure and control evidence to Zero Trust architecture checks
- exports the same graph as JSON, Graphviz DOT, or Mermaid when requested

## What Ariadne Does Not Do

- execute agent runtimes
- run shell commands discovered in configs
- execute MCP or tool servers
- install or resolve packages
- call external network services
- read or emit secret values
- infer safety from missing evidence

## Evidence Grades

| Grade | Meaning |
| --- | --- |
| `observed` | Ariadne observed a file, surface, or boundary indicator. |
| `declared` | Ariadne parsed a config or instruction declaration. |
| `inferred` | Ariadne modeled a fact from deterministic evidence. |
| `skipped` | Ariadne intentionally skipped a noisy or private surface. |

## Status Semantics

| Status | Meaning |
| --- | --- |
| `exposed` | Ariadne found a supported graph path from influence or tool authority to a sensitive boundary without a breaking control. |
| `protected` | Ariadne found a supported path attempt and a control that breaks it. |
| `inconclusive` | Ariadne did not collect enough evidence to prove exposure or protection. |

## Zero Trust Control Evidence

Ariadne parses declared controls from runtime configuration, `.ariadne/agent-policy.json`, and focused policy files such as `.ariadne/tool-policy.json`, `.ariadne/input-policy.json`, `.ariadne/identity-policy.json`, `.ariadne/workload-policy.json`, `.ariadne/egress-policy.json`, and `.ariadne/integrity-policy.json`.

Supported control signals include:

- cryptographic identity, workload identity, mTLS, X.509, or SPIFFE indicators
- per-agent credential isolation, non-shared credentials, or agent-scoped credential indicators
- hardware-bound credential indicators such as passkeys, FIDO2, WebAuthn, TPM, Secure Enclave, or YubiKey posture
- least agency, least privilege, RBAC, scoped permissions, or deny-by-default indicators
- runtime-scoped permissions such as Claude `defaultMode: default`, scoped `Read(...)` / `Bash(...)` permissions, Codex `read-only`, or Codex `workspace-write`
- identity-based isolation, workload isolation, network segmentation, or microsegmentation indicators
- named-caller, principal allowlist, service-account allowlist, or workload allowlist indicators
- ABAC, attribute condition, claim, subject-attribute, resource-attribute, or context-attribute indicators
- per-tool scope, allowed-tool, tool allowlist, MCP allowlist, or permission-scope indicators
- approved tool or MCP server allowlists, MCP review and pinning, descriptor/schema integrity, tool argument validation, tool authentication, signed tool artifacts, deployment verification, sandboxed tool execution, and circuit breakers
- egress destination allowlists, webhook allowlists, per-tool network scope, output filtering, and egress audit indicators
- approval-required posture
- sandbox or filesystem isolation posture
- credential helper, vault, or keychain retrieval
- short-lived, OAuth/OIDC, federated, JIT, or token-lifetime credential indicators
- credential rotation, revocation, or identity lifecycle indicators
- audit, tool-call, approval, telemetry, or trace logging indicators
- request ID, trace ID, correlation ID, distributed tracing, or provenance indicators
- input isolation, trusted instruction source, instruction provenance, schema validation, prompt-injection filtering, untrusted-content delimiting, spotlighting, or maximum input length indicators
- automated first-pass investigation or alert triage indicators
- transcript, memory, or context retention indicators
- memory isolation, context integrity, and context provenance indicators
- reviewed version-controlled config, signed config, deployment verification, managed-settings enforcement, immutable runtime, and rollback indicators
- observed structured transcript metadata for tool-call events, approval decisions, action logs, request IDs, trace IDs, correlation IDs, or session IDs
- telemetry export and immutable audit log indicators from observability policy or OpenTelemetry collector config

Ariadne also flags inline credential field indicators as `boundary:credential-material`. It reports the field presence only; values are never emitted.

## Redaction

Secret values are never emitted. Private context surfaces are summarized by file count, size, source, and category. Exact sensitive paths outside the scan root are redacted by default.

For transcript and history JSONL files, Ariadne samples bounded structured metadata only. It looks at JSON keys and safe event-shape fields such as event type, request ID, trace ID, timestamp, tool-call presence, and approval-decision presence. It does not emit prompt text, tool arguments, tool outputs, or transcript content.
