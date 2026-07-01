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

Ariadne parses declared controls from runtime configuration, `.ariadne/agent-policy.json`, and focused policy files such as `.ariadne/tool-policy.json`, `.ariadne/delegation-policy.json`, `.ariadne/input-policy.json`, `.ariadne/output-policy.json`, `.ariadne/identity-policy.json`, `.ariadne/authorization-policy.json`, `.ariadne/resource-policy.json`, `.ariadne/memory-policy.json`, `.ariadne/workload-policy.json`, `.ariadne/egress-policy.json`, `.ariadne/response-policy.json`, `.ariadne/governance-policy.json`, `.ariadne/integrity-policy.json`, and `.ariadne/supply-chain-policy.json`.

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
- AI-BOM or ML-BOM, model provenance, training-data lineage, dependency health, provider review, signed AI artifacts, runtime component validation, and dependency reachability analysis
- delegation scope, delegate allowlist, agent-to-agent authorization, original-intent verification, delegated credential scoping, subagent context isolation, and delegation audit indicators
- egress destination allowlists, webhook allowlists, per-tool network scope, output filtering, and egress audit indicators
- approval-required posture, ask/PreToolUse settings, and approval decision logging
- sandbox or filesystem isolation posture
- credential helper, vault, or keychain retrieval
- short-lived, OAuth/OIDC, federated, JIT, or token-lifetime credential indicators
- credential rotation, revocation, or identity lifecycle indicators
- per-action authorization, continuous policy evaluation, dynamic privilege scoping, JIT elevation, no-standing-access, and automatic access revocation indicators
- rate limits, spend limits, loop guards, tool timeouts, concurrency limits, circuit breakers, and resource usage audit indicators
- audit, tool-call, approval, telemetry, or trace logging indicators
- request ID, trace ID, correlation ID, distributed tracing, or provenance indicators that connect the original request to resulting agent actions
- input isolation, trusted instruction source, instruction provenance, schema validation, prompt-injection filtering, untrusted-content delimiting, spotlighting, or maximum input length indicators
- sensitive-output filtering, output redaction or blocking, output filter logging, semantic output analysis, and high-risk output review indicators
- automated first-pass investigation or alert triage indicators
- behavioral monitoring, session termination, credential revocation, quarantine, dynamic access reduction, or response escalation indicators
- agent inventory, accountable owner, deployment approval, risk assessment, governance review, or Shadow AI discovery indicators
- transcript, memory, or context retention indicators
- memory isolation, context retention, context integrity, context provenance, and memory credential-isolation indicators
- reviewed version-controlled config, signed config, deployment verification, managed-settings enforcement, immutable runtime, and rollback indicators
- observed structured transcript metadata for tool-call events, approval decisions, action logs, request IDs, trace IDs, correlation IDs, or session IDs
- telemetry export and immutable audit log indicators from observability policy or OpenTelemetry collector config

Ariadne also flags inline credential field indicators as `boundary:credential-material` and credential-like filename indicators inside summarized private context as `boundary:memory-credential-retention`. It reports field or filename presence only; values are never emitted.

For the Zero Trust observability boundary, Ariadne separates partial observability from a stronger request-to-action trail. Audit, telemetry, transcript, or cache evidence is useful, but it is not enough by itself. The boundary is treated as controlled only when Ariadne observes action logging evidence plus request, trace, or correlation propagation evidence. High-risk tool or authority surfaces with no observability controls are reported as a breaking architecture path.

## Redaction

Secret values are never emitted. Private context surfaces are summarized by file count, size, source, category, and count-only credential-like filename indicators. Exact sensitive paths outside the scan root are redacted by default.

For transcript and history JSONL files, Ariadne samples bounded structured metadata only. It looks at JSON keys and safe event-shape fields such as event type, request ID, trace ID, timestamp, tool-call presence, and approval-decision presence. It does not emit prompt text, tool arguments, tool outputs, or transcript content.
