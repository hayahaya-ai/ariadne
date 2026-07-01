# Zero Trust Agent Architecture

Ariadne maps local agent setups against a Zero Trust architecture model for AI agents.

The goal is not to certify that an environment is safe. The goal is to expose where the architecture is breaking, controlled, unknown, or not observed from deterministic evidence.

## Core Question

> Where can untrusted influence, agent authority, sensitive boundaries, unverified agent components, missing controls, weak identity, persistent context, or missing observability combine into exposure?

## Status Vocabulary

- `breaking`: Ariadne found a graph-backed path or missing break-path control.
- `controlled`: Ariadne found a control edge that breaks a supported path.
- `unknown`: Ariadne found relevant surfaces, but not enough evidence to prove or clear the architecture boundary.
- `not_observed`: Ariadne did not observe supported evidence for that boundary.

## Product Readout

The first readout is `zero_trust.architecture_flaws`.

This is the user-centered map of architecture flaw categories Ariadne is trying to expose:

- untrusted instructions steering privileged tools
- broad standing agent authority
- mutable or unverified tools and MCP servers
- arbitrary external egress
- weak agent identity
- missing workload or continuous authorization
- missing approval, observability, response, governance, or configuration integrity
- unsafe persistent memory or context
- controls that add friction instead of removing the risky path

Each flaw carries a status, severity, underlying check IDs, evidence references, graph edges, observed controls, a `control_test`, `control_evidence_needed`, `evidence_surfaces`, actions, and limitations. The flaw map is derived from the lower-level `zero_trust.checks`; it does not introduce a second opinion layer.

## Architecture Boundaries

Ariadne currently evaluates these Zero Trust checks:

- Influence boundary: whether untrusted instructions can steer an agent runtime or are broken by input isolation or trusted-source gates.
- Authority boundary: whether agent authority is scoped to least agency.
- Sensitive data boundary: whether authority reaches secrets, private context, or external destinations.
- External egress boundary: whether external communication is constrained by network restrictions, destination allowlists, webhook allowlists, or per-tool network scope.
- Output controls boundary: whether sensitive or harmful agent output is filtered, blocked or redacted, reviewed, and logged before delivery.
- Tool and MCP boundary: whether model-callable tools can expand capability through mutable launch paths.
- Tool integrity boundary: whether model-callable tools are approved, provenance-bound, descriptor-validated, authenticated, and argument-validated.
- AI supply-chain boundary: whether model, dataset, framework, MCP, plugin, tool, and provider components have AI-BOM, provenance, dependency-health, signing, and runtime-validation evidence.
- Agent delegation boundary: whether delegated or sub-agent work has explicit scope, agent-to-agent authorization, original-intent verification, and delegated credential controls.
- Memory and context boundary: whether persisted context can be reached, poisoned, or retain credential-like material without isolation, retention, integrity, provenance, and credential-isolation evidence.
- Agent identity boundary: whether Ariadne observed strong per-agent identity evidence plus scoped or ephemeral credential issuance.
- Workload authorization boundary: whether agent authority is constrained by ABAC, named callers, network segments, or tool scope.
- Continuous authorization boundary: whether high-risk agent authority is re-authorized per action, dynamically scoped, and automatically revoked when task or risk state changes.
- Human approval boundary: whether high-risk autonomous actions require explicit human approval and approval-decision logging.
- Resource exhaustion boundary: whether tool/API calls, spend, loops, runtime, and concurrency are bounded and audited before agent automation can run away.
- Observability boundary: whether Ariadne observed action logging plus request or trace propagation evidence to reconstruct request-to-action chains.
- Response and containment boundary: whether suspicious agent behavior can trigger containment that terminates sessions, revokes credentials, quarantines workloads, or reduces authority.
- Deployment governance boundary: whether observed agent deployments are registered, owned, approved, risk-assessed, and reviewed instead of unmanaged Shadow AI.
- Configuration integrity boundary: whether agent settings, MCP definitions, and policy files are reviewable, tamper-evident, centrally enforced, or immutable.
- Control boundary: whether controls remove a path or only add friction.

## Agent Architecture Failure Map

The Zero Trust goal is to expose boundary failures in agent architecture, not to grade an agent by vibes. Ariadne maps common AI-agent architecture flaws into deterministic evidence questions:

| Architecture flaw | Ariadne boundary | Current posture |
| --- | --- | --- |
| Untrusted instructions can steer privileged tools | Influence, authority, sensitive data, and egress boundaries | Modeled today through trust inputs, runtime authority, tool surfaces, secret/private boundaries, egress destinations, and break-path controls. A specific data exposure can be inconclusive while the influence boundary is still breaking if risky instructions reach high-risk authority without input isolation or trusted-source gates. |
| Agent has broad standing authority instead of least agency | Authority boundary and Foundation maturity | Modeled today through Claude/Codex permission posture, deny-by-default evidence, broad local authority, and scoped permission controls. |
| MCP/tooling expands capability through mutable or unpinned launch paths | Tool and MCP boundary | Modeled today for package launchers, reviewed/pinned controls, plugin surfaces, and shell-capable command surfaces. |
| Tool descriptors, schemas, metadata, or remote tool auth can change underneath the agent | Tool integrity boundary | Modeled today through approved tool/MCP allowlists, MCP review and pinning, descriptor integrity, argument validation, tool authentication, signed artifacts, and deployment verification declarations. |
| Agent tools, frameworks, model components, or providers are unknown, mutable, or unverified | AI supply-chain boundary and Foundation maturity | Modeled today through AI-BOM or ML-BOM surfaces, supply-chain policy, model provenance, training-data lineage, dependency health, provider review, signed AI artifacts, runtime component validation, and reachability analysis declarations. |
| A lower-trust delegated or sub-agent path can inherit parent authority | Agent delegation boundary | Modeled today through Claude subagent definitions, delegation language in instruction surfaces, delegation scope, delegate allowlists, agent-to-agent authorization, original-intent verification, delegated credential scoping, context isolation, and delegation audit declarations. |
| Data can leave through arbitrary destinations | External egress boundary | Modeled today through external communication authority, destination allowlists, webhook allowlists, per-tool network scope, and network restriction evidence. A complete private-data egress path can be inconclusive while the external egress boundary is still breaking if risky influence, high-risk authority, or risky tools can reach arbitrary external destinations. |
| Sensitive data can leak through an agent response even without arbitrary network egress | Output controls boundary and Foundation maturity | Modeled today through output policy, sensitive-output filters, block or redaction controls, output filter logging, semantic output analysis, and high-risk output review declarations. |
| Agent identity is a label rather than a cryptographic boundary | Agent identity boundary | Modeled today from declared identity and credential controls. High-risk authority without strong scoped agent identity is breaking; helper-only evidence remains partial. Live certificate, hardware attestation, and IdP validation are future collectors. |
| Workload isolation relies on network placement or sandbox alone | Workload authorization boundary | Modeled today as partial unless Ariadne also observes caller or condition evidence such as named callers or ABAC plus isolation or scope evidence such as identity-based isolation, network segmentation, or per-tool scope. High-risk authority without that boundary is breaking. |
| Agent authority is granted at session start and remains usable after task or risk context changes | Continuous authorization boundary | Modeled today through authorization policy, per-action authorization, continuous policy evaluation, dynamic privilege scoping, JIT elevation, no-standing-access declarations, and automatic revocation controls. |
| Agent can execute high-risk actions without a human approval gate or approval decision log | Human approval boundary and Foundation maturity | Modeled today through runtime approval policy, ask/PreToolUse posture, approval-required declarations, approval decision logs, audit logging, and trace/request metadata. |
| Agent automation can loop tool calls, exhaust APIs, spike bills, or deny service | Resource exhaustion boundary | Modeled today through resource policy, tool/API rate limits, spend or token budgets, loop guards, tool timeouts, concurrency limits, circuit breakers, and resource usage audit declarations. |
| Agent actions cannot be reconstructed fast enough after compromise | Observability boundary | Modeled today through action logging evidence, tool-call or approval records, request/trace/correlation IDs, telemetry export, and immutable log declarations. Audit evidence without request-to-action traceability remains partial. |
| A compromised agent keeps operating while humans investigate | Response and containment boundary | Modeled today through behavioral monitoring, automated triage, session termination, credential revocation, quarantine, dynamic access reduction, and response escalation declarations. |
| Employees or teams run agents outside accountable governance | Deployment governance boundary | Modeled today through agent inventory, accountable owner, deployment approval, risk assessment, governance review, and Shadow AI discovery declarations. |
| Memory or context persists across sessions without isolation, provenance, or credential exclusion | Memory and context boundary | Modeled today through private-context surfaces, credential-like filename indicators in summarized context, retention policy, memory isolation, context integrity, context provenance, and credential-isolation declarations. |
| Agent config can be silently changed to widen authority or disable controls | Configuration integrity boundary | Modeled today through reviewed version-controlled config, signed deployment verification, managed-settings enforcement, immutable runtime, and rollback evidence. |

This gives Ariadne a product rule: a report should separate observed facts, declared controls, inferred paths, and limitations. If Ariadne cannot prove a hard boundary from evidence, it should say `unknown`, not pretend the architecture is safe.

## Design Test

Every check uses the same design test:

> Does the control remove the capability or path, or does it merely make the attack tedious?

Architecture flaws expose this as `control_test`:

- `hard_barrier_observed`: Ariadne observed control evidence that removes or enforceably constrains the supported risky path.
- `missing_hard_barrier`: Ariadne observed the risk path or risky surface, but not the hard control evidence needed to break it.
- `partial_or_friction_only`: Ariadne observed some control evidence, but not enough to prove the risky capability is removed.
- `evidence_gap`: Ariadne observed relevant surfaces, but not enough control evidence to decide.
- `not_observed`: Ariadne did not observe a supported risk-bearing surface for the flaw category.

Examples of controls Ariadne can model today:

- deny-read rules for secret-like paths
- scoped runtime permission controls from Claude or Codex settings
- deny-by-default runtime permission posture
- network restrictions for external destinations
- destination allowlists, webhook allowlists, and per-tool network scope for external communication
- sensitive-output filtering, block or redaction, output filter logging, semantic output analysis, and high-risk output review declarations
- reviewed or pinned MCP server launchers
- approved tool and MCP server allowlists
- tool descriptor or schema integrity declarations
- tool argument validation declarations
- authenticated tool access declarations
- signed tool artifacts and deployment verification declarations
- sandboxed tool execution and circuit-breaker declarations
- AI-BOM or ML-BOM declarations
- model provenance, training-data lineage, dependency health, provider review, signed AI artifact, runtime component validation, and dependency reachability declarations
- delegation scope, delegate allowlist, agent-to-agent authorization, original-intent verification, delegated credential scoping, subagent context isolation, and delegation audit declarations
- input isolation or trusted-source controls for instruction inputs
- instruction provenance, untrusted-content delimiting, spotlighting, or prompt-injection filter declarations
- managed runtime settings surfaces
- approval-required posture, ask/PreToolUse settings, and approval decision logging
- sandbox or filesystem isolation posture
- credential helper or vault-backed credential retrieval
- per-agent or non-shared credential isolation
- short-lived, federated, JIT, or token-lifetime credential posture
- hardware-bound credential posture
- credential rotation, revocation, or identity lifecycle declarations
- ABAC or attribute-condition policy declarations
- per-action authorization, continuous policy evaluation, dynamic privilege scoping, JIT elevation, no-standing-access, and automatic access revocation declarations
- rate limits, spend limits, loop guards, tool timeouts, concurrency limits, circuit breakers, and resource usage audit declarations
- named-caller or principal allowlists
- network segmentation or microsegmentation declarations
- per-tool scope, tool allowlist, MCP allowlist, or permission-scope declarations
- audit, tool-call, approval, or telemetry logging declarations
- request ID, trace ID, correlation ID, or distributed tracing declarations that connect a user request to resulting agent actions
- observed structured transcript metadata for tool-call events, approval decisions, request IDs, trace IDs, and timestamped action records
- telemetry export and immutable audit log declarations from observability policy or OpenTelemetry collector config
- behavioral monitoring, automated triage, session termination, credential revocation, containment quarantine, dynamic access reduction, and response escalation declarations
- agent inventory, accountable owner, deployment approval, risk assessment, governance review, and Shadow AI discovery declarations
- memory, transcript, or context retention declarations
- memory isolation, context integrity, context provenance, and credential-isolation declarations for persisted context
- version-controlled config, config review, signed config, deployment verification, managed-settings enforcement, immutable runtime, and rollback declarations

Examples Ariadne reports as `unknown` today:

- credential helper evidence without cryptographic, hardware-bound, or per-agent identity evidence on non-high-risk surfaces
- strong identity evidence without scoped or ephemeral credential issuance evidence on non-high-risk surfaces
- input validation, filtering, provenance, or delimiting evidence without input isolation or trusted-source gating
- egress audit or output filtering evidence without destination allowlists, webhook allowlists, per-tool network scope, or network isolation
- output filtering and redaction evidence without output filter logging
- per-action authorization or ABAC evidence without dynamic/JIT privilege scoping and automatic revocation evidence
- approval prompts without approval decision logging or audit evidence
- rate-limit evidence without loop/time/concurrency stop conditions and resource usage audit evidence
- memory isolation or retention evidence without context integrity and provenance evidence
- tool sandboxing, rate limits, or circuit breakers without allowlist, provenance, authentication, descriptor integrity, or argument-validation evidence
- AI-BOM evidence without dependency health, model provenance or provider review, and artifact signing or runtime validation evidence
- delegation audit or subagent context isolation without explicit delegation scope, agent-to-agent authorization, original-intent verification, or delegated credential scoping
- sandbox or network restriction evidence without identity-aware workload authorization evidence
- audit logging evidence without request, trace, or correlation propagation evidence
- local history or cache evidence without structured request-to-action audit metadata
- tamper-resistant audit logs without immutable-log or equivalent evidence
- automated triage, behavioral monitoring, or response runbooks without a capability-removing action such as session termination, credential revocation, quarantine, or dynamic access reduction
- governance inventory or ownership evidence without deployment approval, risk assessment, and review evidence
- configuration version-control evidence without review, or signed-config evidence without deployment verification
- live behavioral telemetry

Examples Ariadne reports as `breaking` when observed:

- inline credential field indicators in agent configuration
- risky untrusted instruction input influencing high-risk runtime authority or tool surfaces without input isolation or trusted-source gates
- risky agent influence, high-risk authority, or risky tool surfaces reaching arbitrary external communication without hard egress controls
- high-risk agent authority or tool surfaces without strong scoped agent identity
- high-risk agent authority or tool surfaces without identity-aware workload authorization
- authority paths that reach private context without observed hard memory controls
- credential-like material retained in private agent context without observed credential-isolation evidence
- reachable sensitive data without observed output filtering and block or redaction controls
- risk-bearing agent configuration without observed hard integrity controls
- standing high-risk authority without observed continuous authorization, dynamic/JIT scoping, and automatic revocation controls
- high-risk local execution, external communication, delegation, or sensitive-data access without an observed human approval gate
- runaway tool, execution, external communication, or delegated authority without resource limits, stop conditions, and usage audit controls
- high-risk agent authority or tool surfaces without action logging or request traceability evidence
- risk-bearing model-callable tool surfaces without observed hard tool integrity controls
- risk-bearing agent supply-chain surfaces without observed AI-BOM, provenance, dependency-health, provider-review, signing, or runtime-validation evidence
- delegated or sub-agent authority inheritance without observed hard delegation controls
- supported exposed paths without observed automated containment controls
- risk-bearing agent surfaces without observed registration, owner, approval, risk assessment, and review evidence

## Foundation Maturity

Ariadne also emits a Foundation maturity evidence readout under `zero_trust.maturity`.

This is not a compliance attestation. It is an evidence map for the raised Foundation bar described in Zero Trust agent architecture guidance. Each requirement has a status, control quality, evidence, missing evidence, and next actions.

Foundation requirements currently modeled:

- Cryptographically rooted, hardware-bound, or per-agent identity.
- Short-lived, JIT, or token-limited identity-provider-issued credentials.
- Deny-by-default least-agency permissions.
- Tool allowlisting, provenance, and invocation validation.
- AI-BOM, model provenance, dependency health, and artifact validation.
- Identity-based workload isolation with ABAC, named callers, segmentation, or tool scope.
- Comprehensive logs of agent actions with request context and traceability.
- Input isolation, trusted-source gating, and validation for untrusted agent context.
- Output filtering, redaction, and logging for sensitive agent output.
- Approval escalation for high-risk actions.
- Context retention policy for persisted agent memory.
- Automated first-pass investigation and containment for agent alerts.
- Registered, owned, approved, risk-assessed, and reviewed agent deployments.

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
  "named_callers": ["agent://codex/local/appsec-review"],
  "abac_policy": {
    "subject_attributes": ["agent_id", "repo_id"],
    "resource_attributes": ["workspace", "tool"]
  },
  "network_segmentation": true,
  "tool_scope": {
    "allowed_tools": ["Read", "mcp:approved"],
    "permission_scope": "workspace"
  },
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

Repositories can declare focused tool integrity controls in `.ariadne/tool-policy.json`:

```json
{
  "approved_tools": ["mcp:filesystem"],
  "approved_mcp_servers": ["filesystem"],
  "require_pinned_packages": true,
  "tool_descriptor_integrity": true,
  "tool_argument_validation": true,
  "tool_auth_required": true,
  "signed_tool_artifacts": true,
  "tool_deployment_verification": true,
  "tool_sandbox_execution": true,
  "tool_circuit_breaker": true
}
```

Ariadne treats allowlist plus MCP/package pinning, signed tool artifacts plus deployment verification, descriptor integrity plus argument validation, or authenticated tool access plus short-lived/JIT credential evidence as hard tool integrity evidence. Sandboxed tool execution and circuit breakers are reported as evidence, but they do not by themselves prove tool provenance or invocation integrity.

Repositories can declare focused resource-exhaustion controls in `.ariadne/resource-policy.json`:

```json
{
  "tool_rate_limit": {
    "requests_per_minute": 30,
    "api_call_limit": 300
  },
  "spend_limit": {
    "token_budget": 250000,
    "cost_limit": "25.00"
  },
  "loop_guard": {
    "max_iterations": 12,
    "recursion_limit": 3,
    "loop_detection": true
  },
  "tool_timeout": {
    "timeout_seconds": 120,
    "wall_clock_limit": "10m"
  },
  "concurrency_limit": {
    "max_parallel_tools": 3,
    "worker_limit": 4
  },
  "tool_circuit_breaker": true,
  "resource_usage_audit": {
    "usage_logging": true,
    "budget_alert": true,
    "quota_alert": true
  }
}
```

Ariadne treats rate, spend, or concurrency bounds plus loop guards, timeouts, or circuit breakers plus resource usage audit as hard resource-exhaustion evidence. A rate limit alone is partial because it may slow a runaway agent without proving the operation stops or leaves investigation evidence.

Repositories can declare focused AI supply-chain controls in `.ariadne/supply-chain-policy.json`:

```json
{
  "ai_bom": true,
  "model_provenance": {
    "model_provider": "approved-provider",
    "model_version": "stable"
  },
  "training_data_lineage": {
    "dataset_lineage": "provider-attested"
  },
  "dependency_health": {
    "openssf_scorecard": true,
    "dependency_scan": true,
    "signed_releases": true
  },
  "provider_risk_review": true,
  "signed_ai_artifacts": true,
  "runtime_component_validation": true,
  "reachability_analysis": true
}
```

Ariadne also discovers AI-BOM and ML-BOM files such as `.ariadne/ai-bom.json`, `.ariadne/ml-bom.json`, `ai-bom.json`, `ml-bom.json`, and CycloneDX-style `bom.json` or `cyclonedx.json` surfaces. It treats BOM plus dependency health plus model provenance, training-data lineage, or provider review plus signed artifacts or runtime validation as hard supply-chain evidence. A BOM alone is partial evidence, not a controlled boundary.

Repositories can declare focused delegation controls in `.ariadne/delegation-policy.json`:

```json
{
  "delegation_scope": true,
  "allowed_delegate_agents": ["security-reviewer"],
  "agent_to_agent_authorization": true,
  "origin_intent_verification": true,
  "delegated_credential_scope": true,
  "subagent_context_isolation": true,
  "delegation_audit": true
}
```

Ariadne treats delegation scope plus agent-to-agent authorization or delegate allowlists, and original-intent verification plus delegated credential scoping, as hard delegation trust-boundary evidence. Subagent context isolation and delegation audit are reported as important evidence, but they do not by themselves prove that a delegated agent cannot inherit parent authority.

Repositories can declare focused input controls in `.ariadne/input-policy.json`:

```json
{
  "input_isolation": true,
  "trusted_instruction_sources": ["org/security-reviewed"],
  "instruction_provenance": {
    "signed_instructions": true,
    "source_digest": true
  },
  "untrusted_input_delimiting": true,
  "prompt_injection_filter": true,
  "schema_validation": true
}
```

Ariadne treats input isolation and trusted-source policy as graph break controls for untrusted instruction influence. Validation, provenance, delimiting, and filtering are still reported as evidence, but they are partial unless Ariadne also observes an input-isolation or trusted-source gate. A specific secret or egress exposure can remain inconclusive while the influence boundary is still `breaking` when risky untrusted instructions can steer high-risk runtime authority or model-callable tools.

Repositories can declare focused output controls in `.ariadne/output-policy.json`:

```json
{
  "output_sensitive_data_filter": {
    "pii_filter": true,
    "credential_filter": true,
    "sensitive_data_patterns": ["secret-like", "token-like"]
  },
  "output_redaction": {
    "block_sensitive_output": true,
    "redact_secret_like": true
  },
  "output_filter_logging": true,
  "semantic_output_analysis": true,
  "high_risk_output_review": true
}
```

Ariadne treats sensitive-output filtering plus block or redaction plus output filter logging as hard Foundation output-control evidence. Semantic analysis and high-risk output review are additional evidence, but output filtering without logging remains partial.

Repositories can declare focused identity controls in `.ariadne/identity-policy.json`:

```json
{
  "cryptographic_identity": "spiffe",
  "credential_isolation": true,
  "credential_helper": "vault",
  "short_lived_credentials": true,
  "jit_access": true,
  "token_lifetime": { "max_minutes": 15 },
  "hardware_bound_credentials": true,
  "identity_lifecycle": {
    "credential_rotation_days": 30,
    "revocation": true
  }
}
```

Ariadne treats helper-only evidence as partial. The identity boundary is controlled only when strong identity evidence and scoped or ephemeral credential issuance evidence are both present. If high-risk local execution, broad local authority, external communication, delegated authority, or sensitive-data access exists without that hard identity boundary, Ariadne reports the identity boundary as `breaking` because the agent may be operating under inherited local user authority. In the graph, identity controls emit `identifies` edges to runtimes and credential controls emit `scopes_credentials` edges to authorities.

Repositories can declare focused continuous authorization controls in `.ariadne/authorization-policy.json`:

```json
{
  "per_action_authorization": true,
  "continuous_authorization": {
    "real_time_policy_evaluation": true,
    "policy_evaluation_per_action": true,
    "reauthorize_on_risk_change": true
  },
  "dynamic_privilege_scoping": {
    "just_enough_access": true,
    "task_scoped_privileges": true
  },
  "jit_elevation": {
    "privilege_elevation_ttl": "15m",
    "elevate_permissions_only_when_needed": true
  },
  "standing_access": false,
  "automatic_access_revocation": {
    "revoke_after_task": true,
    "revoke_on_risk_change": true,
    "revoke_on_anomaly": true
  }
}
```

Ariadne treats per-action or continuous authorization plus dynamic or JIT scoping plus automatic revocation or downscoping as hard continuous-authorization evidence. ABAC, tool scope, token lifetime, or JIT evidence without the full set is useful evidence, but it remains partial for this boundary.

Repositories can declare focused workload authorization controls in `.ariadne/workload-policy.json`:

```json
{
  "identity_based_isolation": true,
  "named_callers": [
    "agent://codex/local/appsec-review",
    "agent://claude/local/appsec-review"
  ],
  "abac_policy": {
    "subject_attributes": ["agent_id", "repo_id", "runtime"],
    "resource_attributes": ["workspace", "tool", "boundary"],
    "context_attributes": ["task_type", "approval_state"]
  },
  "network_segmentation": true,
  "tool_scope": {
    "allowed_tools": ["Read"],
    "permission_scope": "workspace"
  }
}
```

Ariadne treats sandbox or network restriction alone as partial for workload authorization. The workload authorization boundary is controlled only when Ariadne observes caller or condition evidence such as named callers or ABAC plus an isolation or scope signal such as workload isolation, segmentation, or tool scope. If high-risk local execution, broad local authority, external communication, delegated authority, or sensitive-data access exists without that hard workload authorization boundary, Ariadne reports the workload authorization boundary as `breaking`. In the graph, workload controls emit `authorizes` edges to the runtime or authority they authorize.

Repositories can declare focused egress controls in `.ariadne/egress-policy.json`:

```json
{
  "egress_destination_allowlist": [
    "https://api.company.example"
  ],
  "webhook_allowlist": [
    "https://hooks.company.example/agent"
  ],
  "per_tool_network_scope": {
    "WebFetch": [
      "https://api.company.example"
    ]
  },
  "egress_content_filter": {
    "block_secret_like": true
  },
  "egress_audit": true
}
```

Ariadne treats destination allowlists, webhook allowlists, per-tool network scope, and network restriction as hard egress boundary evidence. Output filtering and egress audit are reported as facts, but they do not by themselves break a data-egress path because they monitor or transform output rather than remove arbitrary destination reachability. A full data-egress chain can remain inconclusive while the external egress boundary is still `breaking` when risky influence, high-risk authority, or risky tool surfaces can reach arbitrary external communication without hard egress controls.

Repositories can also declare observability controls in `.ariadne/observability-policy.json`, or provide OpenTelemetry collector config such as `.ariadne/otel-collector.yaml`.

Transcript and history JSONL files are handled differently from policy files. Ariadne samples bounded structured metadata to identify whether event-shape evidence exists for tool calls, approval decisions, request IDs, trace IDs, correlation IDs, session IDs, and timestamps. It does not emit prompt text, tool arguments, tool outputs, or transcript content.

Ariadne treats observability as controlled only when it sees both sides of the request-to-action trail: action evidence such as agent action logs, tool-call audit evidence, or approval logs, and correlation evidence such as request IDs, trace IDs, or observed request traceability. Audit logging by itself is reported as partial or `unknown`. When high-risk authority or tool surfaces exist with no observability controls, Ariadne reports the observability boundary as `breaking`. In the graph, observability controls emit `observes` edges to the runtime, tool, or authority they monitor, and traceability controls emit `traces` edges to the same targets.

Repositories can declare focused response and containment controls in `.ariadne/response-policy.json`:

```json
{
  "automated_triage": true,
  "behavioral_monitoring": true,
  "session_termination": true,
  "credential_revocation": true,
  "containment_quarantine": true,
  "dynamic_access_reduction": true,
  "response_escalation": true,
  "audit_logging": true
}
```

Ariadne treats response as controlled only when detection or triage evidence is paired with a capability-removing action such as session termination, credential revocation, quarantine, or dynamic access reduction, plus audit, trace, telemetry, or escalation evidence. Triage, monitoring, or runbook evidence alone is reported as partial because it does not stop a compromised agent from continuing to operate.

Repositories can declare focused deployment governance controls in `.ariadne/governance-policy.json`:

```json
{
  "agent_inventory": {
    "registered_agents": ["codex-local-appsec-review"]
  },
  "deployment_owner": {
    "responsible_team": "appsec"
  },
  "deployment_approval": true,
  "risk_assessment": {
    "risk_tier": "medium",
    "data_classification": "developer-secrets"
  },
  "governance_audit": {
    "review_cadence": "quarterly"
  },
  "shadow_ai_discovery": true
}
```

Ariadne treats governance as controlled only when it observes inventory, accountable ownership, deployment approval, risk assessment, and governance review evidence. Shadow AI discovery is reported as useful evidence, but it does not by itself prove the observed deployment is approved or accountable.

Repositories can declare persisted-context controls in `.ariadne/memory-policy.json`:

```json
{
  "context_retention": { "retention_days": 7 },
  "memory_isolation": { "session_isolation": true },
  "context_integrity": { "content_hash": true },
  "context_provenance": { "source_attribution": true },
  "credential_isolation": true
}
```

Memory isolation, retention, integrity, and provenance are modeled as graph controls for the private-context boundary. If summarized private context contains credential-like filename indicators, Ariadne emits `boundary:memory-credential-retention`; credential isolation is then required before the memory boundary is considered controlled. Ariadne still does not inspect or emit private memory content.

Repositories can declare focused configuration integrity controls in `.ariadne/integrity-policy.json`:

```json
{
  "version_controlled_config": true,
  "config_review_required": true,
  "signed_config": true,
  "config_deployment_verification": true,
  "managed_settings_enforced": true,
  "immutable_agent_runtime": true,
  "rollback_procedure": true,
  "automated_rollback": true
}
```

Ariadne treats reviewed version-controlled configuration, signed configuration with deployment verification, managed settings enforcement, and immutable runtime declarations as hard configuration integrity evidence. Rollback controls are reported as recovery evidence, but they do not by themselves prevent a configuration change from widening authority.

## Evidence Contract

Zero Trust architecture results are emitted under `zero_trust` in `prove` JSON and rendered in the local dashboard.

For the shortest CLI readout, use:

```bash
ariadne architecture --path .
ariadne architecture --targets targets.txt
ariadne architecture --path . --status all --format json
ariadne architecture --path . --format html --out architecture-dashboard.html
ariadne architecture --targets targets.txt --format html --out fleet-architecture.html
ariadne architecture --path . --mode endpoint --include-sensitive-paths
```

`ariadne architecture` defaults to `--status breaking`, so the first output answers where the architecture is currently breaking. Use `--format html` for a focused local operator dashboard. Use `--targets` to group the same architecture flaws across a fleet target list. Use `--status unknown`, `--status controlled`, `--status observed`, or `--status all` when triaging evidence gaps or validating controls.

Start with:

- `architecture_summary`: counts architecture flaw categories by status
- `architecture_flaws`: user-centered flaw categories with evidence, graph edges, observed controls, control-test result, control evidence needed, evidence surfaces, and next actions
- `boundary_coverage`: check-level Zero Trust boundary coverage with target counts, evidence sources, controls, missing evidence, next collectors, and control evidence needed
- `evidence_coverage`: known versus missing Zero Trust evidence for a single target
- `maturity`: Foundation requirement status for a single target
- `checks`: lower-level boundary evaluations that support the flaw map

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
