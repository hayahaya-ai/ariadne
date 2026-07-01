# Threat Model

Ariadne focuses on local AI-agent exposure management.

## Assets

- developer secrets and credentials
- repository files
- endpoint-level agent config
- agent memory, history, and paste caches
- tool and MCP configuration
- AI-BOM, ML-BOM, model, tool, framework, dependency, and provider provenance records
- external communication paths
- API quotas, budgets, token usage, and compute/runtime limits

## Trust Boundaries

- untrusted repository or project instructions
- local agent runtime
- local filesystem and user context
- model-callable tools
- agent model, tool, framework, and dependency supply chain
- external destinations
- policy and control surfaces
- continuous authorization and privilege elevation controls
- resource, rate, spend, loop, timeout, concurrency, and quota controls
- response and containment controls
- deployment governance records

## Supported Exposure Questions

- Can untrusted instructions influence an agent with private-data access?
- Can the agent reach secret-like local boundaries?
- Can a mutable tool launcher grant local execution?
- Are model-callable tools approved, provenance-bound, descriptor-validated, authenticated, and argument-validated?
- Are model, tool, framework, MCP, and dependency components covered by AI-BOM or ML-BOM evidence, model provenance, dependency health, provider review, signing, or runtime validation?
- Can delegated or sub-agent work inherit parent authority without explicit authorization and scope?
- Can private-data reachability combine with external communication reachability?
- Are external destinations constrained by destination allowlists, webhook allowlists, per-tool network scope, or network isolation?
- Are agent outputs filtered, redacted or blocked, reviewed, and logged before sensitive content reaches users or external channels?
- Is high-risk agent authority re-authorized per action, dynamically scoped, and automatically revoked when task or risk state changes?
- Do high-risk local execution, external communication, delegation, or sensitive-data access actions require human approval and approval-decision logging?
- Can an agent loop tool calls, exhaust APIs, create billing spikes, or deny service without resource limits and circuit breakers?
- Does a declared control break a modeled path?
- Does configuration declare cryptographic or per-agent identity, scoped or short-lived credentials, least-agency scope, identity-aware workload authorization, approval, sandbox, audit, traceability, input isolation, input validation, automated triage, containment, retention, memory integrity, provenance, or credential-isolation controls?
- Is the agent deployment registered, owned, approved, risk-assessed, reviewed, or still effectively Shadow AI?
- Are agent settings, MCP definitions, and policy files protected by review, signatures, managed enforcement, immutable runtime, or rollback controls?
- Does configuration contain inline credential field indicators?

## Zero Trust Architecture Questions

- Is the influence boundary isolated from authority-bearing agent runtimes?
- Are repo, memory, web, or document instructions trust-gated before they can steer authority?
- Is runtime/tool authority constrained to least agency?
- Can authority reach sensitive data, private context, execution, or external destinations?
- Can private data leave only through approved external destinations?
- Can sensitive data leak through the agent response itself without output filtering, redaction, and output-control logging?
- Can a model-callable tool change capability without allowlisting, pinning, descriptor integrity, authentication, or argument validation?
- Can an agent load model, tool, framework, MCP, or dependency components without AI-BOM, provenance, dependency-health, provider-review, signing, or runtime-validation evidence?
- Can a lower-trust delegated agent become a confused deputy for a more privileged parent agent?
- Do controls remove the path, or do they only add friction?
- Is high-risk agent authority scoped to attributable agent identity, rather than inherited local user authority?
- Is the authenticated agent authorized only for named callers, context attributes, network segments, and tool scopes?
- Is standing high-risk authority replaced with per-action authorization, dynamic/JIT scoping, and automatic revocation?
- Are high-risk autonomous actions gated by explicit human approval with decision logs?
- Are tool/API calls bounded by rate, spend, loop, timeout, concurrency, and usage-audit controls?
- Is persisted memory or context isolated from unrelated sessions and broad local authority, and does it avoid retaining credential-like material without credential isolation?
- Would operators have enough action logs and request or trace correlation to reconstruct what request caused each agent action and approval?
- Can suspicious agent behavior trigger containment that terminates sessions, revokes credentials, quarantines the workload, or reduces authority?
- Is the deployment governed by an inventory, accountable owner, approval process, risk tier, data classification, and review cadence?
- Can agent configuration be silently changed to widen authority or disable controls?

Ariadne reports these as `breaking`, `controlled`, `unknown`, or `not_observed`. It only reports `breaking` when deterministic facts and graph edges support the claim.

## Out Of Scope

- live exploit execution
- runtime behavioral sandbox bypass testing
- registry/package reputation checks
- live MCP descriptor retrieval, registry resolution, package digest verification, or signature validation
- live OpenSSF Scorecard execution, dependency reachability analysis, model-weight inspection, training-data verification, vendor assurance validation, or runtime attestation
- cloud API collection
- non-deterministic LLM review
- identity provider, ABAC, JIT, token lifetime, segmentation, named-caller, or hardware-bound credential enforcement verification
- live continuous authorization, policy-decision-point, JIT elevation, no-standing-access, or access-revocation enforcement verification
- live quota, rate-limit, billing, token accounting, timeout, circuit-breaker, or resource-usage enforcement verification
- live inter-agent authorization, delegated credential downscoping, or subagent execution enforcement verification
- proxy, DNS, firewall, destination allowlist, webhook allowlist, or per-tool network-scope enforcement verification
- live prompt-injection resistance testing
- live output DLP, semantic leakage testing, response inspection, or output-control enforcement verification
- private memory content inspection, live memory quarantine, rollback, or tamper-resistant context-integrity enforcement proof
- live observability, SIEM, telemetry ingestion, request-to-action replay, or tamper-resistant audit proof
- live SOAR execution, session termination, credential revocation, quarantine, or dynamic access-reduction enforcement proof
- live GRC, CMDB, approval workflow, policy exception, or organization-wide Shadow AI discovery verification
- Git branch protection, signature verification, MDM enforcement, admission policy, or rollback execution proof
- runtime enforcement

These are future layers. The deterministic layer must remain useful without them.
