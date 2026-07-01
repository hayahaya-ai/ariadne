# Threat Model

Ariadne focuses on local AI-agent exposure management.

## Assets

- developer secrets and credentials
- repository files
- endpoint-level agent config
- agent memory, history, and paste caches
- tool and MCP configuration
- external communication paths

## Trust Boundaries

- untrusted repository or project instructions
- local agent runtime
- local filesystem and user context
- model-callable tools
- external destinations
- policy and control surfaces
- response and containment controls
- deployment governance records

## Supported Exposure Questions

- Can untrusted instructions influence an agent with private-data access?
- Can the agent reach secret-like local boundaries?
- Can a mutable tool launcher grant local execution?
- Are model-callable tools approved, provenance-bound, descriptor-validated, authenticated, and argument-validated?
- Can delegated or sub-agent work inherit parent authority without explicit authorization and scope?
- Can private-data reachability combine with external communication reachability?
- Are external destinations constrained by destination allowlists, webhook allowlists, per-tool network scope, or network isolation?
- Does a declared control break a modeled path?
- Does configuration declare cryptographic or per-agent identity, scoped or short-lived credentials, least-agency scope, identity-aware workload authorization, approval, sandbox, audit, traceability, input isolation, input validation, automated triage, containment, or retention controls?
- Is the agent deployment registered, owned, approved, risk-assessed, reviewed, or still effectively Shadow AI?
- Are agent settings, MCP definitions, and policy files protected by review, signatures, managed enforcement, immutable runtime, or rollback controls?
- Does configuration contain inline credential field indicators?

## Zero Trust Architecture Questions

- Is the influence boundary isolated from authority-bearing agent runtimes?
- Are repo, memory, web, or document instructions trust-gated before they can steer authority?
- Is runtime/tool authority constrained to least agency?
- Can authority reach sensitive data, private context, execution, or external destinations?
- Can private data leave only through approved external destinations?
- Can a model-callable tool change capability without allowlisting, pinning, descriptor integrity, authentication, or argument validation?
- Can a lower-trust delegated agent become a confused deputy for a more privileged parent agent?
- Do controls remove the path, or do they only add friction?
- Is agent identity scoped and attributable?
- Is the authenticated agent authorized only for named callers, context attributes, network segments, and tool scopes?
- Is persisted memory or context isolated from unrelated sessions and broad local authority?
- Would operators have enough audit evidence to reconstruct agent actions and approvals?
- Can suspicious agent behavior trigger containment that terminates sessions, revokes credentials, quarantines the workload, or reduces authority?
- Is the deployment governed by an inventory, accountable owner, approval process, risk tier, data classification, and review cadence?
- Can agent configuration be silently changed to widen authority or disable controls?

Ariadne reports these as `breaking`, `controlled`, `unknown`, or `not_observed`. It only reports `breaking` when deterministic facts and graph edges support the claim.

## Out Of Scope

- live exploit execution
- runtime behavioral sandbox bypass testing
- registry/package reputation checks
- live MCP descriptor retrieval, registry resolution, package digest verification, or signature validation
- cloud API collection
- non-deterministic LLM review
- identity provider, ABAC, JIT, token lifetime, segmentation, named-caller, or hardware-bound credential enforcement verification
- live inter-agent authorization, delegated credential downscoping, or subagent execution enforcement verification
- proxy, DNS, firewall, destination allowlist, webhook allowlist, or per-tool network-scope enforcement verification
- live prompt-injection resistance testing
- live observability, SIEM, telemetry ingestion, or tamper-resistant audit proof
- live SOAR execution, session termination, credential revocation, quarantine, or dynamic access-reduction enforcement proof
- live GRC, CMDB, approval workflow, policy exception, or organization-wide Shadow AI discovery verification
- Git branch protection, signature verification, MDM enforcement, admission policy, or rollback execution proof
- runtime enforcement

These are future layers. The deterministic layer must remain useful without them.
