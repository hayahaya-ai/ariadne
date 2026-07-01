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

## Supported Exposure Questions

- Can untrusted instructions influence an agent with private-data access?
- Can the agent reach secret-like local boundaries?
- Can a mutable tool launcher grant local execution?
- Can private-data reachability combine with external communication reachability?
- Does a declared control break a modeled path?

## Zero Trust Architecture Questions

- Is the influence boundary isolated from authority-bearing agent runtimes?
- Is runtime/tool authority constrained to least agency?
- Can authority reach sensitive data, private context, execution, or external destinations?
- Do controls remove the path, or do they only add friction?
- Is agent identity scoped and attributable?
- Is persisted memory or context isolated from unrelated sessions and broad local authority?
- Would operators have enough audit evidence to reconstruct agent actions and approvals?

Ariadne reports these as `breaking`, `controlled`, `unknown`, or `not_observed`. It only reports `breaking` when deterministic facts and graph edges support the claim.

## Out Of Scope

- live exploit execution
- runtime behavioral sandbox bypass testing
- registry/package reputation checks
- cloud API collection
- non-deterministic LLM review
- identity provider, ABAC, JIT, or hardware-bound credential verification
- live observability, SIEM, or telemetry ingestion
- runtime enforcement

These are future layers. The deterministic layer must remain useful without them.
