# Security Policy

## Reporting A Vulnerability

Please do not open a public issue for a suspected vulnerability.

Email security reports to the project maintainers. Include:

- affected version or commit
- reproduction steps
- expected impact
- whether any sensitive data was exposed
- suggested remediation, if known

We aim to acknowledge valid reports within 5 business days.

## Scope

In scope:

- secret leakage in Ariadne output
- unsafe execution during deterministic scans
- incorrect redaction behavior
- parser behavior that reads or emits private content unexpectedly
- vulnerabilities in the CLI or report generation

Out of scope:

- findings about deliberately vulnerable test fixtures
- reports requiring execution of third-party agent runtimes or MCP servers
- social engineering against maintainers

## Safety Guarantees

Ariadne's deterministic scan mode is designed not to execute agents, tool servers, package managers, or network calls. Any regression against that expectation is security-sensitive.
