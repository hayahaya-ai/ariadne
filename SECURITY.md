# Security Policy

Please do not open a public issue for suspected vulnerabilities.

Security-sensitive areas include:

- secret leakage in Ariadne output
- unsafe execution during deterministic scans
- incorrect redaction behavior
- parser behavior that reads or emits private content unexpectedly
- vulnerabilities in CLI or report generation

Ariadne's deterministic scan mode is designed not to execute agents, tool servers, package managers, or network calls. Any regression against that expectation is security-sensitive.

Detailed policy: [ariadne-prove/SECURITY.md](ariadne-prove/SECURITY.md).
