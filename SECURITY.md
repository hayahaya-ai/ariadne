# Security Policy

Ariadne is a read-only local posture scanner for AI coding-agent setups.

## Safety Model

The scanner must:

- Never execute discovered commands, package managers, shell scripts, or MCP servers.
- Never upload scan data.
- Never read secret values intentionally.
- Redact home paths, usernames, token-like strings, credential URLs, and sensitive filenames by default.
- Treat malformed configs as findings, not crashes.
- Block symlink escapes outside the scan root in repo mode.
- Enforce file-size, recursion, file-count, and timeout limits.

## Reporting Issues

For now, report security issues privately to the repository owner once the public repo is created.

Good reports include:

- Scanner version or commit.
- Operating system.
- Scan mode.
- Minimal reproduction fixture.
- Whether secret values or sensitive paths appeared in output.

Do not include real credentials, internal hostnames, or private repository contents in reports.

## Current Limitations

Ariadne reports static posture. It does not prove actual runtime access to files, VPN networks, sandboxes, MCP tool behavior, or endpoint controls.
