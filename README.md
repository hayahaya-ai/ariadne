# Ariadne

Ariadne is a local, read-only posture scanner for AI coding-agent setups.
It focuses on Claude Code, Codex, and MCP configuration risk.

The scanner is intentionally narrow:

- It does not execute discovered commands.
- It does not start MCP servers.
- It does not read secret values.
- It does not upload data.
- It reports detected posture, not runtime enforcement.

The differentiator is attack-path synthesis: individual findings are combined into
CISO-readable abuse paths such as network-enabled agent posture plus missing
secret-deny coverage plus unknown MCP servers.

## Usage

```bash
make test
make build

go run ./cmd/ariadne doctor --mode endpoint
go run ./cmd/ariadne scan --mode repo --path .
go run ./cmd/ariadne scan --mode repo --format json --out report.json
go run ./cmd/ariadne scan --mode repo --format markdown --out report.md
go run ./cmd/ariadne scan --mode repo --format sarif --out ariadne.sarif --fail-on high
go run ./cmd/ariadne remediate --input report.json
```

Scan modes:

- `repo`: repo-local files only; safe for CI.
- `endpoint`: repo plus user/system agent configs.
- `devbox`: repo plus devcontainer/devbox indicators.

## What It Flags

- YOLO, bypass, and full-access modes.
- Network-enabled agent config.
- Missing enterprise-managed policy evidence.
- Missing deny-read policy coverage for common secret-adjacent paths.
- Unknown MCP servers.
- MCP launched through `npx`, `uvx`, `node`, `python`, `docker`, or shell.
- Broad filesystem MCP access.
- Non-HTTPS remote MCP.
- Risky agent instruction files.
- Risky devcontainer settings like Docker socket, privileged mode, host network, and secret mounts.
- Missing audit/telemetry hints where supported.

## Important Limit

Ariadne is a static scanner. It cannot prove whether an agent can actually
read a file, reach a VPN service, or is contained by a sandbox at runtime.
Findings use language like "declared config" and "not runtime-verified" on purpose.

## Tests

```bash
GOCACHE=/private/tmp/ariadne-gocache go test ./...
```

## Project Status

This is an early scanner-first implementation. Built-in Go rules are the primary
policy engine. Optional Rego/custom policy support is not implemented yet.
