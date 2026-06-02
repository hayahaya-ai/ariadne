# Privacy Contract

Ariadne is designed to be safe to run in sensitive repositories.

## Collected

- Agent configuration metadata.
- Declared sandbox, approval, network, deny-read, and MCP settings.
- Repo context such as root, remote, and instruction-file presence.
- Devcontainer metadata relevant to runtime boundary risk.

## Not Collected

- Secret values.
- Prompt transcripts.
- Source file contents beyond bounded instruction/config files.
- Runtime process lists.
- Network traffic.
- Browser state.

## Execution Safety

The scanner must not execute:

- agent binaries
- MCP servers
- package managers
- shell scripts
- repo commands

## Reports

Reports are redacted by default but should still be treated as sensitive security artifacts.
They may reveal internal repo names, agent configuration posture, and MCP/tool inventory.

## Runtime Limitations

The scanner reports detected posture only. It does not prove runtime access, sandbox
enforcement, VPN reachability, or exploitability.
