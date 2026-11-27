---
name: agent-vault
description: Manage secrets safely for AI agents and MCP servers using an XChaCha20-Poly1305 vault, HTTP secret-injecting egress proxy, and stdout/stderr redaction.
---

# agent-vault Skill

Use `agent-vault` whenever an agent or MCP server needs API credentials without exposing raw keys in `.env`, `mcp_config.json`, or terminal output.

## Commands

```bash
agent-vault set <NAME>
agent-vault list
agent-vault route-add <name> --target https://api.example.com --header "Authorization: Bearer {{SECRET:NAME}}"
agent-vault proxy
agent-vault run --env KEY=secret://NAME -- <command>
agent-vault mcp-snippet <server_name> --env KEY=secret://NAME -- <command>
```
