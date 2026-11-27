---
name: agent-vault
description: Zero-knowledge secret manager, HTTP egress proxy, and output redactor for AI agents and MCP servers. Trigger whenever a command, script, or MCP server requires an API key, token, or password so secrets are never written in plaintext to .env or mcp_config.json or leaked into agent context.
---

# agent-vault

Use `agent-vault` whenever an agent, script, or MCP server needs credentials. Never ask the user to paste raw secrets into chat or store plaintext tokens in `.env` or `mcp_config.json`.

## When to Run Automatically

1. **Configuring a new MCP server** that needs `GITHUB_TOKEN`, `OPENAI_API_KEY`, `DATABASE_URL`, etc.
2. **Running CLI tools** that require secret environment variables while preventing accidental secret echo into terminal output.
3. **Connecting an agent to an authenticated HTTP API** without exposing the `Authorization` header to the agent.

## Workflow

1. Check if `agent-vault` is installed (`agent-vault --version`). If missing, install via `cargo install --git https://github.com/alexisrazok/agent-vault` or download from GitHub Releases.
2. Have the user store the secret securely in their own terminal (never ask them to paste it in chat):
   ```bash
   agent-vault set <SECRET_NAME>
   ```
3. Wrap the command or MCP server with `secret://` bindings (all `stdout`/`stderr` output is redacted automatically):
   ```bash
   agent-vault run --env <ENV_VAR>=secret://<SECRET_NAME> -- <command>
   ```
4. To generate an `mcpServers` JSON snippet for `mcp_config.json` or `claude_desktop_config.json`:
   ```bash
   agent-vault mcp-snippet <server_name> --env <ENV_VAR>=secret://<SECRET_NAME> -- <command>
   ```
5. For HTTP APIs, configure a route and start the local egress proxy:
   ```bash
   agent-vault route-add <route> --target https://api.example.com --header "Authorization: Bearer {{SECRET:<SECRET_NAME>}}"
   agent-vault proxy
   ```
