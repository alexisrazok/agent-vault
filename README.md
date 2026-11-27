# agent-vault

Proxy local de secretos y limpiador de salidas en tiempo real escrito en Rust para que agentes de código y servidores MCP usen APIs sin ver tus claves reales en disco ni en su ventana de contexto.

## Características de seguridad

- **Cifrado autenticado en reposo**: `XChaCha20-Poly1305` con derivación `Argon2id` en `~/.agent-vault/vault.enc` y limpieza de memoria con `zeroize`.
- **Proxy HTTP por ruta (`agent-vault proxy`)**: inyecta cabeceras (`{{SECRET:NOMBRE}}`) únicamente hacia el destino configurado, bloquea *path traversal* (`..`), elimina cabeceras `Authorization`/`Cookie` entrantes y exige `https://` por defecto.
- **Censura anti-fugas multicapa**: limpia de las respuestas y de `stdout`/`stderr` tanto el secreto en claro como sus variantes en Base64 y URL-encoded (`[REDACTED:NOMBRE]`).
- **Wrapper de subprocesos y MCP (`agent-vault run`)**: resuelve `secret://NOMBRE` solo en el entorno del subproceso y filtra la salida en tiempo real.

## Instalación

```bash
cargo install --git https://github.com/alexisrazok/agent-vault
```

## Uso rápido

```bash
# 1. Guardar un secreto (entrada oculta)
agent-vault set GITHUB_TOKEN

# 2. Configurar una ruta HTTP y arrancar el proxy
agent-vault route-add github --target https://api.github.com --header "Authorization: Bearer {{SECRET:GITHUB_TOKEN}}"
agent-vault proxy

# 3. O envolver un servidor MCP / comando directamente
agent-vault run --env GITHUB_TOKEN=secret://GITHUB_TOKEN -- npx -y @modelcontextprotocol/server-github

# 4. Generar JSON listo para mcp_config.json
agent-vault mcp-snippet github --env GITHUB_TOKEN=secret://GITHUB_TOKEN -- npx -y @modelcontextprotocol/server-github
```

## Tests

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
