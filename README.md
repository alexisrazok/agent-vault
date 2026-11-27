# agent-vault

[![CI](https://github.com/alexisrazok/agent-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/alexisrazok/agent-vault/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/alexisrazok/agent-vault)](https://github.com/alexisrazok/agent-vault/releases)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Proxy local de secretos y limpiador de salidas en tiempo real escrito en Rust para que agentes de código y servidores MCP usen APIs sin ver tus claves reales en disco ni en su ventana de contexto.

## El problema que resuelve

Dar acceso a APIs externas a un agente o a un servidor MCP suele obligar a guardar tokens en texto plano dentro de `.env`, `mcp_config.json` o variables de entorno globales. En ese escenario:

1. **Los archivos de configuración quedan expuestos**: cualquier herramienta o comando que lea el proyecto puede acceder a las claves en claro.
2. **Fugas por salida de terminal o errores**: un script que imprima `env`, un error HTTP detallado o un endpoint que devuelva cabeceras puede meter el token real directamente en la ventana de contexto del modelo.

`agent-vault` separa las credenciales del agente: cifra las claves en local, las inyecta solo en el último salto (subproceso o proxy HTTP por ruta) y censura cualquier aparición del secreto en las respuestas.

## Características de seguridad

- **Cifrado autenticado en reposo**: `XChaCha20-Poly1305` con derivación `Argon2id` en `~/.agent-vault/vault.enc` y limpieza de memoria con `zeroize`.
- **Proxy HTTP por ruta (`agent-vault proxy`)**: inyecta cabeceras (`{{SECRET:NOMBRE}}`) únicamente hacia el destino configurado, bloquea *path traversal* (`..`), elimina cabeceras `Authorization`/`Cookie` entrantes y exige `https://` por defecto.
- **Censura anti-fugas multicapa**: limpia de las respuestas y de `stdout`/`stderr` tanto el secreto en claro como sus variantes en Base64 y URL-encoded (`[REDACTED:NOMBRE]`).
- **Wrapper de subprocesos y MCP (`agent-vault run`)**: resuelve `secret://NOMBRE` solo en el entorno del subproceso y filtra la salida en tiempo real.

## Instalación

### Desde crates.io con Cargo
```bash
cargo install agent-vault-cli
```

### Binarios precompilados (Linux, macOS, Windows)
Descarga el binario correspondiente a tu sistema operativo desde la página de [Releases](https://github.com/alexisrazok/agent-vault/releases/latest).

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

## FAQ

**¿Por qué el paquete en crates.io se llama `agent-vault-cli`?**
El nombre `agent-vault` ya estaba ocupado en `crates.io`, pero al instalar `agent-vault-cli` el binario resultante en tu terminal sigue siendo `agent-vault`.

**¿Funciona sin entorno gráfico o en servidores Linux sin keyring?**
Sí. Usa un almacén cifrado local (`~/.agent-vault/vault.enc`) con `XChaCha20-Poly1305` y `Argon2id` que no depende de librerías gráficas ni de D-Bus, y también funciona en Windows y macOS.

**¿Qué pasa si un servidor intenta devolver el token codificado?**
Además del valor en claro, el filtro de salida censura automáticamente las variantes en Base64 y URL-encoded de cada secreto almacenado.

## Desarrollo, Seguridad y Licencia

- Guía de contribución: [CONTRIBUTING.md](CONTRIBUTING.md)
- Política de seguridad: [SECURITY.md](SECURITY.md)
- Historial de cambios: [CHANGELOG.md](CHANGELOG.md)
- Licencia: [Apache-2.0](LICENSE) y [NOTICE](NOTICE)
