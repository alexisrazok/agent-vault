# Changelog

## [0.1.0] - 2026-11-27

### Added
- Initial Rust release of `agent-vault`.
- `XChaCha20-Poly1305` + `Argon2id` encrypted local vault with `zeroize` memory wiping.
- Local HTTP egress proxy (`agent-vault proxy`) with route-scoped secret injection, path traversal protection, and multi-encoding response redaction (raw, Base64, URL-encoded).
- Subprocess wrapper (`agent-vault run`) with real-time `stdout`/`stderr` redaction and `mcp-snippet` generator.
- `skill/SKILL.md` for AI agent integration.
