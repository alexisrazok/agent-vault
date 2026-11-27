# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in `agent-vault` (e.g., secret leakage, cryptographic weakness, SSRF, or redaction bypass), please report it privately via GitHub Security Advisories.

## Security Architecture

- **Encryption**: Secrets are encrypted at rest with `XChaCha20-Poly1305` and keys derived via `Argon2id` with random 16-byte salt and 24-byte nonce.
- **Memory Hygiene**: Key material and decrypted secrets are wrapped in `zeroize::Zeroizing` so they are wiped from memory on drop.
- **Egress Protection**: Plaintext HTTP upstreams are rejected by default (only `https://` or `http://127.0.0.1` / `http://localhost` are allowed unless `--allow-insecure-http` is explicitly passed).
- **Redaction**: Responses and subprocess `stdout`/`stderr` are scrubbed for raw, Base64-encoded, and URL-encoded forms of stored secrets.
