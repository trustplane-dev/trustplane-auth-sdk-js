# Security Policy

Security reports should be sent to `maintainer@trustplane.dev`.

Do not file public issues for suspected vulnerabilities until the maintainer has had a reasonable opportunity to triage.

## Supported Scope

This repository supports caller-side TrustPlane Auth request signing helpers only:

- transcript-v1 material construction
- body SHA-256 helpers
- passport-bound signing claim parsing
- raw local Ed25519 software signing
- adapter-ready header construction

Verifier, broker, adapter, policy, deployment, enrollment, and Control-plane code are outside this repository.

## Security Principles

- Sign exactly what the verifier rebuilds.
- Treat passport-bound fields as authoritative.
- Reject conflicting caller-supplied consistency checks before signing.
- Keep raw local signing limited to the `software` key-binding class.
- Do not store or log private keys, passports, or local environment secrets.
