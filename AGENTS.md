# Repository Guardrails

- Keep this repo to caller-side TrustPlane Auth SDK helpers only.
- Do not copy auth runtime, verifier, broker, adapter, bundle policy engine, SPIFFE issuance, deployment, enrollment, or Control-plane code here.
- Do not import private `trustplane-auth` packages.
- Do not claim package availability, source availability, or current release state before a verified release exists.
- Do not include secrets, local paths, private cluster details, tokens, or private operational strings.
- Do not use `[codex]` in branch names, commit messages, or PR titles.
- Use `Medh Mesh <maintainer@trustplane.dev>` for commit author and committer identity.
- Release tags and release workflows must also configure and use `Medh Mesh <maintainer@trustplane.dev>`.
