# TrustPlane Auth SDK for TypeScript

Preview TypeScript caller SDK for TrustPlane Auth request signing.

This package provides caller-side helpers for:

- building `transcript-v1` request material
- computing body SHA-256 values
- parsing passport claims needed by signing
- raw local Ed25519 software signing
- returning adapter-ready TrustPlane Auth headers

It does not include a verifier, broker, adapter, policy engine, SPIFFE issuer, deployment code, enrollment flow, or TrustPlane Control API.

## Install

Do not install from npm yet. Until a release exists, test this repository through a local checkout or packed tarball smoke test.

## Package Name

The npm package candidate is `@trustplane/auth-sdk`.

## Minimal Transcript Example

```ts
import {
  bodySHA256,
  buildRequest,
  SoftwareKeyBinding,
  type RequestInput
} from "@trustplane/auth-sdk";

const request: RequestInput = {
  method: "POST",
  scheme: "https",
  authority: "orders.example",
  path: "/v1/orders",
  audience: "orders-api",
  routeId: "orders.create",
  contentEncoding: "identity",
  body: `{"order_id":"ord_123","amount":"42.00"}`,
  headers: [
    { name: "Content-Type", value: "application/json" },
    { name: "X-TrustPlane-Nonce", value: "nonce-v1-001" }
  ],
  headerAllowList: ["content-type", "x-trustplane-nonce"],
  nonce: "nonce-v1-001",
  passportJTI: "passport-v1-minimal-001",
  issuedAtUnix: 1740000000,
  keyBinding: SoftwareKeyBinding
};

const material = buildRequest(request);

console.log({
  bodySHA256: bodySHA256(request.body),
  transcriptSHA256: material.transcriptSHA256
});
```

`signRequest` reads passport-bound fields from the passport and fails if caller-supplied consistency checks conflict. It does not infer or repair `aud`, `jti`, `iat`, `cnf.kid`, `cnf.key_binding`, or `cnf.public_key_b64url` from caller request inputs.

## Conformance Posture

`testdata/conformance/v1` contains public-safe contract vectors copied from the TrustPlane Auth reference. Tests assert exact canonical transcript lines, transcript SHA-256 values, and body SHA-256 values.

## Security Rule

This SDK signs only the verifier-rebuilt request transcript. Raw local signing is software-only and requires an Ed25519 private key whose public key exactly matches the passport `cnf.public_key_b64url` claim.
