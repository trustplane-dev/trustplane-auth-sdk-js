import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import {
  DefaultAuthorizationType,
  DefaultTimeBucketSeconds,
  HeaderAuthorization,
  HeaderBodySHA256,
  HeaderNonce,
  HeaderProof,
  HeaderTranscriptSHA256,
  SoftwareKeyBinding,
  bodySHA256,
  buildRequest,
  ed25519PrivateKeyFromSeed,
  signRequest,
  type Header,
  type ProofInput,
  type RequestInput
} from "../src/index.js";

const conformanceDir = "testdata/conformance/v1";
const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

interface TranscriptFixture {
  raw_request: {
    query: string;
    body_utf8: string;
    headers: Header[];
  };
  transcript: {
    method: string;
    scheme: string;
    authority: string;
    path: string;
    audience: string;
    route_id: string;
    content_encoding: string;
    headers: {
      allow_list: string[];
    };
    body_sha256: string;
    passport_jti: string;
    nonce: string;
    issued_at: number;
    key_binding: string;
  };
  canonical: {
    lines: string[];
    sha256: string;
  };
}

interface BodyFixture {
  vectors: Array<{
    id: string;
    bytes_utf8: string;
    sha256: string;
  }>;
}

test("buildRequest matches transcript-v1 conformance vectors", async () => {
  for (const name of [
    "transcript-v1.json",
    "transcript-v1.ambiguous-query-headers.json"
  ]) {
    const fixture = await readTranscriptFixture(name);
    const material = buildRequest(requestInputFromFixture(fixture));

    assert.equal(material.transcriptSHA256, fixture.canonical.sha256, name);
    assert.equal(material.bodySHA256, fixture.transcript.body_sha256, name);
    assert.deepEqual(material.canonicalLines, fixture.canonical.lines, name);
  }
});

test("bodySHA256 matches conformance vectors", async () => {
  const fixture = await readJSON<BodyFixture>("body-sha256-v1.json");

  for (const vector of fixture.vectors) {
    assert.equal(bodySHA256(vector.bytes_utf8), vector.sha256, vector.id);
  }
});

test("signRequest builds adapter-ready headers", async () => {
  const fixture = await readTranscriptFixture("transcript-v1.json");
  const privateKey = fixedKey();
  const publicKey = rawPublicKey(privateKey);
  const request = softwareRequestInputFromFixture(fixture);
  const token = fixtureTokenWithCNF(fixture, SoftwareKeyBinding, publicKey);
  const material = buildRequest(request);

  const signed = signRequest({
    request,
    passportToken: token,
    privateKey,
    keyId: "proof-key-1",
    signerClass: SoftwareKeyBinding
  });

  assert.equal(signed.headers[HeaderAuthorization], `${DefaultAuthorizationType} ${token}`);
  assert.equal(signed.headers[HeaderTranscriptSHA256], material.transcriptSHA256);
  assert.equal(signed.headers[HeaderNonce], fixture.transcript.nonce);
  assert.equal(signed.headers[HeaderBodySHA256], fixture.transcript.body_sha256);
  assert.ok(signed.headers[HeaderProof]);
  assert.equal(signed.keyId, "proof-key-1");
  assert.equal(signed.signerClass, SoftwareKeyBinding);

  const digest = Buffer.from(signed.transcriptSHA256, "hex");
  const signature = Buffer.from(signed.headers[HeaderProof] ?? "", "base64url");
  assert.equal(verify(null, digest, createPublicKey(privateKey), signature), true);
});

test("signRequest derives request binding from valid passport without repairing passport claims", async () => {
  const fixture = await readTranscriptFixture("transcript-v1.ambiguous-query-headers.json");
  const privateKey = fixedKey();
  const publicKey = rawPublicKey(privateKey);
  const wantRequest = softwareRequestInputFromFixture(fixture);
  const want = buildRequest(wantRequest);
  const request: RequestInput = {
    ...wantRequest,
    audience: "",
    passportJTI: "",
    issuedAtUnix: 0,
    keyBinding: ""
  };

  const signed = signRequest({
    request,
    passportToken: fixtureTokenWithCNF(fixture, SoftwareKeyBinding, publicKey),
    privateKey
  });

  assert.equal(signed.transcriptSHA256, want.transcriptSHA256);
});

test("signRequest rejects passport binding failures", async () => {
  const fixture = await readTranscriptFixture("transcript-v1.json");
  const privateKey = fixedKey();
  const publicKey = rawPublicKey(privateKey);
  const otherPublicKey = rawPublicKey(otherFixedKey());
  const request = softwareRequestInputFromFixture(fixture);

  const cases: Array<{ name: string; token: string; want: RegExp }> = [
    {
      name: "missing audience",
      token: fixtureTokenWithClaims(fixture, SoftwareKeyBinding, publicKey, { aud: "" }),
      want: /passport_missing_aud/
    },
    {
      name: "missing jti",
      token: fixtureTokenWithClaims(fixture, SoftwareKeyBinding, publicKey, { jti: "" }),
      want: /passport_missing_jti/
    },
    {
      name: "missing iat",
      token: fixtureTokenWithClaims(fixture, SoftwareKeyBinding, publicKey, { iat: undefined }),
      want: /passport_missing_iat/
    },
    {
      name: "missing kid",
      token: fixtureTokenWithCNFRaw(fixture, SoftwareKeyBinding, publicKey.toString("base64url"), { kid: "" }),
      want: /passport_missing_cnf_kid/
    },
    {
      name: "missing key binding",
      token: fixtureTokenWithCNFRaw(fixture, "", publicKey.toString("base64url")),
      want: /passport_missing_cnf_key_binding/
    },
    {
      name: "non-software key binding",
      token: fixtureTokenWithCNF(fixture, "hardware_local", publicKey),
      want: /local_raw_key_supports_only_software_key_binding/
    },
    {
      name: "missing public key",
      token: fixtureTokenWithCNFRaw(fixture, SoftwareKeyBinding, ""),
      want: /passport_missing_cnf_public_key_b64url/
    },
    {
      name: "malformed public key",
      token: fixtureTokenWithCNFRaw(fixture, SoftwareKeyBinding, "not base64url"),
      want: /invalid_cnf_public_key_b64url/
    },
    {
      name: "wrong public key length",
      token: fixtureTokenWithCNFRaw(fixture, SoftwareKeyBinding, Buffer.from("short").toString("base64url")),
      want: /invalid_cnf_public_key_size/
    },
    {
      name: "mismatched public key",
      token: fixtureTokenWithCNF(fixture, SoftwareKeyBinding, otherPublicKey),
      want: /cnf_public_key_mismatch/
    }
  ];

  for (const tt of cases) {
    assert.throws(
      () => signRequest({ request, passportToken: tt.token, privateKey }),
      tt.want,
      tt.name
    );
  }
});

test("caller input cannot repair missing passport-bound fields", async () => {
  const fixture = await readTranscriptFixture("transcript-v1.json");
  const privateKey = fixedKey();
  const publicKey = rawPublicKey(privateKey);
  const request = softwareRequestInputFromFixture(fixture);

  const cases: Array<{ name: string; token: string; want: RegExp }> = [
    {
      name: "request audience cannot repair missing aud",
      token: fixtureTokenWithClaims(fixture, SoftwareKeyBinding, publicKey, { aud: "" }),
      want: /passport_missing_aud/
    },
    {
      name: "request jti cannot repair missing jti",
      token: fixtureTokenWithClaims(fixture, SoftwareKeyBinding, publicKey, { jti: "" }),
      want: /passport_missing_jti/
    },
    {
      name: "request iat cannot repair missing iat",
      token: fixtureTokenWithClaims(fixture, SoftwareKeyBinding, publicKey, { iat: undefined }),
      want: /passport_missing_iat/
    },
    {
      name: "input key id cannot repair missing kid",
      token: fixtureTokenWithCNFRaw(fixture, SoftwareKeyBinding, publicKey.toString("base64url"), { kid: "" }),
      want: /passport_missing_cnf_kid/
    },
    {
      name: "request key binding cannot repair missing key binding",
      token: fixtureTokenWithCNFRaw(fixture, "", publicKey.toString("base64url")),
      want: /passport_missing_cnf_key_binding/
    },
    {
      name: "private key cannot repair missing public key",
      token: fixtureTokenWithCNFRaw(fixture, SoftwareKeyBinding, ""),
      want: /passport_missing_cnf_public_key_b64url/
    }
  ];

  for (const tt of cases) {
    assert.throws(
      () => signRequest({ request, passportToken: tt.token, privateKey, keyId: "proof-key-1" }),
      tt.want,
      tt.name
    );
  }
});

test("signRequest rejects caller field conflicts", async () => {
  const fixture = await readTranscriptFixture("transcript-v1.json");
  const privateKey = fixedKey();
  const publicKey = rawPublicKey(privateKey);
  const token = fixtureTokenWithCNF(fixture, SoftwareKeyBinding, publicKey);
  const base = softwareRequestInputFromFixture(fixture);

  const cases: Array<{
    name: string;
    mutate: (request: RequestInput, input: ProofInput) => void;
    want: RegExp;
  }> = [
    {
      name: "audience conflict",
      mutate: (request) => {
        request.audience = "other-api";
      },
      want: /passport_audience_mismatch/
    },
    {
      name: "jti conflict",
      mutate: (request) => {
        request.passportJTI = "other-jti";
      },
      want: /passport_jti_mismatch/
    },
    {
      name: "iat conflict",
      mutate: (request) => {
        request.issuedAtUnix = fixture.transcript.issued_at + 1;
      },
      want: /passport_iat_mismatch/
    },
    {
      name: "kid conflict",
      mutate: (_request, input) => {
        input.keyId = "other-kid";
      },
      want: /passport_cnf_kid_mismatch/
    },
    {
      name: "request key binding conflict",
      mutate: (request) => {
        request.keyBinding = "hardware_local";
      },
      want: /local_raw_key_supports_only_software_key_binding/
    },
    {
      name: "signer class conflict",
      mutate: (_request, input) => {
        input.signerClass = "attested_workload";
      },
      want: /local_raw_key_supports_only_software_key_binding/
    }
  ];

  for (const tt of cases) {
    const request = { ...base };
    const input: ProofInput = { request, passportToken: token, privateKey, keyId: "proof-key-1" };
    tt.mutate(request, input);
    assert.throws(() => signRequest(input), tt.want, tt.name);
  }
});

test("request binding changes affect transcript and proof", async () => {
  const fixture = await readTranscriptFixture("transcript-v1.json");
  const privateKey = fixedKey();
  const publicKey = rawPublicKey(privateKey);
  const token = fixtureTokenWithCNF(fixture, SoftwareKeyBinding, publicKey);
  const base = softwareRequestInputFromFixture(fixture);
  const changed: RequestInput = {
    ...base,
    nonce: "nonce-v1-002",
    headers: [
      { name: "Content-Type", value: "application/json" },
      { name: "X-TrustPlane-Nonce", value: "nonce-v1-002" }
    ]
  };

  const one = signRequest({ request: base, passportToken: token, privateKey });
  const two = signRequest({ request: changed, passportToken: token, privateKey });

  assert.notEqual(two.transcriptSHA256, one.transcriptSHA256);
  assert.notEqual(two.headers[HeaderProof], one.headers[HeaderProof]);
  assert.notDeepEqual(two.canonicalLines, one.canonicalLines);
});

test("missing inputs return clear errors", () => {
  assert.throws(() => buildRequest({}), /missing_/);
  assert.throws(
    () => signRequest({ request: {}, passportToken: "", privateKey: fixedKey() }),
    /missing_passport_token/
  );
  assert.throws(
    () => signRequest({ request: {}, passportToken: "header.payload.signature", privateKey: undefined as unknown as KeyObject }),
    /missing_private_key/
  );
});

function requestInputFromFixture(fixture: TranscriptFixture): RequestInput {
  return {
    method: fixture.transcript.method,
    scheme: fixture.transcript.scheme,
    authority: fixture.transcript.authority,
    path: fixture.transcript.path,
    rawQuery: fixture.raw_request.query,
    audience: fixture.transcript.audience,
    routeId: fixture.transcript.route_id,
    contentEncoding: fixture.transcript.content_encoding,
    body: fixture.raw_request.body_utf8,
    headers: fixture.raw_request.headers,
    headerAllowList: fixture.transcript.headers.allow_list,
    passportJTI: fixture.transcript.passport_jti,
    nonce: fixture.transcript.nonce,
    issuedAtUnix: fixture.transcript.issued_at,
    keyBinding: fixture.transcript.key_binding,
    timeBucketSeconds: DefaultTimeBucketSeconds
  };
}

function softwareRequestInputFromFixture(fixture: TranscriptFixture): RequestInput {
  return {
    ...requestInputFromFixture(fixture),
    keyBinding: SoftwareKeyBinding
  };
}

async function readTranscriptFixture(name: string): Promise<TranscriptFixture> {
  return readJSON<TranscriptFixture>(name);
}

async function readJSON<T>(name: string): Promise<T> {
  const raw = await readFile(join(conformanceDir, name), "utf8");
  return JSON.parse(raw) as T;
}

function fixedKey(): KeyObject {
  return ed25519PrivateKeyFromSeed(new Uint8Array([
    0, 1, 2, 3, 4, 5, 6, 7,
    8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 26, 27, 28, 29, 30, 31
  ]));
}

function otherFixedKey(): KeyObject {
  return ed25519PrivateKeyFromSeed(new Uint8Array([
    31, 30, 29, 28, 27, 26, 25, 24,
    23, 22, 21, 20, 19, 18, 17, 16,
    15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0
  ]));
}

function rawPublicKey(privateKey: KeyObject): Buffer {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(ed25519SpkiPrefix.byteLength);
}

function fixtureTokenWithCNF(fixture: TranscriptFixture, keyBinding: string, publicKey: Buffer): string {
  return fixtureTokenWithCNFRaw(fixture, keyBinding, publicKey.toString("base64url"));
}

function fixtureTokenWithCNFRaw(
  fixture: TranscriptFixture,
  keyBinding: string,
  publicKeyB64URL: string,
  cnfOverride: Record<string, unknown> = {}
): string {
  const cnf: Record<string, unknown> = { kid: "proof-key-1" };
  if (keyBinding !== "") {
    cnf.key_binding = keyBinding;
  }
  if (publicKeyB64URL !== "") {
    cnf.public_key_b64url = publicKeyB64URL;
  }
  for (const [key, value] of Object.entries(cnfOverride)) {
    if (value === undefined) {
      delete cnf[key];
    } else {
      cnf[key] = value;
    }
  }
  return fixtureTokenWithClaims(fixture, keyBinding, undefined, { cnf });
}

function fixtureTokenWithClaims(
  fixture: TranscriptFixture,
  keyBinding: string,
  publicKey: Buffer | undefined,
  overrides: Record<string, unknown>
): string {
  const cnf: Record<string, unknown> = { kid: "proof-key-1" };
  if (keyBinding !== "") {
    cnf.key_binding = keyBinding;
  }
  if (publicKey !== undefined) {
    cnf.public_key_b64url = publicKey.toString("base64url");
  }

  const payload: Record<string, unknown> = {
    aud: fixture.transcript.audience,
    iat: fixture.transcript.issued_at,
    jti: fixture.transcript.passport_jti,
    cnf
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete payload[key];
    } else {
      payload[key] = value;
    }
  }

  return `${encodeJWTPart({ alg: "EdDSA", typ: "JWT" })}.${encodeJWTPart(payload)}.signature`;
}

function encodeJWTPart(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
