import {
  KeyObject,
  createPrivateKey,
  createPublicKey,
  sign
} from "node:crypto";
import {
  DefaultAuthorizationType,
  HeaderAuthorization,
  HeaderBodySHA256,
  HeaderNonce,
  HeaderProof,
  HeaderTranscriptSHA256,
  SoftwareKeyBinding,
  buildRequest,
  type RequestInput
} from "./transcript.js";

export interface ProofInput {
  request: RequestInput;
  passportToken: string;
  privateKey: KeyObject;
  keyId?: string;
  signerClass?: string;
}

export interface SignedRequest {
  transcriptSHA256: string;
  bodySHA256: string;
  headers: Record<string, string>;
  canonicalLines: string[];
  keyId: string;
  signerClass: string;
}

interface PassportBinding {
  audience: string;
  jti: string;
  issuedAt: number;
  keyId: string;
  keyBinding: string;
  publicKeyB64URL: string;
}

const ed25519Pkcs8SeedPrefix = Buffer.from("302e020100300506032b657004220420", "hex");
const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");

export function signRequest(input: ProofInput): SignedRequest {
  const token = input.passportToken.trim();
  if (token === "") {
    throw new Error("missing_passport_token");
  }
  if (input.privateKey === undefined || input.privateKey === null) {
    throw new Error("missing_private_key");
  }
  if (input.privateKey.type !== "private" || input.privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("invalid_private_key_type");
  }

  const claims = parsePassportBinding(token);
  validatePassportBinding(claims, input.privateKey);
  validateSigningConsistency(input, claims);

  const { issuedAt: _issuedAt, ...requestWithoutDate } = input.request;
  const request: RequestInput = {
    ...requestWithoutDate,
    audience: claims.audience,
    passportJTI: claims.jti,
    issuedAtUnix: claims.issuedAt,
    keyBinding: SoftwareKeyBinding
  };

  const material = buildRequest(request);
  const digest = Buffer.from(material.transcriptSHA256, "hex");
  const proof = sign(null, digest, input.privateKey).toString("base64url");

  return {
    transcriptSHA256: material.transcriptSHA256,
    bodySHA256: material.bodySHA256,
    headers: {
      [HeaderAuthorization]: `${DefaultAuthorizationType} ${token}`,
      [HeaderTranscriptSHA256]: material.transcriptSHA256,
      [HeaderProof]: proof,
      [HeaderNonce]: (request.nonce ?? "").trim(),
      [HeaderBodySHA256]: material.bodySHA256
    },
    canonicalLines: [...material.canonicalLines],
    keyId: claims.keyId,
    signerClass: SoftwareKeyBinding
  };
}

export function ed25519PrivateKeyFromSeed(seed: Uint8Array): KeyObject {
  if (seed.byteLength !== 32) {
    throw new Error(`invalid_ed25519_seed_size: ${seed.byteLength}`);
  }
  return createPrivateKey({
    key: Buffer.concat([ed25519Pkcs8SeedPrefix, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8"
  });
}

function parsePassportBinding(token: string): PassportBinding {
  const parts = token.split(".");
  if (parts.length < 2 || parts[1] === undefined) {
    throw new Error("invalid_passport_token");
  }

  let payload: unknown;
  try {
    payload = JSON.parse(decodeBase64URLToBuffer(parts[1]).toString("utf8"));
  } catch (error) {
    throw new Error(`invalid_passport_token: ${messageFrom(error)}`);
  }

  if (!isRecord(payload)) {
    throw new Error("invalid_passport_token");
  }

  const cnf = isRecord(payload.cnf) ? payload.cnf : {};
  const issuedAt = numericUnix(payload.iat);
  if (issuedAt === undefined) {
    throw new Error("passport_missing_iat");
  }

  return {
    audience: audienceString(payload.aud),
    jti: claimString(payload.jti),
    issuedAt,
    keyId: claimString(cnf.kid),
    keyBinding: claimString(cnf.key_binding),
    publicKeyB64URL: claimString(cnf.public_key_b64url)
  };
}

function validatePassportBinding(claims: PassportBinding, privateKey: KeyObject): void {
  const required: Record<string, string> = {
    aud: claims.audience,
    jti: claims.jti,
    cnf_kid: claims.keyId,
    cnf_key_binding: claims.keyBinding,
    cnf_public_key_b64url: claims.publicKeyB64URL
  };

  for (const [name, value] of Object.entries(required)) {
    if (value.trim() === "") {
      throw new Error(`passport_missing_${name}`);
    }
    if (value !== value.trim()) {
      throw new Error(`passport_non_canonical_${name}`);
    }
  }

  if (claims.keyBinding !== SoftwareKeyBinding) {
    throw new Error("local_raw_key_supports_only_software_key_binding");
  }

  const publicKey = decodeCanonicalBase64URL(claims.publicKeyB64URL, "cnf_public_key_b64url");
  if (publicKey.byteLength !== 32) {
    throw new Error(`invalid_cnf_public_key_size: ${publicKey.byteLength}`);
  }

  const privatePublicKey = rawEd25519PublicKey(privateKey);
  if (!publicKey.equals(privatePublicKey)) {
    throw new Error("cnf_public_key_mismatch");
  }
}

function validateSigningConsistency(input: ProofInput, claims: PassportBinding): void {
  validateOptionalSoftware(input.request.keyBinding);
  validateOptionalSoftware(input.signerClass);

  const audience = input.request.audience?.trim() ?? "";
  if (audience !== "" && audience !== claims.audience) {
    throw new Error("passport_audience_mismatch");
  }

  const jti = input.request.passportJTI?.trim() ?? "";
  if (jti !== "" && jti !== claims.jti) {
    throw new Error("passport_jti_mismatch");
  }

  if (input.request.issuedAtUnix !== undefined && input.request.issuedAtUnix !== 0 && input.request.issuedAtUnix !== claims.issuedAt) {
    throw new Error("passport_iat_mismatch");
  }
  if (input.request.issuedAt !== undefined && Math.trunc(input.request.issuedAt.getTime() / 1000) !== claims.issuedAt) {
    throw new Error("passport_iat_mismatch");
  }

  const keyId = input.keyId?.trim() ?? "";
  if (keyId !== "" && keyId !== claims.keyId) {
    throw new Error("passport_cnf_kid_mismatch");
  }
}

function validateOptionalSoftware(value: string | undefined): void {
  if (value === undefined || value.trim() === "") {
    return;
  }
  if (value !== SoftwareKeyBinding) {
    throw new Error("local_raw_key_supports_only_software_key_binding");
  }
}

function rawEd25519PublicKey(privateKey: KeyObject): Buffer {
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ format: "der", type: "spki" });
  const raw = Buffer.from(spki);
  if (!raw.subarray(0, ed25519SpkiPrefix.byteLength).equals(ed25519SpkiPrefix)) {
    throw new Error("invalid_private_key_type");
  }
  return raw.subarray(ed25519SpkiPrefix.byteLength);
}

function decodeCanonicalBase64URL(value: string, name: string): Buffer {
  let decoded: Buffer;
  try {
    decoded = decodeBase64URLToBuffer(value);
  } catch (error) {
    throw new Error(`invalid_${name}: ${messageFrom(error)}`);
  }
  if (decoded.toString("base64url") !== value) {
    throw new Error(`non_canonical_${name}`);
  }
  return decoded;
}

function decodeBase64URLToBuffer(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error("invalid_base64url");
  }
  return Buffer.from(value, "base64url");
}

function claimString(raw: unknown): string {
  return typeof raw === "string" ? raw : "";
}

function audienceString(raw: unknown): string {
  if (typeof raw === "string" && raw !== "") {
    return raw;
  }
  if (Array.isArray(raw) && raw.length > 0) {
    return claimString(raw[0]);
  }
  return "";
}

function numericUnix(raw: unknown): number | undefined {
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw <= 0) {
    return undefined;
  }
  return raw;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function messageFrom(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
