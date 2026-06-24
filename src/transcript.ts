import { createHash } from "node:crypto";

export const HeaderAuthorization = "Authorization";
export const HeaderBodySHA256 = "X-TrustPlane-Body-SHA256";
export const HeaderNonce = "X-TrustPlane-Nonce";
export const HeaderProof = "X-TrustPlane-Proof";
export const HeaderTranscriptSHA256 = "X-TrustPlane-Transcript-SHA256";

export const DefaultAuthorizationType = "Bearer";
export const SoftwareKeyBinding = "software";

export const TranscriptV1Version = "trustplane-transcript-v1";
export const TranscriptV1Kind = "request_transcript";
export const TranscriptV1Format = "trustplane-transcript-v1-lines";
export const QueryNormalizationRFC3986 = "rfc3986-sort-keys-values";
export const DefaultTimeBucketSeconds = 20;

const transcriptV1CoveredFields = [
  "method",
  "scheme",
  "authority",
  "path",
  "audience",
  "route_id",
  "content_encoding",
  "query_normalization.algorithm",
  "query_normalization.normalized",
  "query_normalization.sha256",
  "query_sha256",
  "headers.allow_list",
  "headers.selected",
  "body_sha256",
  "passport_jti",
  "nonce",
  "issued_at",
  "time_bucket",
  "key_binding"
] as const;

export interface Header {
  name: string;
  value: string;
}

export interface RequestInput {
  method?: string;
  scheme?: string;
  authority?: string;
  path?: string;
  rawQuery?: string;
  audience?: string;
  routeId?: string;
  contentEncoding?: string;
  body?: Uint8Array | string;
  bodySHA256?: string;
  headers?: readonly Header[];
  headerAllowList?: readonly string[];
  nonce?: string;
  issuedAt?: Date;
  issuedAtUnix?: number;
  passportJTI?: string;
  keyBinding?: string;
  timeBucketSeconds?: number;
}

export interface RequestMaterial {
  transcriptSHA256: string;
  bodySHA256: string;
  canonicalLines: string[];
}

interface TranscriptV1 {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  audience: string;
  routeId: string;
  contentEncoding: string;
  queryNormalization: QueryNormalization;
  querySHA256: string;
  headers: TranscriptHeaders;
  bodySHA256: string;
  passportJTI: string;
  nonce: string;
  issuedAt: number;
  timeBucket: number;
  keyBinding: string;
  coveredFields: readonly string[];
}

interface QueryNormalization {
  algorithm: string;
  normalized: string;
  sha256: string;
}

interface TranscriptHeaders {
  allowList: string[];
  selected: SelectedHeader[];
}

interface SelectedHeader {
  name: string;
  valueSHA256: string;
}

export function buildRequest(input: RequestInput): RequestMaterial {
  const transcript = buildTranscript(input);
  const canonicalLines = canonicalLinesFor(transcript);

  return {
    transcriptSHA256: sha256Hex(canonicalLines.join("\n")),
    bodySHA256: transcript.bodySHA256,
    canonicalLines
  };
}

function buildTranscript(input: RequestInput): TranscriptV1 {
  let issuedAt = input.issuedAtUnix ?? 0;
  if (issuedAt === 0 && input.issuedAt !== undefined) {
    issuedAt = Math.trunc(input.issuedAt.getTime() / 1000);
  }

  const bucketSeconds = input.timeBucketSeconds ?? DefaultTimeBucketSeconds;
  if (!Number.isInteger(bucketSeconds) || bucketSeconds < 0) {
    throw new Error("invalid_time_bucket_seconds");
  }

  const bodyDigest = input.bodySHA256?.trim() || bodySHA256(input.body);
  const rawQuery = trimLeadingQuestionMark((input.rawQuery ?? "").trim());
  const normalizedQuery = normalizeQueryRFC3986SortKeysValues(rawQuery);
  const queryDigest = sha256Hex(normalizedQuery);
  const allowList = canonicalAllowList(input.headerAllowList ?? []);
  const selected = selectHeaders(input.headers ?? [], allowList);

  const transcript: TranscriptV1 = {
    method: (input.method ?? "").trim().toUpperCase(),
    scheme: (input.scheme ?? "").trim().toLowerCase(),
    authority: (input.authority ?? "").trim().toLowerCase(),
    path: (input.path ?? "").trim(),
    audience: (input.audience ?? "").trim(),
    routeId: (input.routeId ?? "").trim(),
    contentEncoding: (input.contentEncoding ?? "").trim().toLowerCase() || "identity",
    queryNormalization: {
      algorithm: QueryNormalizationRFC3986,
      normalized: normalizedQuery,
      sha256: queryDigest
    },
    querySHA256: queryDigest,
    headers: {
      allowList,
      selected
    },
    bodySHA256: bodyDigest,
    passportJTI: (input.passportJTI ?? "").trim(),
    nonce: (input.nonce ?? "").trim(),
    issuedAt,
    timeBucket: bucketSeconds === 0 ? 0 : Math.trunc(issuedAt / bucketSeconds),
    keyBinding: (input.keyBinding ?? "").trim(),
    coveredFields: transcriptV1CoveredFields
  };

  validateTranscript(transcript);
  return transcript;
}

function canonicalLinesFor(transcript: TranscriptV1): string[] {
  return [
    `version=${TranscriptV1Version}`,
    `method=${transcript.method}`,
    `scheme=${transcript.scheme}`,
    `authority=${transcript.authority}`,
    `path=${transcript.path}`,
    `audience=${transcript.audience}`,
    `route_id=${transcript.routeId}`,
    `content_encoding=${transcript.contentEncoding}`,
    `query_normalization.algorithm=${transcript.queryNormalization.algorithm}`,
    `query_normalization.normalized=${transcript.queryNormalization.normalized}`,
    `query_normalization.sha256=${transcript.queryNormalization.sha256}`,
    `query_sha256=${transcript.querySHA256}`,
    `headers.allow_list=${transcript.headers.allowList.join(",")}`,
    `headers.selected=${selectedHeaderLine(transcript.headers.selected)}`,
    `body_sha256=${transcript.bodySHA256}`,
    `passport_jti=${transcript.passportJTI}`,
    `nonce=${transcript.nonce}`,
    `issued_at=${transcript.issuedAt}`,
    `time_bucket=${transcript.timeBucket}`,
    `key_binding=${transcript.keyBinding}`
  ];
}

function normalizeQueryRFC3986SortKeysValues(raw: string): string {
  if (raw === "") {
    return "";
  }

  const pairs = raw.split("&").map((part, index) => {
    const separator = part.indexOf("=");
    const keyRaw = separator === -1 ? part : part.slice(0, separator);
    const valueRaw = separator === -1 ? "" : part.slice(separator + 1);

    return {
      key: encodeRFC3986(decodeURIComponent(keyRaw)),
      value: encodeRFC3986(decodeURIComponent(valueRaw)),
      index
    };
  });

  pairs.sort((a, b) => {
    if (a.key !== b.key) {
      return a.key < b.key ? -1 : 1;
    }
    if (a.value !== b.value) {
      return a.value < b.value ? -1 : 1;
    }
    return a.index - b.index;
  });

  return pairs.map((pair) => `${pair.key}=${pair.value}`).join("&");
}

function validateTranscript(transcript: TranscriptV1): void {
  const required: Record<string, string> = {
    method: transcript.method,
    scheme: transcript.scheme,
    authority: transcript.authority,
    path: transcript.path,
    audience: transcript.audience,
    route_id: transcript.routeId,
    content_encoding: transcript.contentEncoding,
    "query_normalization.algorithm": transcript.queryNormalization.algorithm,
    "query_normalization.sha256": transcript.queryNormalization.sha256,
    query_sha256: transcript.querySHA256,
    body_sha256: transcript.bodySHA256,
    passport_jti: transcript.passportJTI,
    nonce: transcript.nonce,
    key_binding: transcript.keyBinding
  };

  for (const [name, value] of Object.entries(required)) {
    if (value === "") {
      throw new Error(`missing_${name.replaceAll(".", "_")}`);
    }
  }

  if (transcript.issuedAt === 0) {
    throw new Error("missing_issued_at");
  }
  if (transcript.headers.allowList.length !== transcript.headers.selected.length) {
    throw new Error("missing_selected_headers");
  }
}

function canonicalAllowList(allowList: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];

  for (const rawName of allowList) {
    const name = rawName.trim().toLowerCase();
    if (name === "" || seen.has(name)) {
      continue;
    }
    seen.add(name);
    out.push(name);
  }

  return out.sort();
}

function selectHeaders(headers: readonly Header[], allowList: readonly string[]): SelectedHeader[] {
  const rawByName = new Map<string, string>();

  for (const header of headers) {
    const name = header.name.trim().toLowerCase();
    if (name === "" || rawByName.has(name)) {
      continue;
    }
    rawByName.set(name, header.value.trim());
  }

  const selected: SelectedHeader[] = [];
  for (const allowed of allowList) {
    const value = rawByName.get(allowed);
    if (value === undefined) {
      continue;
    }
    selected.push({
      name: allowed,
      valueSHA256: sha256Hex(value)
    });
  }
  return selected;
}

function selectedHeaderLine(headers: readonly SelectedHeader[]): string {
  return headers.map((header) => `${header.name}:${header.valueSHA256}`).join(",");
}

function encodeRFC3986(value: string): string {
  let out = "";
  for (const byte of new TextEncoder().encode(value)) {
    if (
      (byte >= 0x41 && byte <= 0x5a) ||
      (byte >= 0x61 && byte <= 0x7a) ||
      (byte >= 0x30 && byte <= 0x39) ||
      byte === 0x2d ||
      byte === 0x2e ||
      byte === 0x5f ||
      byte === 0x7e
    ) {
      out += String.fromCharCode(byte);
    } else {
      out += `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  return out;
}

function trimLeadingQuestionMark(value: string): string {
  return value.startsWith("?") ? value.slice(1) : value;
}

export function bodySHA256(body: Uint8Array | string | undefined = new Uint8Array()): string {
  if (typeof body === "string") {
    return sha256Hex(Buffer.from(body, "utf8"));
  }
  return sha256Hex(body);
}

function sha256Hex(value: Uint8Array | string): string {
  return createHash("sha256").update(value).digest("hex");
}
