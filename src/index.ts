interface Env {
  KV: KVNamespace;
  ALLOWED_ORIGINS?: string;
  SETUP_TOKEN?: string;
}

interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

interface VaultEnvelope {
  schemaVersion: 1;
  rev: string;
  updatedAt: string;
  auth: {
    tokenHashAlg: "SHA-256";
    tokenHash: string;
  };
  crypto: {
    kdf: "PBKDF2-HMAC-SHA256";
    iterations: number;
    salt: string;
    cipher: "AES-256-GCM";
    iv: string;
  };
  ciphertext: string;
}

const VAULT_KEY = "vault:state";
const MAX_BODY_BYTES = 1024 * 1024;
const KV_TIMEOUT_MS = 5000;
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};
const CORS_METHODS = "GET,POST,PUT,OPTIONS";
const CORS_HEADERS = "Content-Type,Authorization,If-Match,X-Setup-Token";
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message = code,
  ) {
    super(message);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      if (request.method === "OPTIONS") {
        return handleOptions(request, env);
      }

      const corsError = rejectDisallowedBrowserOrigin(request, env);
      if (corsError) {
        return corsError;
      }

      return await route(request, env);
    } catch (error) {
      if (error instanceof HttpError) {
        return json(request, env, { error: error.code, message: error.message }, error.status);
      }
      return json(request, env, { error: "internal_error" }, 500);
    }
  },
};

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "GET" && url.pathname === "/api/health") {
    const initialized = Boolean(await kvGet(env, VAULT_KEY));
    return json(request, env, { ok: true, initialized });
  }

  if (request.method === "GET" && url.pathname === "/api/vault") {
    const envelope = await getStoredEnvelope(env);
    if (!envelope) {
      throw new HttpError(404, "vault_not_found");
    }
    return json(request, env, envelope, 200, { ETag: envelope.rev });
  }

  if (request.method === "POST" && url.pathname === "/api/setup") {
    return setupVault(request, env);
  }

  if (request.method === "PUT" && url.pathname === "/api/vault") {
    return updateVault(request, env);
  }

  throw new HttpError(404, "not_found");
}

async function setupVault(request: Request, env: Env): Promise<Response> {
  if (env.SETUP_TOKEN) {
    const setupToken = request.headers.get("X-Setup-Token") ?? "";
    if (!timingSafeEqual(setupToken, env.SETUP_TOKEN)) {
      throw new HttpError(401, "invalid_setup_token");
    }
  }

  const existing = await kvGet(env, VAULT_KEY);
  if (existing) {
    throw new HttpError(409, "vault_already_exists");
  }

  const envelope = await readEnvelopeFromRequest(request);
  await kvPut(env, VAULT_KEY, JSON.stringify(envelope));
  return json(request, env, { ok: true, rev: envelope.rev }, 201, { ETag: envelope.rev });
}

async function updateVault(request: Request, env: Env): Promise<Response> {
  const current = await getStoredEnvelope(env);
  if (!current) {
    throw new HttpError(404, "vault_not_found");
  }

  const token = readBearerToken(request);
  const tokenHash = await sha256Base64Url(token);
  if (!timingSafeEqual(tokenHash, current.auth.tokenHash)) {
    throw new HttpError(401, "invalid_write_token");
  }

  const ifMatch = request.headers.get("If-Match");
  if (!ifMatch || ifMatch !== current.rev) {
    throw new HttpError(409, "revision_conflict");
  }

  const next = await readEnvelopeFromRequest(request);
  if (next.rev === current.rev) {
    throw new HttpError(400, "revision_must_change");
  }

  await kvPut(env, VAULT_KEY, JSON.stringify(next));
  return json(request, env, { ok: true, rev: next.rev }, 200, { ETag: next.rev });
}

async function getStoredEnvelope(env: Env): Promise<VaultEnvelope | null> {
  const raw = await kvGet(env, VAULT_KEY);
  if (!raw) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new HttpError(500, "stored_vault_is_corrupt");
  }

  if (!isVaultEnvelope(parsed)) {
    throw new HttpError(500, "stored_vault_is_invalid");
  }

  return parsed;
}

async function kvGet(env: Env, key: string): Promise<string | null> {
  try {
    return await withTimeout(
      env.KV.get(key),
      KV_TIMEOUT_MS,
      new HttpError(503, "kv_timeout", "Cloudflare KV request timed out"),
    );
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    throw new HttpError(503, "kv_unavailable", kvErrorMessage(error));
  }
}

async function kvPut(env: Env, key: string, value: string): Promise<void> {
  try {
    await withTimeout(
      env.KV.put(key, value),
      KV_TIMEOUT_MS,
      new HttpError(503, "kv_timeout", "Cloudflare KV request timed out"),
    );
  } catch (error) {
    if (error instanceof HttpError) {
      throw error;
    }
    throw new HttpError(503, "kv_unavailable", kvErrorMessage(error));
  }
}

function kvErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message) {
    return `Cloudflare KV request failed: ${error.message}`;
  }
  return "Cloudflare KV request failed";
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number, error: HttpError): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;

  const timeout = new Promise<T>((_, reject) => {
    timer = setTimeout(() => reject(error), timeoutMs);
  });

  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

async function readEnvelopeFromRequest(request: Request): Promise<VaultEnvelope> {
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_BODY_BYTES) {
    throw new HttpError(413, "vault_too_large");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new HttpError(400, "invalid_json");
  }

  if (!isVaultEnvelope(parsed)) {
    throw new HttpError(400, "invalid_vault_envelope");
  }

  return parsed;
}

function isVaultEnvelope(value: unknown): value is VaultEnvelope {
  if (!isRecord(value)) {
    return false;
  }

  const auth = value.auth;
  const cryptoConfig = value.crypto;

  return (
    value.schemaVersion === 1 &&
    isNonEmptyString(value.rev) &&
    isIsoDateString(value.updatedAt) &&
    isRecord(auth) &&
    auth.tokenHashAlg === "SHA-256" &&
    isBase64Url(auth.tokenHash) &&
    isRecord(cryptoConfig) &&
    cryptoConfig.kdf === "PBKDF2-HMAC-SHA256" &&
    typeof cryptoConfig.iterations === "number" &&
    Number.isInteger(cryptoConfig.iterations) &&
    cryptoConfig.iterations >= 100_000 &&
    cryptoConfig.iterations <= 5_000_000 &&
    isBase64Url(cryptoConfig.salt) &&
    cryptoConfig.cipher === "AES-256-GCM" &&
    isBase64Url(cryptoConfig.iv) &&
    isBase64Url(value.ciphertext)
  );
}

function readBearerToken(request: Request): string {
  const authorization = request.headers.get("Authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match?.[1]) {
    throw new HttpError(401, "missing_write_token");
  }
  return match[1];
}

function rejectDisallowedBrowserOrigin(request: Request, env: Env): Response | null {
  const origin = request.headers.get("Origin");
  if (!origin || isOriginAllowed(origin, env)) {
    return null;
  }
  return json(request, env, { error: "origin_not_allowed" }, 403);
}

function handleOptions(request: Request, env: Env): Response {
  const origin = request.headers.get("Origin");
  if (origin && !isOriginAllowed(origin, env)) {
    return json(request, env, { error: "origin_not_allowed" }, 403);
  }

  return new Response(null, {
    status: 204,
    headers: withCors(request, env, {
      "Access-Control-Allow-Methods": CORS_METHODS,
      "Access-Control-Allow-Headers": CORS_HEADERS,
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
    }),
  });
}

function json(
  request: Request,
  env: Env,
  payload: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: withCors(request, env, {
      ...JSON_HEADERS,
      ...headers,
      Vary: "Origin",
    }),
  });
}

function withCors(request: Request, env: Env, headers: Record<string, string>): Headers {
  const result = new Headers(headers);
  const origin = request.headers.get("Origin");

  if (origin && isOriginAllowed(origin, env)) {
    result.set("Access-Control-Allow-Origin", origin);
  }

  return result;
}

function isOriginAllowed(origin: string, env: Env): boolean {
  const allowedOrigins = (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  return allowedOrigins.includes(origin);
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let index = 0; index < a.length; index += 1) {
    result |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }

  return result === 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isBase64Url(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && BASE64URL_RE.test(value);
}

function isIsoDateString(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}
