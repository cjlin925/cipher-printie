/**
 * Cipher PTT Speed — Cloudflare Worker
 *
 * Contract (see ../../pttService.js):
 *   GET  /crypto             → { alg, publicKey } RSA-OAEP-256 JWK
 *   POST /login              → { username, passwordEnc } encrypted password only
 *   POST /favorites          → same blob; scrape (F)avorite list (session required)

 *   GET  /hot-boards         → www.ptt.cc/bbs/hotboards.html
 *   GET  /boards/:name       → www.ptt.cc board index
 *   GET  /boards/:name/:id   → www.ptt.cc article
 *
 * Never persist plaintext PTT credentials (no KV / D1 / R2 password writes).
 */

import { loginToPtt, LOGIN_REASONS } from "./pttWs.js";
import { fetchHotBoards, fetchBoardArticles, fetchArticle } from "./pttWeb.js";
import { LOGIN_PUBLIC_JWK } from "./loginPub.js";

const DEFAULT_ORIGINS = [
  "https://cjlin925.github.io",
  "http://localhost:4173",
  "http://localhost:5173",
  "http://localhost:8765",
  "http://127.0.0.1:4173",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:8765",
];

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const BOARD_NAME_RE = /^[A-Za-z0-9_-]{1,20}$/;
const ARTICLE_ID_RE = /^M\.[0-9]+\.A\.[0-9A-Za-z]+$/;

const LOGIN_ERROR_MAP = {
  [LOGIN_REASONS.WRONG_PASSWORD]: { status: 401, message: "帳號或密碼錯誤" },
  [LOGIN_REASONS.SERVER_BUSY]: { status: 503, message: "PTT 忙碌中，請稍後再試" },
  [LOGIN_REASONS.TIMEOUT]: { status: 504, message: "登入逾時，請再試一次" },
  [LOGIN_REASONS.SOCKET_CLOSED]: { status: 502, message: "無法連線到 PTT" },
  [LOGIN_REASONS.NO_PROMPT]: { status: 502, message: "PTT 登入畫面無回應" },
};

export default {
  /**
   * @param {Request} request
   * @param {{ EXTRA_ORIGINS?: string, SESSION_SECRET?: string, LOGIN_PRIVATE_JWK?: string }} env
   */
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = buildCorsHeaders(origin, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      const url = new URL(request.url);
      const path = url.pathname.replace(/\/+$/, "") || "/";

      if (request.method === "GET" && path === "/crypto") {
        return json(
          { alg: "RSA-OAEP-256", publicKey: LOGIN_PUBLIC_JWK },
          200,
          cors
        );
      }

      if (request.method === "POST" && path === "/login") {
        return json(await handleLogin(request, env), 200, cors);
      }

      if (request.method === "POST" && path === "/favorites") {
        return json(await handleFavorites(request, env), 200, cors);
      }

      if (request.method === "GET" && path === "/hot-boards") {
        await requireSession(request, env);
        const boards = await fetchHotBoards();
        return json({ boards }, 200, cors);
      }

      const boardArticle = path.match(/^\/boards\/([^/]+)\/([^/]+)$/);
      if (request.method === "GET" && boardArticle) {
        await requireSession(request, env);
        const board = decodeURIComponent(boardArticle[1]);
        const id = decodeURIComponent(boardArticle[2]);
        assertBoard(board);
        assertArticleId(id);
        const article = await fetchArticle(board, id);
        return json({ article }, 200, cors);
      }

      const boardOnly = path.match(/^\/boards\/([^/]+)$/);
      if (request.method === "GET" && boardOnly) {
        await requireSession(request, env);
        const board = decodeURIComponent(boardOnly[1]);
        assertBoard(board);
        const articles = await fetchBoardArticles(board);
        return json({ board, articles }, 200, cors);
      }

      if (request.method === "GET" && path === "/") {
        return json(
          {
            ok: true,
            service: "cipher-ptt-worker",
            version: "0.2.4",
            mode: "ptt",
            endpoints: ["/crypto", "/login", "/favorites", "/hot-boards", "/boards/:name", "/boards/:name/:id"],
          },
          200,
          cors
        );
      }

      return json({ error: "Not found", path }, 404, cors);
    } catch (error) {
      const status = error?.status || 500;
      const message = error?.message || "Internal error";
      return json({ error: message }, status, cors);
    }
  },
};

/**
 * @param {Request} request
 * @param {{ SESSION_SECRET?: string }} env
 */
async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    throw httpError("Invalid JSON body", 400);
  }

  if (body?.password != null && String(body.password).length > 0) {
    throw httpError("plaintext password is not accepted; send passwordEnc", 400);
  }

  const username = String(body?.username || "").trim();
  if (!username) {
    throw httpError("username is required", 400);
  }
  if (!/^[A-Za-z0-9]{2,20}$/.test(username)) {
    throw httpError("invalid username", 400);
  }

  // Decrypt RSA-OAEP blob in memory, then send the plaintext password to
  // PTT over the WebSocket. The password is never logged or stored.
  const password = await decryptPasswordEnc(body?.passwordEnc, env);
  if (!password) {
    throw httpError("passwordEnc is required", 400);
  }

  const result = await loginToPtt(username, password, { kick: false });
  if (!result.ok) {
    const mapped = LOGIN_ERROR_MAP[result.reason] || LOGIN_ERROR_MAP[LOGIN_REASONS.SOCKET_CLOSED];
    throw httpError(mapped.message, mapped.status);
  }

  const sessionToken = await mintSessionToken(username, env);

  return {
    ok: true,
    mode: "ptt",
    sessionToken,
    user: { username },
    favorites: result.favorites || [],
    message: "已登入 PTT",
  };
}

/**
 * Re-login to PTT just long enough to open (F)avorite and return the list.
 * Requires an existing Speed PTT session; does not mint a new token.
 */
async function handleFavorites(request, env) {
  await requireSession(request, env);

  let body;
  try {
    body = await request.json();
  } catch {
    throw httpError("Invalid JSON body", 400);
  }

  if (body?.password != null && String(body.password).length > 0) {
    throw httpError("plaintext password is not accepted; send passwordEnc", 400);
  }

  const username = String(body?.username || "").trim();
  if (!username || !/^[A-Za-z0-9]{2,20}$/.test(username)) {
    throw httpError("invalid username", 400);
  }

  const password = await decryptPasswordEnc(body?.passwordEnc, env);
  if (!password) {
    throw httpError("passwordEnc is required", 400);
  }

  const result = await loginToPtt(username, password, { kick: false });
  if (!result.ok) {
    const mapped = LOGIN_ERROR_MAP[result.reason] || LOGIN_ERROR_MAP[LOGIN_REASONS.SOCKET_CLOSED];
    throw httpError(mapped.message, mapped.status);
  }

  return {
    ok: true,
    favorites: result.favorites || [],
    message: result.favorites?.length ? `已同步 ${result.favorites.length} 個最愛看板` : "已連線，但未抓到最愛看板",
  };
}

/**
 * @param {string} username
 * @param {{ SESSION_SECRET?: string }} env
 */
async function mintSessionToken(username, env) {
  const secret = sessionSecret(env);
  const payload = JSON.stringify({
    u: username,
    iat: Date.now(),
    exp: Date.now() + SESSION_TTL_MS,
  });
  const payloadB64 = b64urlEncode(payload);
  const sig = await hmacSign(secret, payloadB64);
  return `v1.${payloadB64}.${sig}`;
}

/**
 * @param {Request} request
 * @param {{ SESSION_SECRET?: string }} env
 */
async function requireSession(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) {
    throw httpError("Unauthorized — login first", 401);
  }
  const token = auth.slice("Bearer ".length).trim();
  const valid = await verifySessionToken(token, env);
  if (!valid) {
    throw httpError("Session expired — please login again", 401);
  }
}

/**
 * @param {string} token
 * @param {{ SESSION_SECRET?: string }} env
 */
async function verifySessionToken(token, env) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return false;
  const [, payloadB64, sig] = parts;
  const expected = await hmacSign(sessionSecret(env), payloadB64);
  if (!timingSafeEqual(sig, expected)) return false;
  try {
    const payload = JSON.parse(b64urlDecode(payloadB64));
    if (!payload?.u || typeof payload.exp !== "number") return false;
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

/** @param {{ SESSION_SECRET?: string }} env */
function sessionSecret(env) {
  const secret = String(env?.SESSION_SECRET || "").trim();
  if (!secret) {
    throw httpError("Worker SESSION_SECRET is not configured", 500);
  }
  return secret;
}

/**
 * @param {string} secret
 * @param {string} message
 */
async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return b64urlEncodeBytes(new Uint8Array(sig));
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i += 1) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function b64urlEncode(text) {
  return b64urlEncodeBytes(new TextEncoder().encode(text));
}

function b64urlEncodeBytes(bytes) {
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlDecode(text) {
  return new TextDecoder().decode(b64urlDecodeBytes(text));
}

function b64urlDecodeBytes(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * @param {unknown} passwordEnc
 * @param {{ LOGIN_PRIVATE_JWK?: string }} env
 */
async function decryptPasswordEnc(passwordEnc, env) {
  const blob = String(passwordEnc || "").trim();
  if (!blob) return "";
  const raw = String(env?.LOGIN_PRIVATE_JWK || "").trim();
  if (!raw) {
    throw httpError("Worker LOGIN_PRIVATE_JWK is not configured", 500);
  }
  let jwk;
  try {
    jwk = JSON.parse(raw);
  } catch {
    throw httpError("Worker LOGIN_PRIVATE_JWK is invalid", 500);
  }
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"]
    );
    const plain = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      key,
      b64urlDecodeBytes(blob)
    );
    return new TextDecoder().decode(plain);
  } catch {
    throw httpError("passwordEnc could not be decrypted", 400);
  }
}

function assertBoard(name) {
  if (!BOARD_NAME_RE.test(name)) throw httpError("invalid board name", 400);
}

function assertArticleId(id) {
  if (!ARTICLE_ID_RE.test(id)) throw httpError("invalid article id", 400);
}

function httpError(message, status) {
  const err = new Error(message);
  err.status = status;
  return err;
}

/**
 * @param {string} origin
 * @param {{ EXTRA_ORIGINS?: string }} env
 */
function buildCorsHeaders(origin, env) {
  const extra = String(env?.EXTRA_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const allowed = new Set([...DEFAULT_ORIGINS, ...extra]);

  const headers = new Headers({
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Cipher-Client",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  });

  if (origin && (allowed.has(origin) || isLocalDevOrigin(origin))) {
    headers.set("Access-Control-Allow-Origin", origin);
  }

  return headers;
}

/** @param {string} origin */
function isLocalDevOrigin(origin) {
  try {
    const url = new URL(origin);
    return (
      (url.hostname === "localhost" || url.hostname === "127.0.0.1") &&
      (url.protocol === "http:" || url.protocol === "https:")
    );
  } catch {
    return false;
  }
}

/**
 * @param {unknown} data
 * @param {number} status
 * @param {Headers} cors
 */
function json(data, status, cors) {
  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(data), { status, headers });
}
