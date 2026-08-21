/**
 * Cipher PTT Speed — Cloudflare Worker stub
 *
 * Contract (see ../../pttService.js):
 *   POST /login
 *   GET  /hot-boards
 *   GET  /boards/:name
 *   GET  /boards/:name/:id
 *
 * Never persist plaintext PTT credentials (no KV / D1 / R2 password writes).
 */

const DEFAULT_ORIGINS = [
  "https://cjlin925.github.io",
  "http://localhost:4173",
  "http://localhost:5173",
  "http://localhost:8765",
  "http://127.0.0.1:4173",
  "http://127.0.0.1:5173",
  "http://127.0.0.1:8765",
];

const STUB_BOARDS = [
  { name: "Gossiping", title: "八卦板", nuser: 12840, hot: true },
  { name: "Stock", title: "股板", nuser: 6120, hot: true },
  { name: "Baseball", title: "棒球", nuser: 4210, hot: true },
  { name: "Tech_Job", title: "科技業面試", nuser: 2890, hot: true },
  { name: "Mobilesales", title: "手機買賣", nuser: 1980, hot: false },
  { name: "joke", title: "就可板", nuser: 1540, hot: false },
];

/** @type {Record<string, Array<{ id: string, title: string, author: string, date: string, push: number }>>} */
const STUB_ARTICLES = {
  Gossiping: [
    { id: "M.1700000001.A.001", title: "[爆卦] Worker stub 已上線", author: "cipherer", date: "08/21", push: 99 },
    { id: "M.1700000002.A.002", title: "[問卦] CORS 設定好了沒", author: "fastreader", date: "08/21", push: 42 },
    { id: "M.1700000003.A.003", title: "[新聞] 無伺服器前端討論", author: "newsbot", date: "08/20", push: 18 },
  ],
  Stock: [
    { id: "M.1700000101.A.001", title: "[標的] stub 資料勿跟單", author: "value", date: "08/21", push: 12 },
    { id: "M.1700000102.A.002", title: "[心得] Worker 轉發架構", author: "holder", date: "08/20", push: 7 },
  ],
  Baseball: [
    { id: "M.1700000201.A.001", title: "[Live] 示範賽況", author: "umpire", date: "08/21", push: 56 },
  ],
  Tech_Job: [
    { id: "M.1700000301.A.001", title: "[請益] Cloudflare Worker 心得", author: "sre", date: "08/21", push: 33 },
    { id: "M.1700000302.A.002", title: "[心得] 前後端分離", author: "mobiledev", date: "08/19", push: 21 },
  ],
  Mobilesales: [
    { id: "M.1700000401.A.001", title: "[販售] Demo only", author: "seller", date: "08/18", push: 3 },
  ],
  joke: [
    { id: "M.1700000501.A.001", title: "[豪傑] 告別黑底白字", author: "joker", date: "08/21", push: 88 },
  ],
};

export default {
  /**
   * @param {Request} request
   * @param {{ EXTRA_ORIGINS?: string }} env
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

      if (request.method === "POST" && path === "/login") {
        return json(await handleLogin(request), 200, cors);
      }

      if (request.method === "GET" && path === "/hot-boards") {
        requireSession(request);
        return json({ boards: STUB_BOARDS }, 200, cors);
      }

      const boardArticle = path.match(/^\/boards\/([^/]+)\/([^/]+)$/);
      if (request.method === "GET" && boardArticle) {
        requireSession(request);
        const board = decodeURIComponent(boardArticle[1]);
        const id = decodeURIComponent(boardArticle[2]);
        return json({ article: stubArticle(board, id) }, 200, cors);
      }

      const boardOnly = path.match(/^\/boards\/([^/]+)$/);
      if (request.method === "GET" && boardOnly) {
        requireSession(request);
        const board = decodeURIComponent(boardOnly[1]);
        const articles = (STUB_ARTICLES[board] || []).map((a) => ({ ...a, board }));
        return json({ board, articles }, 200, cors);
      }

      if (request.method === "GET" && path === "/") {
        return json(
          {
            ok: true,
            service: "cipher-ptt-worker",
            version: "0.1.0",
            mode: "stub",
            endpoints: ["/login", "/hot-boards", "/boards/:name", "/boards/:name/:id"],
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
 */
async function handleLogin(request) {
  let body;
  try {
    body = await request.json();
  } catch {
    const err = new Error("Invalid JSON body");
    err.status = 400;
    throw err;
  }

  const username = String(body?.username || "").trim();
  const password = String(body?.password || "");

  // Password is read only to validate presence — never logged or stored.
  if (!username || !password) {
    const err = new Error("username and password are required");
    err.status = 400;
    throw err;
  }

  const sessionToken = await mintSessionToken(username);

  return {
    ok: true,
    mode: "stub",
    sessionToken,
    user: { username },
    message: "Stub login OK — replace with real PTT bridge later.",
  };
}

/**
 * @param {string} username
 */
async function mintSessionToken(username) {
  const payload = {
    u: username,
    iat: Date.now(),
    // Stub only: real impl should be random opaque IDs server-side.
    n: crypto.randomUUID(),
  };
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return `stub.${btoa(binary)}`;
}

/**
 * @param {Request} request
 */
function requireSession(request) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ") || auth.length < 16) {
    const err = new Error("Unauthorized — login first");
    err.status = 401;
    throw err;
  }
}

/**
 * @param {string} board
 * @param {string} id
 */
function stubArticle(board, id) {
  const list = STUB_ARTICLES[board] || [];
  const summary = list.find((a) => a.id === id) || {
    id,
    title: id,
    author: "unknown",
    date: "—",
    push: 0,
  };

  return {
    id: summary.id,
    board,
    title: summary.title,
    author: summary.author,
    date: summary.date,
    push: summary.push,
    content: [
      `作者: ${summary.author}`,
      `看板: ${board}`,
      `標題: ${summary.title}`,
      `時間: 2026-${summary.date || "08/21"} 12:00:00`,
      "",
      "※ 這是 Cloudflare Worker stub 回傳的示範內文。",
      "※ 請在 workers/cipher-ptt/src/index.js 接上真實 PTT 轉發。",
      "※ 帳密僅用於本次 /login 請求，Worker 不落盤。",
      "",
      "推文區（示範）",
      "→ 推 cipherer: Worker CORS 通過",
      "→ → fastreader: 接下來接 telnet/websocket",
      "",
      "--",
      "※ 發信站: cipher-ptt-worker (stub)",
    ].join("\n"),
  };
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
  } else if (!origin) {
    // Non-browser clients (curl / wrangler) — no ACAO needed.
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
