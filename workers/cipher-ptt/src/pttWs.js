/**
 * PTT WebSocket login (Cloudflare Workers).
 *
 * Connects to wss://ws.ptt.cc/bbs with Origin https://term.ptt.cc,
 * authenticates, then logs out. Credentials stay in memory for this
 * request only — never written to KV / D1 / R2 / logs.
 *
 * Trailing comma after username switches PTT to UTF-8. Login prompts
 * may still arrive in Big5, so both decoders run in parallel. Phrase
 * detection also searches raw bytes so a bad TextDecoder cannot stall login.
 */

const PTT_WS_URL = "https://ws.ptt.cc/bbs/";
const PTT_ORIGIN = "https://term.ptt.cc";
const KEY_ENTER = "\r";
const ANSI_RE = /\x1b\[[\??!>]?[0-9;]*[@A-Za-z`]|\x1b[\(\)][AB012]|\x07/g;
const HTTP_NOISE_RE = /^HTTP\/1\.\d \d+ [^\r\n]*\r?\n\r?\n/;
const ROLLING_BUFFER_LIMIT = 32 * 1024;
const RAW_BUFFER_LIMIT = 24 * 1024;
const TAIL_CHARS = 1400;

export const LOGIN_REASONS = Object.freeze({
  WRONG_PASSWORD: "wrong_password",
  SERVER_BUSY: "server_busy",
  TIMEOUT: "timeout",
  SOCKET_CLOSED: "socket_closed",
  NO_PROMPT: "no_prompt",
});

/** UTF-8 + Big5 encodings of the phrases we must detect. */
const PHRASES = {
  anyKey: {
    text: ["按任意鍵繼續", "請按任意鍵繼續"],
    bytes: [u8("ab f6 a5 f4 b7 4e c1 e4 c4 7e c4 f2"), u8("e6 8c 89 e4 bb bb e6 84 8f e9 8d b5 e7 b9 bc e7 ba 8c")],
  },
  mainMenu: {
    text: ["【主功能表】", "主功能表", "(F)avorite", "精華公佈欄", "我 的 最愛"],
    bytes: [u8("a1 69 a5 44 a5 5c af e0 aa ed a1 6a"), u8("e3 80 90 e4 b8 bb e5 8a 9f e8 83 bd e8 a1 a8 e3 80 91")],
  },
  wrongPassword: {
    text: ["密碼不對或無此帳號", "密碼不對"],
    bytes: [u8("b1 4b bd 58 a4 a3 b9 ef"), u8("e5 af 86 e7 a2 bc e4 b8 8d e5 b0 8d")],
  },
  duplicate: {
    text: ["您想刪除其他重複登入"],
    bytes: [u8("b1 7a b7 51 a7 52 b0 a3 a8 e4 a5 4c ad ab bd c6"), u8("e6 82 a8 e6 83 b3 e5 88 aa e9 99 a4 e5 85 b6 e4 bb 96 e9 87 8d e8 a4 87")],
  },
  tooOften: {
    text: ["請勿頻繁登入"],
    bytes: [u8("bd d0 a4 c5 c0 57 c1 63 b5 6e a4 4a"), u8("e8 ab 8b e5 8b bf e9 a0 bb e7 b9 81 e7 99 bb e5 85 a5")],
  },
  cleanup: {
    text: ["您要刪除以上錯誤嘗試"],
    bytes: [u8("b1 7a ad 6e a7 52 b0 a3 a5 48 a4 57 bf f9 bb 7e"), u8("e6 82 a8 e8 a6 81 e5 88 aa e9 99 a4 e4 bb a5 e4 b8 8a e9 8c af e8 aa a4")],
  },
  loginPrompt: {
    text: ["請輸入", "代號"],
    bytes: [u8("bd d0 bf e9 a4 4a"), u8("e8 ab 8b e8 bc b8 e5 85 a5")],
  },
  loggingIn: {
    text: ["登入中"],
    bytes: [u8("b5 6e a4 4a a4 a4"), u8("e7 99 bb e5 85 a5 e4 b8 ad")],
  },
  iAm: {
    text: ["我是"],
    bytes: [u8("a7 da ac 4f"), u8("e6 88 91 e6 98 af")],
  },
  busy: {
    text: ["請稍後再試", "系統過載"],
    bytes: [u8("bd d0 b5 79 ab e1 a6 41 b8 d5"), u8("e8 ab 8b e7 a8 8d e5 be 8c e5 86 8d e8 a9 a6")],
  },
  unfinished: {
    text: ["您有一篇文章尚未完成"],
    bytes: [u8("b1 7a a6 b3 a4 40 bd 67 a4 e5 b3 b9"), u8("e6 82 a8 e6 9c 89 e4 b8 80 e7 af 87 e6 96 87 e7 ab a0")],
  },
  browsing: {
    text: ["目前顯示", "q)離開", "←/q)離開", "瀏覽 第"],
    bytes: [u8("e7 9b ae e5 89 8d e9 a1 a5 e7 a4 ba"), u8("e9 9b a2 e9 96 8b")],
  },
  favList: {
    text: ["選擇看板", "增加看板", "進入已知板名", "(a)增加看板", "(s)進入已知板名"],
    bytes: [
      u8("bf ef be dc ac dd aa 4f"),
      u8("e9 81 b8 e6 93 87 e7 9c 8b e6 9d bf"),
      u8("bc 57 a5 5b ac dd aa 4f"),
      u8("e5 a2 9e e5 8a a0 e7 9c 8b e6 9d bf"),
      u8("b6 69 a4 4a a4 77 aa be aa 4f a6 57"),
      u8("e9 80 b2 e5 85 a5 e5 b7 b2 e7 9f a5 e6 9d bf e5 90 8d"),
    ],
  },
};

function u8(hex) {
  return Uint8Array.from(hex.trim().split(/\s+/).map((h) => parseInt(h, 16)));
}

function stripAnsi(s) {
  return s.replace(ANSI_RE, "").replace(HTTP_NOISE_RE, "");
}

function appendStripped(buf, text) {
  let next = buf + stripAnsi(text);
  if (next.length > ROLLING_BUFFER_LIMIT) {
    next = next.slice(next.length - ROLLING_BUFFER_LIMIT);
  }
  return next;
}

function encodeAsciiBytes(text) {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

function makeDecoder(label) {
  try {
    return new TextDecoder(label, { fatal: false, ignoreBOM: true });
  } catch {
    return null;
  }
}

function containsBytes(haystack, needle) {
  if (!needle.length || haystack.length < needle.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

function appendRaw(prev, chunk) {
  if (!chunk.length) return prev;
  if (prev.length + chunk.length <= RAW_BUFFER_LIMIT) {
    const next = new Uint8Array(prev.length + chunk.length);
    next.set(prev, 0);
    next.set(chunk, prev.length);
    return next;
  }
  const keep = RAW_BUFFER_LIMIT - chunk.length;
  const next = new Uint8Array(RAW_BUFFER_LIMIT);
  if (keep > 0) next.set(prev.subarray(prev.length - keep), 0);
  next.set(chunk, Math.max(0, keep));
  return next;
}

class PttSocket {
  constructor() {
    this.ws = null;
    this.chunks = [];
    this.big5Decoder = makeDecoder("big5");
    this.utf8Decoder = makeDecoder("utf-8");
    this.big5Buffer = "";
    this.utf8Buffer = "";
    this.raw = new Uint8Array(0);
    this.closed = false;
    this.waiters = [];
  }

  async connect() {
    const resp = await fetch(PTT_WS_URL, {
      headers: { Upgrade: "websocket", Origin: PTT_ORIGIN },
    });
    if (resp.status !== 101 || !resp.webSocket) {
      throw new Error(`PTT WS handshake failed: status=${resp.status}`);
    }
    const ws = resp.webSocket;
    try {
      ws.binaryType = "arraybuffer";
    } catch {
      /* Blob frames still handled in onMessage */
    }
    ws.addEventListener("message", (event) => this.onMessage(event.data));
    ws.addEventListener("close", () => {
      this.closed = true;
      this.notify();
    });
    ws.addEventListener("error", () => {
      this.closed = true;
      this.notify();
    });
    ws.accept();
    this.ws = ws;
  }

  onMessage(data) {
    if (data instanceof ArrayBuffer) {
      this.feed(new Uint8Array(data));
    } else if (ArrayBuffer.isView(data)) {
      this.feed(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
    } else if (typeof Blob !== "undefined" && data instanceof Blob) {
      this.chunks.push(data.arrayBuffer().then((ab) => this.feed(new Uint8Array(ab))));
    } else if (typeof data === "string") {
      this.utf8Buffer = appendStripped(this.utf8Buffer, data);
      this.raw = appendRaw(this.raw, encodeAsciiBytes(data));
      this.notify();
    }
  }

  feed(bytes) {
    if (!bytes.length) return;
    this.raw = appendRaw(this.raw, bytes);
    if (this.big5Decoder) {
      this.big5Buffer = appendStripped(
        this.big5Buffer,
        this.big5Decoder.decode(bytes, { stream: true })
      );
    }
    if (this.utf8Decoder) {
      this.utf8Buffer = appendStripped(
        this.utf8Buffer,
        this.utf8Decoder.decode(bytes, { stream: true })
      );
    }
    this.notify();
  }

  notify() {
    const waiters = this.waiters;
    this.waiters = [];
    for (const cb of waiters) cb();
  }

  async drain() {
    while (this.chunks.length > 0) {
      const pending = this.chunks;
      this.chunks = [];
      await Promise.allSettled(pending);
    }
  }

  send(text) {
    if (!this.ws) throw new Error("socket not connected");
    this.ws.send(encodeAsciiBytes(text));
  }

  get screen() {
    return `${this.big5Buffer}\n${this.utf8Buffer}`;
  }

  get tail() {
    const screen = this.screen;
    return screen.slice(Math.max(0, screen.length - TAIL_CHARS));
  }

  /**
   * @param {{ text: string[], bytes: Uint8Array[] }} phrase
   * @param {boolean} [useTail]
   */
  has(phrase, useTail = true) {
    const text = useTail ? this.tail : this.screen;
    if (phrase.text.some((p) => text.includes(p))) return true;
    const raw = useTail ? this.raw.subarray(Math.max(0, this.raw.length - 2048)) : this.raw;
    return phrase.bytes.some((needle) => containsBytes(raw, needle));
  }

  isClosed() {
    return this.closed;
  }

  close(code = 1000, reason = "done") {
    if (this.ws && !this.closed) {
      try {
        this.ws.close(code, reason);
      } catch {
        /* noop */
      }
    }
    this.closed = true;
  }

  async waitFor(predicate, timeoutMs) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      await this.drain();
      if (predicate(this)) return true;
      if (this.closed) return false;
      await new Promise((resolve) => {
        let woken = false;
        const wake = () => {
          if (woken) return;
          woken = true;
          resolve();
        };
        this.waiters.push(wake);
        if (predicate(this)) wake();
        setTimeout(wake, 200);
      });
    }
    return false;
  }
}

function sanitizeTail(bot) {
  return bot.tail.replace(/\s+/g, " ").slice(-360);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function logoutBestEffort(bot) {
  bot.send("q");
  await sleep(200);
  bot.send("q");
  await sleep(200);
  bot.send(`G${KEY_ENTER}Y${KEY_ENTER}`);
  await sleep(400);
  bot.send(KEY_ENTER);
}

const SKIP_BOARD_NAMES = new Set([
  "announce", "boards", "class", "favorite", "mail", "chat", "talk", "user",
  "help", "guest", "new", "ptt", "bbs", "index",
]);

function mergeBoards(into, extra) {
  const seen = new Set(into.map((b) => b.name.toLowerCase()));
  for (const board of extra) {
    const key = board.name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    into.push(board);
  }
  return into;
}

function onFavoriteList(bot) {
  return bot.has(PHRASES.favList);
}

function onMainMenu(bot) {
  return bot.has(PHRASES.mainMenu);
}

/**
 * After login, open (F)avorite and parse the board list. Best-effort: an
 * empty array is fine — login itself still succeeds.
 * @param {PttSocket} bot
 * @returns {Promise<Array<{ name: string, title: string }>>}
 */
async function scrapeFavorites(bot) {
  try {
    await bot.drain();

    if (!onFavoriteList(bot)) {
      if (bot.has(PHRASES.browsing) && !onMainMenu(bot)) {
        bot.send("q");
        await bot.waitFor((sock) => onMainMenu(sock) || onFavoriteList(sock), 2_000);
      }
      if (!onFavoriteList(bot)) {
        await sleep(250);
        // Letter shortcut only — Enter would open the highlighted board.
        bot.send("F");
        const opened = await bot.waitFor((sock) => onFavoriteList(sock), 3_500);
        if (!opened) {
          bot.send("f");
          await bot.waitFor((sock) => onFavoriteList(sock), 2_000);
        }
      }
    }

    await sleep(280);
    await bot.drain();
    let boards = parseFavoriteBoards(bot.screen);

    if (boards.length < 2 && onFavoriteList(bot)) {
      bot.send(" ");
      await sleep(280);
      await bot.drain();
      boards = mergeBoards(boards, parseFavoriteBoards(bot.screen));
    }

    const names = boards.map((b) => b.name).join(",");
    if (!boards.length) {
      console.log(`ptt favorites scraped 0 tail=${sanitizeTail(bot)}`);
    } else {
      console.log(`ptt favorites scraped ${boards.length} ${names}`);
    }
    return boards;
  } catch (error) {
    console.log(`ptt favorites scrape failed: ${error?.message || error}`);
    return [];
  }
}

/**
 * @param {string} screen
 * @returns {Array<{ name: string, title: string }>}
 */
function parseFavoriteBoards(screen) {
  const text = String(screen || "")
    .replace(/\x1b\[[\??!>]?[0-9;]*[@A-Za-z`]/g, "")
    .replace(/[\r\n]+/g, " ")
    .replace(/\s+/g, " ");
  const found = [];
  const seen = new Set();

  const add = (name, title) => {
    const key = String(name || "").toLowerCase();
    if (!key || seen.has(key) || SKIP_BOARD_NAMES.has(key)) return;
    if (!/^[A-Za-z][A-Za-z0-9_-]{1,19}$/.test(name)) return;
    seen.add(key);
    const cleaned = String(title || name).replace(/[\[\]〔〕◎○]/g, "").trim() || name;
    found.push({ name, title: cleaned.slice(0, 40) });
  };

  let match;
  const marked = /ˇ([A-Za-z][A-Za-z0-9_-]{1,19})/g;
  while ((match = marked.exec(text))) add(match[1], match[1]);

  const titled =
    /([A-Za-z][A-Za-z0-9_-]{1,19})\s*\S{0,8}\s*◎\s*(\[[^\]]*\]|〔[^〕]*〕|[^\sˇ>]+)/g;
  while ((match = titled.exec(text))) add(match[1], match[2]);

  return found.slice(0, 40);
}

/**
 * @param {string} username
 * @param {string} password
 * @param {{ kick?: boolean }} [options]
 * @returns {Promise<{ ok: true, elapsedMs: number, favorites: Array<{ name: string, title: string }> } | { ok: false, reason: string, elapsedMs: number }>}
 */
export async function loginToPtt(username, password, options = {}) {
  const kick = options.kick === true;
  const bot = new PttSocket();
  const started = Date.now();

  const fail = (reason) => {
    console.log(`ptt login ${reason} after ${Date.now() - started}ms tail=${sanitizeTail(bot)}`);
    return { ok: false, reason, elapsedMs: Date.now() - started };
  };

  try {
    await bot.connect();
    const sawPrompt = await bot.waitFor(
      (sock) => sock.has(PHRASES.loginPrompt, false) || sock.screen.toLowerCase().includes("guest"),
      8_000
    );
    if (!sawPrompt) return fail(LOGIN_REASONS.NO_PROMPT);

    // Give the password field a moment to render, then send UTF-8 negotation comma.
    await new Promise((r) => setTimeout(r, 250));
    bot.send(`${username},${KEY_ENTER}${password}${KEY_ENTER}`);

    const seen = { kick: false, tooOften: false, cleanup: false, unfinished: false };
    let lastAnyKeyAt = 0;
    const deadline = Date.now() + 20_000;

    while (Date.now() < deadline) {
      await bot.drain();

      if (bot.has(PHRASES.wrongPassword, false)) return fail(LOGIN_REASONS.WRONG_PASSWORD);
      if (bot.has(PHRASES.busy, false)) return fail(LOGIN_REASONS.SERVER_BUSY);

      if (!seen.kick && bot.has(PHRASES.duplicate)) {
        bot.send(`${kick ? "y" : "n"}${KEY_ENTER}`);
        seen.kick = true;
      } else if (!seen.tooOften && bot.has(PHRASES.tooOften)) {
        bot.send(KEY_ENTER);
        seen.tooOften = true;
      } else if (!seen.cleanup && bot.has(PHRASES.cleanup)) {
        bot.send(`y${KEY_ENTER}`);
        seen.cleanup = true;
      } else if (!seen.unfinished && bot.has(PHRASES.unfinished)) {
        bot.send(`q${KEY_ENTER}`);
        seen.unfinished = true;
      } else if (bot.has(PHRASES.anyKey) && Date.now() - lastAnyKeyAt > 450) {
        bot.send(KEY_ENTER);
        lastAnyKeyAt = Date.now();
      }

      const loggedIn =
        bot.has(PHRASES.mainMenu) ||
        bot.has(PHRASES.browsing) ||
        (bot.has(PHRASES.iAm) && (bot.tail.includes("聊天") || bot.tail.includes("電子郵件") || bot.has(PHRASES.mainMenu, false)));
      if (loggedIn && !bot.has(PHRASES.loggingIn)) {
        let favorites = [];
        try {
          favorites = await scrapeFavorites(bot);
        } catch {
          favorites = [];
        }
        try {
          await logoutBestEffort(bot);
        } catch {
          /* logout is best-effort */
        }
        return { ok: true, elapsedMs: Date.now() - started, favorites };
      }

      await new Promise((r) => setTimeout(r, 250));
      if (bot.isClosed()) return fail(LOGIN_REASONS.SOCKET_CLOSED);
    }

    return fail(LOGIN_REASONS.TIMEOUT);
  } catch (error) {
    console.log(`ptt login exception: ${error?.message || error}`);
    return fail(LOGIN_REASONS.SOCKET_CLOSED);
  } finally {
    bot.close();
  }
}
