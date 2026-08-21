/**
 * PTT WebSocket login (Cloudflare Workers).
 *
 * Connects to wss://ws.ptt.cc/bbs with Origin https://term.ptt.cc,
 * authenticates, then logs out. Credentials stay in memory for this
 * request only — never written to KV / D1 / R2 / logs.
 *
 * Trailing comma after username switches PTT to UTF-8. Login prompts
 * may still arrive in Big5, so both decoders run in parallel.
 */

const PTT_WS_URL = "https://ws.ptt.cc/bbs/";
const PTT_ORIGIN = "https://term.ptt.cc";
const KEY_ENTER = "\r";
const ANSI_RE = /\x1b\[[\??!>]?[0-9;]*[@A-Za-z`]|\x1b[\(\)][AB012]|\x07/g;
const HTTP_NOISE_RE = /^HTTP\/1\.\d \d+ [^\r\n]*\r?\n\r?\n/;
const ROLLING_BUFFER_LIMIT = 32 * 1024;

export const LOGIN_REASONS = Object.freeze({
  WRONG_PASSWORD: "wrong_password",
  SERVER_BUSY: "server_busy",
  TIMEOUT: "timeout",
  SOCKET_CLOSED: "socket_closed",
  NO_PROMPT: "no_prompt",
});

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

class PttSocket {
  constructor() {
    this.ws = null;
    this.chunks = [];
    this.big5Decoder = makeDecoder("big5");
    this.utf8Decoder = makeDecoder("utf-8");
    this.big5Buffer = "";
    this.utf8Buffer = "";
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
    ws.accept();
    ws.addEventListener("message", (event) => this.onMessage(event.data));
    ws.addEventListener("close", () => {
      this.closed = true;
      this.notify();
    });
    ws.addEventListener("error", () => {
      this.closed = true;
      this.notify();
    });
    this.ws = ws;
  }

  onMessage(data) {
    if (data instanceof ArrayBuffer) {
      this.feed(new Uint8Array(data));
    } else if (typeof Blob !== "undefined" && data instanceof Blob) {
      this.chunks.push(data.arrayBuffer().then((ab) => this.feed(new Uint8Array(ab))));
    } else if (typeof data === "string") {
      this.utf8Buffer = appendStripped(this.utf8Buffer, data);
      this.notify();
    }
  }

  feed(bytes) {
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
      if (predicate(this.screen)) return true;
      if (this.closed) return false;
      await new Promise((resolve) => {
        let woken = false;
        const wake = () => {
          if (woken) return;
          woken = true;
          resolve();
        };
        this.waiters.push(wake);
        if (predicate(this.screen)) wake();
        setTimeout(wake, 200);
      });
    }
    return false;
  }
}

/**
 * @param {string} username
 * @param {string} password
 * @param {{ kick?: boolean }} [options]
 * @returns {Promise<{ ok: true, elapsedMs: number } | { ok: false, reason: string, elapsedMs: number }>}
 */
export async function loginToPtt(username, password, options = {}) {
  const kick = options.kick === true;
  const bot = new PttSocket();
  const started = Date.now();

  const fail = (reason) => ({ ok: false, reason, elapsedMs: Date.now() - started });

  try {
    await bot.connect();
    const sawPrompt = await bot.waitFor(
      (buf) => buf.includes("請輸入") || buf.includes("代號") || buf.includes("guest"),
      10_000
    );
    if (!sawPrompt) return fail(LOGIN_REASONS.NO_PROMPT);

    // Trailing comma enables UTF-8 after login. Password is sent once and discarded.
    bot.send(`${username},${KEY_ENTER}${password}${KEY_ENTER}`);

    const seen = { kick: false, tooOften: false, cleanup: false, anyKey: false };
    const deadline = Date.now() + 15_000;

    while (Date.now() < deadline) {
      const buf = bot.screen;

      if (buf.includes("密碼不對或無此帳號")) return fail(LOGIN_REASONS.WRONG_PASSWORD);
      if (buf.includes("請稍後再試") || buf.includes("系統過載")) {
        return fail(LOGIN_REASONS.SERVER_BUSY);
      }

      if (!seen.kick && buf.includes("您想刪除其他重複登入的連線嗎")) {
        bot.send(`${kick ? "y" : "n"}${KEY_ENTER}`);
        seen.kick = true;
      } else if (!seen.tooOften && buf.includes("請勿頻繁登入以免造成系統過度負荷")) {
        bot.send(KEY_ENTER);
        seen.tooOften = true;
      } else if (!seen.cleanup && buf.includes("您要刪除以上錯誤嘗試的記錄嗎")) {
        bot.send(`y${KEY_ENTER}`);
        seen.cleanup = true;
      } else if (!seen.anyKey && buf.includes("按任意鍵繼續")) {
        bot.send(KEY_ENTER);
        seen.anyKey = true;
      }

      if (buf.includes("【主功能表】")) {
        try {
          bot.send(`G${KEY_ENTER}Y${KEY_ENTER}`);
          await new Promise((r) => setTimeout(r, 400));
          bot.send(KEY_ENTER);
        } catch {
          /* logout is best-effort */
        }
        return { ok: true, elapsedMs: Date.now() - started };
      }

      await new Promise((r) => setTimeout(r, 250));
      if (bot.isClosed()) return fail(LOGIN_REASONS.SOCKET_CLOSED);
    }

    return fail(LOGIN_REASONS.TIMEOUT);
  } catch {
    return fail(LOGIN_REASONS.SOCKET_CLOSED);
  } finally {
    bot.close();
  }
}
