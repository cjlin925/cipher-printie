/**
 * Cipher PTT Speed — API & credential layer
 *
 * Talks to a Cloudflare Worker proxy. Never persists plaintext PTT
 * credentials on any server; encrypted blobs stay in the browser.
 *
 * Worker contract (expected JSON endpoints):
 *   GET  /crypto             → { alg, publicKey } RSA-OAEP-256 JWK
 *   POST /login              { username, passwordEnc } → { ok, sessionToken?, user?, favorites? }
 *   POST /favorites          { username, passwordEnc } → { ok, favorites }
 *   GET  /hot-boards         → { boards: HotBoard[] }
 *   GET  /boards/:name       → { board, articles: ArticleSummary[] }
 *   GET  /boards/:name/:id   → { article: ArticleDetail }
 *
 * passwordEnc is RSA-OAEP-SHA-256 ciphertext (base64url). Plaintext
 * passwords are never sent to the Worker.
 */

const STORAGE_KEYS = Object.freeze({
  vault: "cipher-ptt-speed.vault.v1",
  session: "cipher-ptt-speed.session.v1",
  workerUrl: "cipher-ptt-speed.worker-url.v1",
  demoMode: "cipher-ptt-speed.demo.v1",
  rememberUser: "cipher-ptt-speed.remember-user.v1",
  favorites: "cipher-ptt-speed.favorites.v1",
  pttFavorites: "cipher-ptt-speed.ptt-favorites.v1",
  webauthn: "cipher-ptt-speed.webauthn.v1",
});

export const APP_VERSION = "0.5.3";

const DEFAULT_WORKER_URL = "";

/** @typedef {{ name: string, title?: string, nuser?: number, hot?: boolean }} HotBoard */
/** @typedef {{ id: string, title: string, author: string, date?: string, push?: number, board?: string }} ArticleSummary */
/** @typedef {{ id: string, board: string, title: string, author: string, date?: string, content: string, push?: number }} ArticleDetail */

export class PttServiceError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, code?: string, cause?: unknown }} [meta]
   */
  constructor(message, meta = {}) {
    super(message);
    this.name = "PttServiceError";
    this.status = meta.status;
    this.code = meta.code || "UNKNOWN";
    this.cause = meta.cause;
  }
}

/**
 * Thin Web Crypto helpers for AES-GCM credential vaults.
 * Key material is derived from a local unlock secret (PIN / passphrase).
 * WebAuthn PRF can also wrap a copy of the vault for Touch ID / Face ID.
 */
const CryptoVault = {
  textEncoder: new TextEncoder(),
  textDecoder: new TextDecoder(),

  bytesToBase64(bytes) {
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  },

  base64ToBytes(b64) {
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  },

  async deriveKey(secret, saltBytes) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      this.textEncoder.encode(secret),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 210_000,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  },

  /**
   * @param {{ username: string, password: string }} credentials
   * @param {string} unlockSecret
   */
  async seal(credentials, unlockSecret) {
    if (!window.crypto?.subtle) {
      throw new PttServiceError("Web Crypto unavailable in this browser.", {
        code: "CRYPTO_UNAVAILABLE",
      });
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(unlockSecret, salt);
    const payload = this.textEncoder.encode(JSON.stringify(credentials));
    const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, payload);
    return {
      v: 1,
      alg: "AES-GCM-256/PBKDF2",
      salt: this.bytesToBase64(salt),
      iv: this.bytesToBase64(iv),
      ciphertext: this.bytesToBase64(new Uint8Array(cipherBuf)),
      usernameHint: String(credentials.username || "").slice(0, 3),
      savedAt: new Date().toISOString(),
    };
  },

  /**
   * @param {object} vault
   * @param {string} unlockSecret
   * @returns {Promise<{ username: string, password: string }>}
   */
  async open(vault, unlockSecret) {
    const key = await this.deriveKey(unlockSecret, this.base64ToBytes(vault.salt));
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: this.base64ToBytes(vault.iv) },
      key,
      this.base64ToBytes(vault.ciphertext)
    );
    return JSON.parse(this.textDecoder.decode(plainBuf));
  },

  /**
   * @param {unknown} payload
   * @param {BufferSource} rawKeyBytes
   */
  async wrapWithRawKey(payload, rawKeyBytes) {
    const digest = await crypto.subtle.digest("SHA-256", rawKeyBytes);
    const key = await crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipherBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      this.textEncoder.encode(JSON.stringify(payload))
    );
    return {
      iv: this.bytesToBase64(iv),
      ciphertext: this.bytesToBase64(new Uint8Array(cipherBuf)),
    };
  },

  /**
   * @param {{ iv: string, ciphertext: string }} blob
   * @param {BufferSource} rawKeyBytes
   */
  async unwrapWithRawKey(blob, rawKeyBytes) {
    const digest = await crypto.subtle.digest("SHA-256", rawKeyBytes);
    const key = await crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["decrypt"]);
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: this.base64ToBytes(blob.iv) },
      key,
      this.base64ToBytes(blob.ciphertext)
    );
    return JSON.parse(this.textDecoder.decode(plainBuf));
  },
};

const DemoData = {
  boards: [
    { name: "Gossiping", title: "八卦板", nuser: 12840, hot: true },
    { name: "Stock", title: "股板", nuser: 6120, hot: true },
    { name: "Baseball", title: "棒球", nuser: 4210, hot: true },
    { name: "Tech_Job", title: "科技業面試", nuser: 2890, hot: true },
    { name: "Mobilesales", title: "手機買賣", nuser: 1980, hot: false },
    { name: "joke", title: "就可板", nuser: 1540, hot: false },
  ],

  /** @type {Record<string, ArticleSummary[]>} */
  articles: {
    Gossiping: [
      { id: "M.1700000001.A.001", title: "[爆卦] Speed PTT 原型上線測試", author: "cipherer", date: "08/21", push: 99, board: "Gossiping" },
      { id: "M.1700000002.A.002", title: "[問卦] 有沒有秒開文章的八卦", author: "fastreader", date: "08/21", push: 42, board: "Gossiping" },
      { id: "M.1700000003.A.003", title: "[新聞] 無伺服器前端討論串", author: "newsbot", date: "08/20", push: 18, board: "Gossiping" },
    ],
    Stock: [
      { id: "M.1700000101.A.001", title: "[標的] 示範用假資料勿跟單", author: "value", date: "08/21", push: 12, board: "Stock" },
      { id: "M.1700000102.A.002", title: "[心得] 長文閱讀體驗測試", author: "holder", date: "08/20", push: 7, board: "Stock" },
    ],
    Baseball: [
      { id: "M.1700000201.A.001", title: "[Live] 示範賽況推文串", author: "umpire", date: "08/21", push: 56, board: "Baseball" },
    ],
    Tech_Job: [
      { id: "M.1700000301.A.001", title: "[請益] Cloudflare Worker 架構分享", author: "sre", date: "08/21", push: 33, board: "Tech_Job" },
      { id: "M.1700000302.A.002", title: "[心得] 前後端分離與行動 App", author: "mobiledev", date: "08/19", push: 21, board: "Tech_Job" },
    ],
    Mobilesales: [
      { id: "M.1700000401.A.001", title: "[販售] Demo only", author: "seller", date: "08/18", push: 3, board: "Mobilesales" },
    ],
    joke: [
      { id: "M.1700000501.A.001", title: "[豪傑] 終端機黑底白字退散", author: "joker", date: "08/21", push: 88, board: "joke" },
    ],
  },

  /**
   * @param {string} boardName
   * @param {string} articleId
   * @returns {ArticleDetail}
   */
  articleContent(boardName, articleId) {
    const list = this.articles[boardName] || [];
    const summary = list.find((a) => a.id === articleId) || {
      id: articleId,
      title: articleId,
      author: "unknown",
      date: "—",
      push: 0,
      board: boardName,
    };
    return {
      id: summary.id,
      board: boardName,
      title: summary.title,
      author: summary.author,
      date: summary.date,
      push: summary.push,
      content: [
        `作者: ${summary.author} (${summary.author})`,
        `看板: ${boardName}`,
        `標題: ${summary.title}`,
        `時間: 2026-${summary.date || "08/21"} 12:00:00`,
        "",
        "※ 此為 Cipher PTT Speed 本機示範內容（Demo Mode）。",
        "※ 設定 Cloudflare Worker URL 後，會改打真實 PTT（登入走 ws.ptt.cc，文章走 www.ptt.cc）。",
        "",
        "設計原則：",
        "1. 帳密只在瀏覽器端加密保存，Worker 不落盤。",
        "2. UI 與 pttService 解耦，方便之後包成 Capacitor App。",
        "3. 文章閱讀走純文字排版，追求秒開、無干擾。",
        "",
        "\u001b[1;33mANSI 色碼示範\u001b[0m：\u001b[31m紅\u001b[0m \u001b[32m綠\u001b[0m \u001b[36m青\u001b[0m \u001b[35m紫\u001b[0m",
        "",
        "推文區（示範）",
        "推 cipherer: 終於不是 telnet 轉圈圈了",
        "噓 lurker: 還在等 Worker",
        "→ fastreader: skeleton loader 讚",
        "",
        "--",
        "※ 發信站: Cipher PTT Speed (demo)",
      ].join("\n"),
    };
  },
};

export class PttService {
  #livePassword = null;

  /**
   * @param {{ workerUrl?: string, demoMode?: boolean }} [options]
   */
  constructor(options = {}) {
    this.workerUrl = (options.workerUrl ?? this.#readWorkerUrl() ?? DEFAULT_WORKER_URL).replace(/\/$/, "");
    this.demoMode =
      typeof options.demoMode === "boolean"
        ? options.demoMode
        : this.#readDemoFlag() || !this.workerUrl;
    /** @type {string | null} */
    this.sessionToken = this.#readSession()?.token || null;
    /** @type {string | null} */
    this.username = this.#readSession()?.username || null;
  }

  #readWorkerUrl() {
    try {
      return localStorage.getItem(STORAGE_KEYS.workerUrl) || "";
    } catch {
      return "";
    }
  }

  #readDemoFlag() {
    try {
      return localStorage.getItem(STORAGE_KEYS.demoMode) === "1";
    } catch {
      return false;
    }
  }

  #readSession() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.session);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  #writeSession(session) {
    if (!session) {
      localStorage.removeItem(STORAGE_KEYS.session);
      this.sessionToken = null;
      this.username = null;
      return;
    }
    localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(session));
    this.sessionToken = session.token || null;
    this.username = session.username || null;
  }

  setWorkerUrl(url) {
    this.workerUrl = String(url || "").trim().replace(/\/$/, "");
    localStorage.setItem(STORAGE_KEYS.workerUrl, this.workerUrl);
    if (this.workerUrl) {
      this.demoMode = false;
      localStorage.setItem(STORAGE_KEYS.demoMode, "0");
    }
  }

  setDemoMode(enabled) {
    this.demoMode = Boolean(enabled);
    localStorage.setItem(STORAGE_KEYS.demoMode, this.demoMode ? "1" : "0");
  }

  isLoggedIn() {
    return Boolean(this.sessionToken || (this.demoMode && this.username));
  }

  /**
   * PTT 我的最愛 (from last login) merged with local ★ extras.
   * @returns {Array<{ name: string, title?: string }>}
   */
  getFavoriteBoards() {
    const ptt = this.#readBoardList(STORAGE_KEYS.pttFavorites);
    const local = this.#readBoardList(STORAGE_KEYS.favorites);
    const seen = new Set(ptt.map((board) => board.name.toLowerCase()));
    return [...ptt, ...local.filter((board) => !seen.has(board.name.toLowerCase()))];
  }

  /** @param {string} key */
  #readBoardList(key) {
    try {
      const raw = localStorage.getItem(key);
      const list = raw ? JSON.parse(raw) : [];
      if (!Array.isArray(list)) return [];
      return list
        .map((item) => ({
          name: String(item?.name || "").trim(),
          title: String(item?.title || item?.name || "").trim(),
        }))
        .filter((item) => item.name);
    } catch {
      return [];
    }
  }

  /** @param {Array<{ name: string, title?: string }>} boards */
  savePttFavorites(boards) {
    const cleaned = (Array.isArray(boards) ? boards : [])
      .map((item) => ({
        name: String(item?.name || "").trim(),
        title: String(item?.title || item?.name || "").trim(),
      }))
      .filter((item) => item.name)
      .slice(0, 40);
    localStorage.setItem(STORAGE_KEYS.pttFavorites, JSON.stringify(cleaned));
    return cleaned;
  }

  /** @param {Array<{ name: string, title?: string }>} boards */
  saveFavoriteBoards(boards) {
    const cleaned = (Array.isArray(boards) ? boards : [])
      .map((item) => ({
        name: String(item?.name || "").trim(),
        title: String(item?.title || item?.name || "").trim(),
      }))
      .filter((item) => item.name)
      .slice(0, 40);
    localStorage.setItem(STORAGE_KEYS.favorites, JSON.stringify(cleaned));
    return cleaned;
  }

  isFavorite(boardName) {
    const name = String(boardName || "").trim();
    return this.getFavoriteBoards().some((board) => board.name === name);
  }

  /**
   * @param {{ name: string, title?: string }} board
   * @returns {boolean} true if now favorited
   */
  toggleFavorite(board) {
    const name = String(board?.name || "").trim();
    if (!name) return false;
    const title = String(board?.title || name).trim() || name;
    let list = this.getFavoriteBoards().filter((item) => item.name !== name);
    const wasFavorite = this.isFavorite(name);
    if (!wasFavorite) list = [{ name, title }, ...list];
    this.saveFavoriteBoards(list);
    return !wasFavorite;
  }

  hasVault() {
    try {
      return Boolean(localStorage.getItem(STORAGE_KEYS.vault));
    } catch {
      return false;
    }
  }

  getVaultMeta() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.vault);
      if (!raw) return null;
      const vault = JSON.parse(raw);
      return {
        usernameHint: vault.usernameHint || "",
        savedAt: vault.savedAt || null,
        alg: vault.alg || "",
      };
    } catch {
      return null;
    }
  }

  /**
   * Encrypt + persist credentials locally. Plaintext never leaves the device
   * except transiently inside login() → Worker (no server-side storage).
   * @param {{ username: string, password: string }} credentials
   * @param {string} unlockSecret  local PIN / passphrase for the vault
   */
  async saveEncryptedCredentials(credentials, unlockSecret) {
    const username = String(credentials?.username || "").trim();
    const password = String(credentials?.password || "");
    if (!username || !password) {
      throw new PttServiceError("請輸入完整的 PTT 帳號與密碼。", { code: "VALIDATION" });
    }
    if (!unlockSecret || unlockSecret.length < 4) {
      throw new PttServiceError("解鎖密語至少 4 個字元。", { code: "VALIDATION" });
    }
    const vault = await CryptoVault.seal({ username, password }, unlockSecret);
    localStorage.setItem(STORAGE_KEYS.vault, JSON.stringify(vault));
    return this.getVaultMeta();
  }

  /**
   * @param {string} unlockSecret
   */
  async loadEncryptedCredentials(unlockSecret) {
    const raw = localStorage.getItem(STORAGE_KEYS.vault);
    if (!raw) {
      throw new PttServiceError("尚未儲存加密憑證。", { code: "NO_VAULT" });
    }
    try {
      return await CryptoVault.open(JSON.parse(raw), unlockSecret);
    } catch (cause) {
      throw new PttServiceError("解鎖失敗，請確認密語。", { code: "UNLOCK_FAILED", cause });
    }
  }

  clearVault() {
    localStorage.removeItem(STORAGE_KEYS.vault);
    this.clearWebAuthn();
  }

  logout() {
    this.#livePassword = null;
    this.#writeSession(null);
  }

  getRememberedUsername() {
    try {
      return localStorage.getItem(STORAGE_KEYS.rememberUser) || "";
    } catch {
      return "";
    }
  }

  /**
   * Stores the PTT id only (never the password). Pass empty to forget.
   * @param {string} username
   */
  setRememberedUsername(username) {
    const value = String(username || "").trim();
    try {
      if (value) localStorage.setItem(STORAGE_KEYS.rememberUser, value);
      else localStorage.removeItem(STORAGE_KEYS.rememberUser);
    } catch {
      /* ignore quota / private mode */
    }
  }

  /**
   * Platform authenticator (Touch ID on Mac, Face ID on iPhone).
   * Credentials are wrapped with the WebAuthn PRF output — never sent to a server.
   */
  biometricLabel() {
    const ua = navigator.userAgent || "";
    if (/iPhone|iPad/.test(ua)) return "Face ID";
    if (/Mac/.test(ua)) return "Touch ID";
    return "生物辨識";
  }

  hasWebAuthn() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.webauthn);
      if (!raw) return false;
      const rec = JSON.parse(raw);
      return Boolean(rec?.credId && rec?.wrap && rec?.prfSalt);
    } catch {
      return false;
    }
  }

  clearWebAuthn() {
    try {
      localStorage.removeItem(STORAGE_KEYS.webauthn);
    } catch {
      /* ignore */
    }
  }

  #webauthnRpId() {
    const host = window.location.hostname;
    if (!host || host === "localhost" || host === "127.0.0.1") return host || "localhost";
    return host;
  }

  #randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  #asBuffer(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
  }

  #prfFromCredential(credential) {
    const ext = credential?.getClientExtensionResults?.() || {};
    const first = ext.prf?.results?.first;
    if (!first) return null;
    return first instanceof Uint8Array ? first : new Uint8Array(first);
  }

  /**
   * Bind platform biometrics and wrap PTT credentials with the PRF secret.
   * @param {{ username: string, password: string }} credentials
   */
  async enrollWebAuthn(credentials) {
    const username = String(credentials?.username || "").trim();
    const password = String(credentials?.password || "");
    if (!username || !password) {
      throw new PttServiceError("請先輸入 PTT 帳號與密碼再綁定生物辨識。", { code: "VALIDATION" });
    }
    if (!window.PublicKeyCredential || !window.crypto?.subtle) {
      throw new PttServiceError("此瀏覽器不支援生物辨識解鎖。", { code: "WEBAUTHN_UNAVAILABLE" });
    }
    const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().catch(
      () => false
    );
    if (!available) {
      throw new PttServiceError("這台裝置沒有可用的指紋 / 面容感應器。", { code: "NO_PLATFORM_AUTH" });
    }

    const salt = this.#randomBytes(32);
    const userId = this.#randomBytes(16);
    const rpId = this.#webauthnRpId();
    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: {
          challenge: this.#asBuffer(this.#randomBytes(32)),
          rp: { name: "Speed PTT", id: rpId },
          user: {
            id: this.#asBuffer(userId),
            name: username,
            displayName: username,
          },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          timeout: 120_000,
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            residentKey: "preferred",
            userVerification: "required",
          },
          extensions: { prf: { eval: { first: this.#asBuffer(salt) } } },
        },
      });
    } catch (cause) {
      if (cause?.name === "NotAllowedError") {
        throw new PttServiceError("已取消生物辨識。", { code: "WEBAUTHN_CANCELLED", cause });
      }
      throw new PttServiceError("無法綁定生物辨識。", { code: "WEBAUTHN_CREATE", cause });
    }

    let prf = this.#prfFromCredential(credential);
    if (!prf) {
      try {
        const asserted = await navigator.credentials.get({
          publicKey: {
            challenge: this.#asBuffer(this.#randomBytes(32)),
            rpId,
            timeout: 120_000,
            userVerification: "required",
            allowCredentials: [
              {
                type: "public-key",
                id: credential.rawId,
                transports: ["internal"],
              },
            ],
            extensions: { prf: { eval: { first: this.#asBuffer(salt) } } },
          },
        });
        prf = this.#prfFromCredential(asserted);
      } catch (cause) {
        throw new PttServiceError("生物辨識已建立，但此瀏覽器不支援用它解鎖密碼（缺 PRF）。", {
          code: "WEBAUTHN_NO_PRF",
          cause,
        });
      }
    }
    if (!prf) {
      throw new PttServiceError("此瀏覽器的生物辨識無法用來加密密碼庫（需要 WebAuthn PRF）。", {
        code: "WEBAUTHN_NO_PRF",
      });
    }

    const wrap = await CryptoVault.wrapWithRawKey({ username, password }, prf);
    localStorage.setItem(
      STORAGE_KEYS.webauthn,
      JSON.stringify({
        v: 1,
        credId: CryptoVault.bytesToBase64(new Uint8Array(credential.rawId)),
        rpId,
        prfSalt: CryptoVault.bytesToBase64(salt),
        wrap,
        usernameHint: username.slice(0, 3),
        enrolledAt: new Date().toISOString(),
      })
    );
    return {
      ok: true,
      method: "webauthn",
      message: `已綁定${this.biometricLabel()}，之後可用它解鎖登入。`,
    };
  }

  /**
   * Unlock wrapped credentials with Touch ID / Face ID.
   * @returns {Promise<{ username: string, password: string }>}
   */
  async unlockWithWebAuthn() {
    if (!window.PublicKeyCredential) {
      throw new PttServiceError("此瀏覽器尚不支援 WebAuthn / 生物辨識。", {
        code: "WEBAUTHN_UNAVAILABLE",
      });
    }
    const raw = localStorage.getItem(STORAGE_KEYS.webauthn);
    if (!raw) {
      throw new PttServiceError(`尚未綁定${this.biometricLabel()}。請先用帳密登入後再綁定。`, {
        code: "NO_WEBAUTHN",
      });
    }
    let rec;
    try {
      rec = JSON.parse(raw);
    } catch {
      throw new PttServiceError("生物辨識設定損壞，請重新綁定。", { code: "WEBAUTHN_BAD" });
    }

    let credential;
    try {
      credential = await navigator.credentials.get({
        publicKey: {
          challenge: this.#asBuffer(this.#randomBytes(32)),
          rpId: rec.rpId || this.#webauthnRpId(),
          timeout: 120_000,
          userVerification: "required",
          allowCredentials: [
            {
              type: "public-key",
              id: this.#asBuffer(CryptoVault.base64ToBytes(rec.credId)),
              transports: ["internal"],
            },
          ],
          extensions: {
            prf: { eval: { first: this.#asBuffer(CryptoVault.base64ToBytes(rec.prfSalt)) } },
          },
        },
      });
    } catch (cause) {
      if (cause?.name === "NotAllowedError") {
        throw new PttServiceError("已取消生物辨識。", { code: "WEBAUTHN_CANCELLED", cause });
      }
      throw new PttServiceError(`${this.biometricLabel()} 驗證失敗。`, { code: "WEBAUTHN_GET", cause });
    }

    const prf = this.#prfFromCredential(credential);
    if (!prf) {
      throw new PttServiceError("生物辨識成功，但無法解出密碼庫（缺 PRF）。", {
        code: "WEBAUTHN_NO_PRF",
      });
    }
    try {
      return await CryptoVault.unwrapWithRawKey(rec.wrap, prf);
    } catch (cause) {
      throw new PttServiceError("生物辨識解鎖失敗。", { code: "WEBAUTHN_UNWRAP", cause });
    }
  }

  /**
   * @param {string} path
   * @param {RequestInit & { json?: unknown }} [options]
   */
  async #request(path, options = {}) {
    if (!this.workerUrl) {
      throw new PttServiceError("尚未設定 Cloudflare Worker URL。", { code: "NO_WORKER" });
    }

    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    headers.set("X-Cipher-Client", "cipher-ptt-speed");
    if (options.json !== undefined) {
      headers.set("Content-Type", "application/json");
    }
    if (this.sessionToken) {
      headers.set("Authorization", `Bearer ${this.sessionToken}`);
    }

    const { json, ...rest } = options;
    let response;
    try {
      response = await fetch(`${this.workerUrl}${path}`, {
        ...rest,
        headers,
        body: json !== undefined ? JSON.stringify(json) : rest.body,
      });
    } catch (cause) {
      throw new PttServiceError("無法連線到 Worker，請檢查網路或 CORS。", {
        code: "NETWORK",
        cause,
      });
    }

    let data = null;
    const text = await response.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { raw: text };
      }
    }

    if (!response.ok) {
      throw new PttServiceError(
        (data && (data.error || data.message)) || `Worker 回應 ${response.status}`,
        { status: response.status, code: "HTTP" }
      );
    }
    return data;
  }

  /**
   * Wrap the PTT password with the Worker's RSA-OAEP public key so the
   * JSON body never contains plaintext credentials.
   * @param {string} password
   */
  async #encryptPassword(password) {
    if (!window.crypto?.subtle) {
      throw new PttServiceError("此瀏覽器無法加密密碼（需要 Web Crypto）。", {
        code: "CRYPTO_UNAVAILABLE",
      });
    }
    const data = await this.#request("/crypto");
    if (!data?.publicKey) {
      throw new PttServiceError("Worker 未提供加密公鑰。", { code: "NO_PUBKEY" });
    }
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        data.publicKey,
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
      );
      const cipher = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        key,
        new TextEncoder().encode(password)
      );
      return CryptoVault.bytesToBase64(new Uint8Array(cipher))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    } catch (cause) {
      throw new PttServiceError("密碼加密失敗。", { code: "ENCRYPT_FAILED", cause });
    }
  }

  #delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * @param {{ username: string, password: string }} credentials
   */
  async login(credentials) {
    const username = String(credentials?.username || "").trim();
    const password = String(credentials?.password || "");
    if (!username || !password) {
      throw new PttServiceError("請輸入完整的 PTT 帳號與密碼。", { code: "VALIDATION" });
    }

    if (this.demoMode || !this.workerUrl) {
      await this.#delay(280);
      this.#writeSession({
        token: `demo.${btoa(unescape(encodeURIComponent(username))).slice(0, 24)}`,
        username,
        mode: "demo",
        at: Date.now(),
      });
      this.#livePassword = password;
      this.savePttFavorites(DemoData.boards.slice(0, 4));
      return {
        ok: true,
        mode: "demo",
        user: { username },
        favorites: this.getFavoriteBoards(),
        message: "Demo Mode：未連 Worker，使用本機示範資料。",
      };
    }

    const passwordEnc = await this.#encryptPassword(password);
    const data = await this.#request("/login", {
      method: "POST",
      json: { username, passwordEnc },
    });

    const token = data.sessionToken || data.token || null;
    if (!token) {
      throw new PttServiceError("登入成功但未取得 session token。", { code: "NO_TOKEN" });
    }

    this.#writeSession({
      token,
      username: data.user?.username || username,
      mode: "worker",
      at: Date.now(),
    });
    this.#livePassword = password;
    if (Array.isArray(data.favorites) && data.favorites.length) {
      this.savePttFavorites(data.favorites);
    }

    return { ok: true, mode: "worker", user: data.user || { username }, ...data };
  }

  hasLiveCredentials() {
    return Boolean(this.username && this.#livePassword);
  }

  /**
   * Log into PTT again, press F, and replace the local favorite list.
   * @returns {Promise<Array<{ name: string, title?: string }>>}
   */
  async fetchFavorites() {
    if (this.demoMode || !this.workerUrl) {
      await this.#delay(180);
      return this.getFavoriteBoards();
    }
    if (!this.username || !this.#livePassword) {
      throw new PttServiceError("請先重新登入，才能向 PTT 重抓我的最愛。", { code: "NO_LIVE_CREDS" });
    }
    const passwordEnc = await this.#encryptPassword(this.#livePassword);
    const data = await this.#request("/favorites", {
      method: "POST",
      json: { username: this.username, passwordEnc },
    });
    const list = Array.isArray(data.favorites) ? data.favorites : [];
    if (list.length) this.savePttFavorites(list);
    return list;
  }

  /** @returns {Promise<{ boards: HotBoard[] }>} */
  async getHotBoards() {
    if (this.demoMode || !this.workerUrl) {
      await this.#delay(220);
      return { boards: DemoData.boards.map((b) => ({ ...b })) };
    }
    const data = await this.#request("/hot-boards");
    return { boards: data.boards || data || [] };
  }

  /**
   * @param {string} boardName
   * @returns {Promise<{ board: string, articles: ArticleSummary[] }>}
   */
  async getBoardArticles(boardName) {
    const name = String(boardName || "").trim();
    if (!name) {
      throw new PttServiceError("缺少看板名稱。", { code: "VALIDATION" });
    }

    if (this.demoMode || !this.workerUrl) {
      await this.#delay(260);
      const articles = (DemoData.articles[name] || []).map((a) => ({ ...a, board: name }));
      return { board: name, articles };
    }

    const data = await this.#request(`/boards/${encodeURIComponent(name)}`);
    return {
      board: data.board || name,
      articles: data.articles || [],
    };
  }

  /**
   * @param {string} boardName
   * @param {string} articleId
   * @returns {Promise<{ article: ArticleDetail }>}
   */
  async getArticleContent(boardName, articleId) {
    const board = String(boardName || "").trim();
    const id = String(articleId || "").trim();
    if (!board || !id) {
      throw new PttServiceError("缺少看板或文章編號。", { code: "VALIDATION" });
    }

    if (this.demoMode || !this.workerUrl) {
      await this.#delay(300);
      return { article: DemoData.articleContent(board, id) };
    }

    const data = await this.#request(
      `/boards/${encodeURIComponent(board)}/${encodeURIComponent(id)}`
    );
    return { article: data.article || data };
  }
}

export function createPttService(options) {
  return new PttService(options);
}

export default PttService;

console.log(`Speed PTT v${APP_VERSION}`);
