/**
 * Read-only PTT web (www.ptt.cc) — real boards / articles.
 * Uses over18=1 for age-gated boards. No credentials involved.
 */

const PTT_WEB = "https://www.ptt.cc";
const UA = "CipherPttWorker/0.2 (+https://cjlin925.github.io/cipher-printie/speed-ptt.html)";

export class PttWebError extends Error {
  /**
   * @param {string} message
   * @param {number} status
   */
  constructor(message, status = 502) {
    super(message);
    this.name = "PttWebError";
    this.status = status;
  }
}

function decodeEntities(value) {
  return String(value || "")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number(dec)))
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

function innerText(html) {
  return decodeEntities(
    String(html || "")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/p>/gi, "\n")
      .replace(/<\/div>/gi, "\n")
      .replace(/<[^>]+>/g, "")
  )
    .replace(/\u00a0/g, " ")
    .trim();
}

function parsePush(raw) {
  const text = String(raw || "").trim();
  if (!text) return 0;
  if (text === "爆") return 100;
  if (/^X\d+$/i.test(text)) return -Number(text.slice(1));
  const n = Number(text);
  return Number.isFinite(n) ? n : 0;
}

/** Map www.ptt.cc color spans (f0–f7 / b0–b7 / hl) into ANSI SGR for the reader. */
function htmlColorsToAnsi(html) {
  return String(html || "").replace(/<span\b([^>]*)>([\s\S]*?)<\/span>/gi, (_, attrs, inner) => {
    const converted = htmlColorsToAnsi(inner);
    const cls = `${attrs.match(/class\s*=\s*"([^"]*)"/i)?.[1] || ""} ${
      attrs.match(/class\s*=\s*'([^']*)'/i)?.[1] || ""
    }`;
    const codes = [];
    const hl = /\bhl\b/.test(cls);
    const fg = cls.match(/\bf([0-7])\b/);
    const bg = cls.match(/\bb([0-7])\b/);
    if (fg) codes.push((hl ? 90 : 30) + Number(fg[1]));
    else if (hl) codes.push(1);
    if (bg) codes.push(40 + Number(bg[1]));
    if (!codes.length) return converted;
    return `\x1b[${codes.join(";")}m${converted}\x1b[0m`;
  });
}

/**
 * @param {string} board
 * @param {string} [path]
 */
async function fetchPtt(board, path) {
  const url = path
    ? `${PTT_WEB}${path}`
    : `${PTT_WEB}/bbs/${board}`;
  const response = await fetch(url, {
    headers: {
      "User-Agent": UA,
      Cookie: "over18=1",
      Accept: "text/html,application/xhtml+xml",
    },
    redirect: "follow",
  });
  const html = await response.text();
  if (response.status === 404) {
    throw new PttWebError("找不到看板或文章", 404);
  }
  if (!response.ok) {
    throw new PttWebError(`PTT 網頁回應 ${response.status}`, 502);
  }
  if (html.includes('action="/ask/over18"')) {
    throw new PttWebError("無法通過 18 歲驗證", 403);
  }
  return html;
}

/**
 * @returns {Promise<Array<{ name: string, title: string, nuser: number, hot: boolean }>>}
 */
export async function fetchHotBoards() {
  const html = await fetchPtt("", "/bbs/hotboards.html");
  const boards = [];
  const re =
    /<a class="board" href="\/bbs\/([^/]+)\/index\.html">\s*<div class="board-name">([^<]*)<\/div>\s*<div class="board-nuser">(?:<span[^>]*>)?([^<]*)(?:<\/span>)?<\/div>\s*<div class="board-class">([^<]*)<\/div>\s*<div class="board-title">([^<]*)<\/div>/g;

  let match;
  while ((match = re.exec(html))) {
    const name = match[1].trim();
    const title = decodeEntities(match[5] || "").replace(/^◎/, "").trim() || name;
    const nuser = Number(String(match[3] || "").replace(/[^\d]/g, "")) || 0;
    boards.push({ name, title, nuser, hot: true });
    if (boards.length >= 48) break;
  }

  if (!boards.length) {
    throw new PttWebError("熱門看板解析失敗", 502);
  }
  return boards;
}

/**
 * @param {string} board
 * @returns {Promise<Array<{ id: string, title: string, author: string, date: string, push: number, board: string }>>}
 */
export async function fetchBoardArticles(board) {
  const html = await fetchPtt(board, `/bbs/${board}/index.html`);
  const prevPath = html.match(/href="(\/bbs\/[^"]+)"[^>]*>[\s\S]{0,40}上頁/)?.[1];
  let prevHtml = "";
  if (prevPath && !prevPath.endsWith("/index1.html")) {
    try {
      prevHtml = await fetchPtt(board, prevPath);
    } catch {
      prevHtml = "";
    }
  }

  const [mainHtml, restHtml = ""] = html.split(/<div class="r-list-sep">/);
  const [prevMainHtml] = prevHtml.split(/<div class="r-list-sep">/);
  const articles = [
    ...parseArticleEntries(mainHtml, board).reverse(),
    ...parseArticleEntries(prevMainHtml || "", board).reverse(),
    ...parseArticleEntries(restHtml, board),
  ];
  return articles.slice(0, 40);
}

/**
 * @param {string} html
 * @param {string} board
 */
function parseArticleEntries(html, board) {
  const chunks = html.split('<div class="r-ent">').slice(1);
  const articles = [];

  for (const chunk of chunks) {
    const href = chunk.match(/href="\/bbs\/[^/]+\/(M\.[^"]+)\.html"/);
    if (!href) continue;
    const titleMatch = chunk.match(/<div class="title">[\s\S]*?<a href="\/bbs\/[^"]+">([\s\S]*?)<\/a>/);
    const authorMatch = chunk.match(/<div class="author">([^<]*)<\/div>/);
    const dateMatch = chunk.match(/<div class="date">([^<]*)<\/div>/);
    const nrecMatch = chunk.match(/<div class="nrec">(?:<span[^>]*>)?([^<]*)/);
    articles.push({
      id: href[1],
      title: innerText(titleMatch?.[1] || href[1]),
      author: innerText(authorMatch?.[1] || ""),
      date: innerText(dateMatch?.[1] || ""),
      push: parsePush(nrecMatch?.[1]),
      board,
    });
  }

  return articles;
}

/**
 * @param {string} board
 * @param {string} articleId
 */
export async function fetchArticle(board, articleId) {
  const id = String(articleId || "").replace(/\.html$/i, "");
  const html = await fetchPtt(board, `/bbs/${board}/${id}.html`);
  const start = html.indexOf('id="main-content"');
  if (start < 0) {
    throw new PttWebError("文章內容解析失敗", 502);
  }
  const tagEnd = html.indexOf(">", start);
  const poll = html.indexOf('<div id="article-polling"', start);
  const slice = html.slice(tagEnd + 1, poll > start ? poll : start + 80_000);

  const meta = {};
  const metaRe =
    /<span class="article-meta-tag">([^<]+)<\/span><span class="article-meta-value">([^<]*)<\/span>/g;
  let metaMatch;
  while ((metaMatch = metaRe.exec(slice))) {
    meta[metaMatch[1].trim()] = decodeEntities(metaMatch[2] || "").trim();
  }

  const bodyHtml = slice
    .replace(/<div class="article-metaline[\s\S]*?<\/div>/g, "")
    .replace(/<div class="article-metaline-right"[\s\S]*?<\/div>/g, "");

  const coloredBody = htmlColorsToAnsi(bodyHtml);

  const withPushes = coloredBody.replace(
    /<div class="push">([\s\S]*?)<\/div>/g,
    (_, pushHtml) => {
      const tag = innerText(pushHtml.match(/push-tag">([^<]*)/)?.[1] || "").trim();
      const user = innerText(pushHtml.match(/push-userid">([^<]*)/)?.[1] || "").trim();
      const content = innerText(htmlColorsToAnsi(pushHtml.match(/push-content">:?\s*([\s\S]*?)<\/span>/)?.[1] || ""));
      const time = innerText(pushHtml.match(/push-ipdatetime">([^<]*)/)?.[1] || "").trim();
      return `\n${tag} ${user}${content ? `: ${content}` : ""}${time ? `  ${time}` : ""}`;
    }
  );

  const content = innerText(withPushes)
    .replace(/<[^>]*$/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  const pushCount = (slice.match(/<div class="push">/g) || []).length;

  return {
    id,
    board: meta["看板"] || board,
    title: meta["標題"] || id,
    author: (meta["作者"] || "").replace(/\s*\(.*\)$/, "").trim() || "unknown",
    date: meta["時間"] || "",
    push: pushCount,
    content,
  };
}
