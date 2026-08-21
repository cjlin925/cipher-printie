# Cipher PTT Worker

Cloudflare Worker for **Speed PTT**. Matches `pttService.js` routes, enables CORS for GitHub Pages, and **never stores PTT passwords**.

## How it works

1. **`POST /login`** — opens `wss://ws.ptt.cc/bbs`, logs into PTT, then logs out. Password is used only for that request.
2. **Boards / articles** — fetched from `https://www.ptt.cc` (with `over18=1`) so the reader stays fast and does not keep a BBS session open.
3. **Session token** — HMAC-signed, 12-hour browser token. Not a PTT cookie.

## Endpoints

| Method | Path | Response |
|--------|------|----------|
| `OPTIONS` | `*` | CORS preflight |
| `POST` | `/login` | `{ ok, sessionToken, user }` |
| `GET` | `/hot-boards` | `{ boards }` |
| `GET` | `/boards/:name` | `{ board, articles }` |
| `GET` | `/boards/:name/:id` | `{ article }` |

## Setup

```bash
cd workers/cipher-ptt
npm install
npx wrangler login
npx wrangler secret put SESSION_SECRET   # random string; signs session tokens only
npm run dev      # local: http://127.0.0.1:8787
npm run deploy   # → https://cipher-ptt-worker.<account>.workers.dev
```

`wrangler.toml` has a dev `SESSION_SECRET` fallback so local `npm run dev` works without the secret command. Override it in production.

## Connect Speed PTT

1. Open `/cipher-printie/speed-ptt.html`
2. Paste the Worker URL (no trailing slash), e.g. `https://cipher-ptt-worker.YOUR_SUBDOMAIN.workers.dev`
3. Login with a real PTT account — first login may take several seconds

Allowed browser origins (CORS):

- `https://cjlin925.github.io`
- `http://localhost:*` / `http://127.0.0.1:*` (local testing)

## Security checklist

- [x] Do not log `password`
- [x] Do not `env.KV.put` credentials
- [x] Prefer short-lived session tokens
- [ ] Tighten CORS to production origins only before public launch
- [ ] `npx wrangler secret put SESSION_SECRET` on the deployed worker
