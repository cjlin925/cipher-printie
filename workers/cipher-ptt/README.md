# Cipher PTT Worker

Cloudflare Worker for **Speed PTT**. Matches `pttService.js` routes, enables CORS for GitHub Pages, and **never stores PTT passwords**.

## How it works

1. **`POST /login`** — browser wraps the password with RSA-OAEP (`passwordEnc`); Worker decrypts in memory, logs into `wss://ws.ptt.cc/bbs`, then logs out. Plaintext passwords are rejected. Nothing is stored.
2. **Boards / articles** — fetched from `https://www.ptt.cc` (with `over18=1`) so the reader stays fast and does not keep a BBS session open.
3. **Session token** — HMAC-signed, 12-hour browser token. Not a PTT cookie.

## Endpoints

| Method | Path | Response |
|--------|------|----------|
| `OPTIONS` | `*` | CORS preflight |
| `GET` | `/crypto` | `{ alg, publicKey }` RSA-OAEP-256 JWK |
| `POST` | `/login` | `{ username, passwordEnc }` → `{ ok, sessionToken, user }` |
| `GET` | `/hot-boards` | `{ boards }` |
| `GET` | `/boards/:name` | `{ board, articles }` |
| `GET` | `/boards/:name/:id` | `{ article }` |

## Setup

```bash
cd workers/cipher-ptt
npm install
npx wrangler login
npx wrangler secret put SESSION_SECRET      # signs browser session tokens
npx wrangler secret put LOGIN_PRIVATE_JWK   # RSA private JWK; paste from .dev.vars
npm run dev      # local: http://127.0.0.1:8787  (reads .dev.vars)
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
- [x] Reject plaintext `password` on `/login` (RSA-OAEP `passwordEnc` only)
- [x] Do not `env.KV.put` credentials
- [x] Prefer short-lived session tokens
- [ ] Tighten CORS to production origins only before public launch
- [ ] `npx wrangler secret put SESSION_SECRET` and `LOGIN_PRIVATE_JWK` on the deployed worker
