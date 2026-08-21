# Cipher PTT Worker (stub)

Cloudflare Worker scaffold for **Speed PTT**. Matches `pttService.js` routes, enables CORS for GitHub Pages, and **never stores PTT passwords**.

## Endpoints

| Method | Path | Response |
|--------|------|----------|
| `OPTIONS` | `*` | CORS preflight |
| `POST` | `/login` | `{ ok, sessionToken, user }` |
| `GET` | `/hot-boards` | `{ boards }` |
| `GET` | `/boards/:name` | `{ board, articles }` |
| `GET` | `/boards/:name/:id` | `{ article }` |

Current behavior is **stub / demo data**. Replace the handlers later with a real PTT bridge (WebSocket/over18/session pool). Keep the rule: credentials only transit memory for the request — no KV/D1/R2 password writes.

## Setup

```bash
cd workers/cipher-ptt
npm install
npx wrangler login
npm run dev      # local: http://127.0.0.1:8787
npm run deploy   # → https://cipher-ptt-worker.<account>.workers.dev
```

## Connect Speed PTT

1. Open `/cipher-printie/speed-ptt.html`
2. Paste the Worker URL (no trailing slash), e.g. `https://cipher-ptt-worker.YOUR_SUBDOMAIN.workers.dev`
3. Login — Demo Mode turns off automatically when a Worker URL is set

Allowed browser origins (CORS):

- `https://cjlin925.github.io`
- `http://localhost:*` / `http://127.0.0.1:*` (local testing)
- `null` (some `file://` edge cases — prefer a local static server)

## Security checklist

- [ ] Do not log `password`
- [ ] Do not `env.KV.put` credentials
- [ ] Prefer short-lived session tokens
- [ ] Tighten CORS to production origins only before public launch
