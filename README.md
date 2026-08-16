# URLGuard

A heuristic fake-URL / phishing detector: paste a link, get a 0–100 risk
score and a breakdown of what triggered it (typosquatting, homoglyph swaps,
brand spoofing, suspicious TLDs, etc). Full-stack app — Express backend does
the real analysis, a static frontend calls it.

```
┌────────────┐   POST /api/analyze   ┌──────────────────┐
│  Frontend  │ ─────────────────────▶│  Express backend  │
│ (public/)  │◀───────────────────── │  src/analyzer.js  │
└────────────┘     JSON result       └──────────────────┘
                                              │
                                     hostname+score only
                                              ▼
                                      data/history.json
```

## Features

- **Server-side analysis** (`src/analyzer.js`) — 11 heuristic checks: IP
  hosts, high-abuse TLDs, homoglyph substitution (including brand names
  disguised with digit swaps like `paypa1.com`), brand spoofing, excessive
  subdomains, phishing keyword stacking, abnormal length, missing HTTPS,
  heavy URL-encoding, sensitive path keywords, and `@`-symbol redirect tricks.
- **REST API** — `/api/analyze`, `/api/history`, `/api/stats`, `/api/health`.
- **Privacy-conscious history** — only the hostname, score, and level are
  persisted, never the full URL or query string.
- **Rate limiting + security headers** via `express-rate-limit` and `helmet`.
- **Offline-friendly frontend** — if the API is unreachable, the page falls
  back to a local copy of the same checks so it still works standalone.
- **Test suite** using Node's built-in test runner (no extra dependency).

## Project structure

```
urlguard/
├── server.js              # Express app, API routes, static file serving
├── src/
│   ├── analyzer.js        # Pure heuristic scoring engine (unit-testable)
│   └── store.js           # JSON-file history/stats persistence
├── public/
│   └── index.html          # Frontend (calls the API, has an offline fallback)
├── test/
│   └── analyzer.test.js
├── data/                   # Created at runtime; history.json lives here
├── Dockerfile
├── docker-compose.yml
├── render.yaml             # Render.com blueprint
├── Procfile                 # Heroku / Railway style
└── .github/workflows/ci.yml
```

## Run locally

Requires Node.js 18+.

```bash
npm install
cp .env.example .env
npm start
# → http://localhost:3000
```

For auto-reload during development:

```bash
npm run dev
```

Run the test suite:

```bash
npm test
```

## API reference

### `POST /api/analyze`
```json
// request
{ "url": "https://paypa1.com/login/secure-account" }
```
```json
// response 200
{
  "input": "https://paypa1.com/login/secure-account",
  "normalizedUrl": "https://paypa1.com/login/secure-account",
  "hostname": "paypa1.com",
  "registeredDomain": "paypa1.com",
  "score": 63,
  "level": "danger",
  "flags": [ { "id": "homoglyph", "name": "Homoglyph Substitution", "triggered": true, "weight": 35, "desc": "..." }, ... ],
  "analyzedAt": "2026-08-16T07:36:47.407Z"
}
```
Returns `400` with `{ "error": "..." }` if `url` is missing or unparsable.

### `GET /api/history?limit=20`
Recent scans (hostname + score + level only), most recent first.

### `GET /api/stats`
```json
{ "total": 42, "safe": 20, "warn": 15, "danger": 7 }
```

### `GET /api/health`
Liveness check for uptime monitors / container orchestrators.

## Deploying

### GitHub → Render (recommended, has a free tier)
1. Push this repo to GitHub.
2. In Render, choose **New → Blueprint** and point it at the repo — it will
   read `render.yaml` and provision the service automatically.
3. Alternatively, **New → Web Service**: build command `npm install`, start
   command `node server.js`.

### Railway / Heroku
Both read the included `Procfile` (`web: node server.js`). Push the repo,
set `NODE_ENV=production`, deploy.

### Docker
```bash
docker compose up --build
# → http://localhost:3000
```
or manually:
```bash
docker build -t urlguard .
docker run -p 3000:3000 -v urlguard-data:/app/data urlguard
```

### Plain VM / VPS
```bash
git clone <your-fork-url>
cd urlguard
npm install --omit=dev
NODE_ENV=production PORT=3000 node server.js
# put behind nginx/Caddy + a process manager like pm2 or systemd
```

## Pushing to GitHub

```bash
git init
git add .
git commit -m "Initial commit: URLGuard full-stack app"
git branch -M main
git remote add origin https://github.com/<your-username>/urlguard.git
git push -u origin main
```
`.gitignore` already excludes `node_modules/`, `.env`, and the runtime
`data/history.json`, so only source files get committed.

## Notes & limitations

- This is a **heuristic** detector, not a substitute for a real threat-intel
  service (no live blocklists, WHOIS lookups, or certificate-transparency
  checks). Treat scores as a signal, not a verdict.
- The scoring weights and keyword/brand lists live in `src/analyzer.js` —
  tune them for your use case.
- `data/history.json` is a simple flat-file store meant for small/demo
  deployments; swap `src/store.js` for a real database if you need
  concurrent-write safety at scale.
