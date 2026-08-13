# Phishing Reporter — Backend (API)

Standalone Express.js API and forensic worker for the Phishing Website Reporter platform.
Split out from the original monorepo (https://github.com/ekorangin/phising-website-reporter)
so it can be developed, run, and deployed independently from the frontend.

## Requirements

- Node.js v18+
- npm v9+
- Redis (used by BullMQ for the forensic job queue) — `REDIS_URL` in `.env`
- Playwright Chromium (for forensic screenshots)

## Setup

```bash
npm install
npx playwright install chromium
cp .env.example .env   # edit values as needed
npm run dev             # nodemon, http://localhost:5000
# or
npm start                # production
```

## Environment variables (`.env`)

| Variable      | Description                                                              | Default                        |
| ------------- | ------------------------------------------------------------------------- | ------------------------------- |
| `PORT`        | Port the API server listens on                                            | `5000`                          |
| `REDIS_URL`   | Redis connection string for the BullMQ worker queue                       | `redis://127.0.0.1:6379`        |
| `CORS_ORIGIN` | Comma-separated allowed origins for CORS. Leave empty to allow all (dev). | *(unset = all origins allowed)* |

When deploying the frontend separately (different domain), set `CORS_ORIGIN` to that
frontend's URL, e.g. `CORS_ORIGIN=https://reporter.example.com`.

## Project structure

```
phishing-reporter-backend/
├── src/
│   ├── index.js             # Express API server entrypoint & routes
│   ├── worker.js             # Playwright forensic & screenshot worker
│   ├── threat_dispatcher.js  # Multi-vector threat intelligence dispatcher
│   ├── mailer.js             # Registrar abuse email generator
│   ├── janitor.js            # Scheduled site death checker
│   └── db.js                 # SQLite database initialization
├── public/screenshots/       # Captured forensic screenshot output (.jpg)
├── .env.example
└── package.json
```

## API Reference

| Method   | Endpoint                      | Description                                                       |
| -------- | ------------------------------ | -------------------------------------------------------------------- |
| `POST`   | `/api/reports`                 | Submit a new suspicious URL report.                                  |
| `GET`    | `/api/reports/status?url=...`  | Check report status by URL.                                          |
| `GET`    | `/api/reports/pending`         | Retrieve all pending triage cases for the admin console.             |
| `POST`   | `/api/reports/:id/approve`     | Approve report & broadcast across threat intelligence channels.      |
| `POST`   | `/api/reports/:id/reject`      | Reject report.                                                       |
| `DELETE` | `/api/reports/pending`         | Delete all pending cases.                                            |
| `DELETE` | `/api/reports/:id`             | Delete a specific report by ID.                                      |
| `GET`    | `/api/brands?q=...`            | Retrieve brand suggestions autocomplete.                             |
| `POST`   | `/api/janitor/run`             | Manually trigger site availability verification check.               |

Screenshots are served statically at `/screenshots/<file>.jpg`.

## Deploying alongside a separately-hosted frontend

Point the frontend's `VITE_API_URL` environment variable to wherever this backend is
publicly reachable (e.g. `https://api.example.com`), and set this backend's
`CORS_ORIGIN` to the frontend's public URL.
