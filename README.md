# bashar-teacher-server

This is the backend for the Bashar Teacher tuition management system.

## Required environment variables

Create a `.env` file at the project root (do NOT commit it). You can copy `.env.example` and fill values.

- `MONGO_USER` / `MONGO_PASS` — MongoDB credentials
- `JWT_SECRET` — strong random secret for signing JWTs
- `JWT_EXPIRE` — token expiration (e.g. `7d`)
- `PORT` — server port (defaults to 5000)
- `CLIENT_URL` — frontend base URL (for Stripe redirects)
- `FIREBASE_SERVICE_KEY` — base64 encoded Firebase service account JSON (or use secret manager)
- `STRIPE_SECRET_KEY` — Stripe secret key for payments

## Security notes

- Do NOT commit `.env` or service account JSON files to the repository. If any secrets have been committed previously, rotate them immediately.
- Remove `bashar-teacher-firebase-adminsdk.json` from the repo and use the base64 `FIREBASE_SERVICE_KEY` or a secrets manager for deployments.

## Quick start (local)

1. Copy `.env.example` to `.env` and fill secrets.
2. Install dependencies: `npm install`
3. Run server: `node index.js`

## Troubleshooting

- If Stripe fails, ensure `STRIPE_SECRET_KEY` is set.
- If Firebase admin errors appear, verify `FIREBASE_SERVICE_KEY` is a valid base64 encoded JSON.
