# Sealero — Server & Web

Sealero is a zero-knowledge, offline-first password manager. Your vault is encrypted on your device before it ever leaves it; the server stores ciphertext only and can never read your passwords.

This repository holds the Sealero backend API and the React web client in a single package. The API (Hono + Node.js + TypeScript) and the web vault and admin console (React + TypeScript + Vite) deploy together from this repository. The Flutter Android client lives in the separate `sealero-app` repository.

Product and architecture baseline: [Sealero Architecture](https://docero.gitbook.io/docero/sealero/sealero-architecture) (System Design v1.48 / PRD v4.44). The technical design follows the [System Design](https://docero.gitbook.io/docero/sealero/sealero-system-design.md); the product scope follows the [PRD](https://docero.gitbook.io/docero/sealero/sealero-prd.md).

## What this repository contains

- **API** (`api/`) — Hono service with login, vault, vault-key, devices, admin, OAuth and MCP routes. Authentication uses Argon2id password hashing and RS256 JWTs (15-minute access tokens, 30-day refresh tokens). Vault data is ciphertext only; the server never sees a master password, KEK or DEK.
- **Web** (`src/`) — React vault and admin console. The web client is an online thin client: it decrypts in memory and holds no local database. It includes login, unlock, vault list/detail, password generator, settings and sync, MCP confirmation page, cloud backup / export, and the admin console.
- **Single package** — one `package.json` at the repository root. `api/` is the backend source and `src/` is the frontend source, side by side. There is no pnpm workspace (no workspace packages); `pnpm-workspace.yaml` only carries `allowBuilds`. There is no separate `web/` directory.

## Security model

Two passwords, kept strictly separate:

- **Login password** — authenticates you to the server (Argon2id hash, recoverable by email).
- **Master password** — unlocks your vault only. It never leaves your device and cannot be recovered, except with the 24-word BIP39 recovery key you back up at registration.

A random 256-bit data-encryption key (DEK) encrypts all vault items with AES-256-GCM. Your master password derives a key-encryption key (KEK) with Argon2id; the KEK wraps the DEK. Changing the master password only re-wraps the DEK.

## Tech stack

- Backend: Hono, Node.js, TypeScript, Argon2id, RS256 JWT, Neon Postgres (serverless driver)
- Frontend: React 19, TypeScript, Vite, Tailwind CSS, i18next (six languages)
- Tests: Vitest (API), Node's built-in test runner (web)

## Project structure

- `api/` — Hono API, routes, auth, vault, devices, admin, database schema (incl. `oauth/` and MCP routes)
- `src/` — React web client (pages, components, features, client, hooks, locales; incl. MCP confirmation page and cloud backup)
- `public/` — static assets (favicon)
- `tests/` — web tests (Node test runner)
- `api/test/` — API tests (Vitest)
- `vercel.json` — Vercel build and routing (API under `/v1/*`, frontend as static files)

## Local development

Requires Node.js and pnpm (this repository declares `pnpm@11.25.0`).

```bash
pnpm install
```

Run the API and the web client in two terminals:

```bash
pnpm dev:api
pnpm dev:web
```

The API listens on `http://localhost:3000` (check `GET /v1/health`). The web dev server proxies same-origin `/v1` calls to the API (see `vite-proxy.ts`; target defaults to `http://localhost:3000`, overridable with `VITE_API_PROXY_TARGET`).

Local admin bootstrap (development only, never in deployment): the local
PGlite database starts empty (in-memory, wiped on restart) and registration grants no roles, so seed the
first admin with environment variables when starting the API:

```bash
SEALERO_LOCAL_DEV_ADMIN_EMAIL=admin@local.test \
SEALERO_LOCAL_DEV_ADMIN_PASSWORD='at-least-8-chars' \
pnpm dev:api
```

The seed creates the account (already email-verified) and grants it
`super_admin` + `admin`; an existing account with the same email keeps its
own password but is still granted `super_admin` + `admin`. Without both variables no admin is created, but the `roles`
rows are still seeded so `make-admin` can work once an admin exists; setting only one of the two variables fails startup — they must be set together.

## Commands

```bash
pnpm typecheck        # API + web typechecks
pnpm test             # API (Vitest) + web (Node test runner)
pnpm build            # API (tsc) + web (tsc + Vite build)
pnpm lint             # web ESLint
pnpm preview          # preview the production web build
```

Provide the official-cloud API address (`VITE_API_BASE_URL`), the cloud-backup OAuth client IDs (`VITE_GOOGLE_DRIVE_CLIENT_ID`, `VITE_DROPBOX_CLIENT_ID`) and the OAuth redirect override (`VITE_OAUTH_REDIRECT_URI`) at web build time via `import.meta.env` if needed; the published privacy-policy version comes from the release manifest (`release.json`, see System Design §8). Release signing for the Android client is configured in the `sealero-app` repository.

## Deployment

The repository deploys to Vercel as one deployment: the API runs as a serverless function (`api/index.ts`, routed under `/v1/*`) and the web client is served as static files from `dist/`. See `vercel.json` for the build command, output directory and rewrites.

The Vercel entry point serves `GET /v1/health` and returns `503 auth_runtime_unavailable` for business routes until a real durable store and notification provider are injected. Do not substitute the local PGlite store or a fake notification provider in deployment.

## Current status

The API implements auth (login, recovery, consent, devices), vault and vault-key, and the admin console routes, with tests. The web client implements login, unlock, vault, password generator, settings and the admin console. Deployment wiring to a real database and end-to-end verification are still in progress. The architecture documents describe the V1 design baseline; they are not a claim that every feature is delivered.

## Branch convention

`dev` is for development, `main` is the stable branch. Keep the existing history; do not rewrite history and do not force-push.
