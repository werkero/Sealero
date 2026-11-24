# Sealero

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-6-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-green?logo=node.js&logoColor=white)](https://nodejs.org/)
[![Hono](https://img.shields.io/badge/Hono-4-orange?logo=hono&logoColor=white)](https://hono.dev/)
[![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?logo=vite&logoColor=white)](https://vite.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)

Sealero is a zero-knowledge, offline-first password manager. Your vault is encrypted on your device before it ever leaves it; the server stores ciphertext only and can never read your passwords.

This repository holds the open-source server: the backend API (Hono + Node.js) and the React web client, in a single package. The Flutter Android client is closed-source and lives in a separate private repository.

## Security model

- **Login password** — authenticates you to the server (Argon2id hash, recoverable by email).
- **Master password** — unlocks your vault only. It never leaves your device and cannot be recovered, except with the 24-word BIP39 recovery key you back up at registration.
- A random 256-bit DEK encrypts vault items with AES-256-GCM. Your master password derives a KEK with Argon2id; the KEK wraps the DEK.

## Quick start

Requires Node.js and pnpm.

```bash
pnpm install
pnpm dev:api    # API on http://localhost:3000
pnpm dev:web    # web dev server (proxies /v1 to the API)
```

## Commands

```bash
pnpm typecheck
pnpm test
pnpm build
```

## License

AGPLv3. See [LICENSE](LICENSE).
