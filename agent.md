# Sealero Server / Web Agent Rules

## Source of truth
- V1 baseline: System Design v1.46 and PRD v4.44, both dated 2026-11-16.
- System Design is the technical source of truth. PRD defines product scope and behavior.
- Architecture: https://docero.gitbook.io/docero/sealero/sealero-architecture
- System Design: https://docero.gitbook.io/docero/sealero/sealero-system-design.md
- PRD: https://docero.gitbook.io/docero/sealero/sealero-prd.md
- Server schema: https://docero.gitbook.io/docero/sealero/schema.md
- OpenAPI reference: https://docero.gitbook.io/docero/sealero/openapi.md (human-readable derivative of System Design §5; §5 prevails).

## Repository boundary
- This repository contains Hono/Node.js/TypeScript API, React web vault, and React admin console, deployed together as described by the architecture.
- Keep backend under `api/`, web under `src/`, and database schema/migrations under `api/db/` or the exact layout finalized by the backend owner from the architecture. Single package: one root `package.json`, no workspace, no separate `web/` directory. Do not put Android/Flutter code here.
- The web vault is online-only, has no local vault database or sync queue, and keeps keys/plaintext in browser memory only.

## Security and behavior
- The server receives/stores encrypted vault payloads only; never send or store master passwords, KEK/DEK plaintext, item plaintext, or plaintext-derived content summaries.
- Follow System Design §§3, 5, 6, and 7 for schema, API contracts, version checks, tombstones, synchronization behavior, backup boundaries, and security controls. Do not invent or silently alter contracts.
- All authenticated requests perform the required per-request account/device revocation checks and ownership checks.
- Preserve stable documented error codes and 409/410 behavior. Never silently overwrite a conflict or revive a tombstoned item ID.
- Migrations are explicit, versioned, tested locally, and never run automatically at serverless startup.

## Work and approvals
- Work only in this fresh local repository: `/workspace/sealero-dev-20261122-0139/sealero-server`. Do not treat the previous `/workspace/sealero-work` files as a baseline; do not copy from them unless Tai explicitly asks.
- Validate changes with relevant tests, type checks, and local build; report exactly what was run.
- No Neon connection, production migration, push, deployment, or authoritative-document edit without Tai's explicit approval.
- If a source-document conflict or missing contract blocks implementation, stop that slice and raise the exact section and decision in the development group rather than guessing.
