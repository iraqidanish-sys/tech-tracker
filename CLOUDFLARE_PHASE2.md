# GearNest Phase 2 (Preserve Existing Firebase Data)

This phase adds Cloudflare D1 APIs and migration tooling while keeping your current app behavior stable.

## What this phase adds
- D1 schema for user snapshots and app config.
- Pages Functions API:
  - `GET /api/v1/me`
  - `GET/PUT /api/v1/snapshot`
  - `GET/PUT /api/v1/app-config`
- Admin migration tools in UI:
  - Download full backup JSON
  - Upload current in-memory data to Cloudflare
  - Upload backup JSON file to Cloudflare

## 1) Create D1 database
Run once:

```bash
cd "/Users/raven/Documents/tech-tracker"
npx wrangler d1 create gearnest-db
```

Copy the returned `database_id`.

## 2) D1 binding config
This repo already includes `wrangler.jsonc` with:
- binding: `GEARNEST_DB`
- database: `gearnest-db`
- database id: `ca605462-44f6-4cc2-9174-a332cae003b8`

If you prefer dashboard setup, use:
1. `Workers & Pages` -> `gearnest` -> `Settings` -> `Functions` -> `D1 bindings`.
2. Add binding `GEARNEST_DB` -> `gearnest-db`.

## 3) Apply schema
Use the database name returned by step 1.

```bash
cd "/Users/raven/Documents/tech-tracker"
npx wrangler d1 execute gearnest-db --remote --file ./cloudflare/d1/001_init.sql
```

## 4) Admin emails for app-config writes
`wrangler.jsonc` sets:
- `ADMIN_EMAILS=iraqidanish@gmail.com`

If you override vars in Dashboard, keep this value there too.

## 5) Protect API routes with Cloudflare Access
Zero Trust -> Access -> Applications -> Add `Self-hosted` app:
- Hostname: `gearnest.pages.dev`
- Path: `/api/*`
- Policy: `Allow` email(s) you trust.

Without this, API returns `missing_access_identity`.

## 6) Deploy
```bash
cd "/Users/raven/Documents/tech-tracker"
npx wrangler pages deploy . --project-name gearnest --branch main
```

## 7) Migrate data from Admin panel
1. Open `https://gearnest.pages.dev/admin`.
2. In `Cloudflare Phase 2 Migration`:
   - `Download Backup JSON` (safe backup copy)
   - `Upload Current Data` (writes current loaded data to D1)
   - or `Upload Backup File` (restore from JSON)

## Notes
- This phase preserves your Firebase data via migration snapshot uploads.
- Runtime cutover (reading/writing app directly from Cloudflare API only) is the next step.
