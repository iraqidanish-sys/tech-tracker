# GearNest Cloudflare Ops Runbook

## 1) Verify live deployment
```bash
cd "/Users/raven/Documents/tech-tracker"
npx wrangler pages deploy . --project-name gearnest
```

## 2) Verify current user snapshot in D1
```bash
cd "/Users/raven/Documents/tech-tracker"
npx wrangler d1 execute gearnest-db --remote --command "SELECT email, source, updated_at, length(payload_json) AS payload_size FROM user_snapshots WHERE email='iraqidanish@gmail.com' ORDER BY updated_at DESC LIMIT 1;"
```

## 3) Verify Access identity endpoint
Open in browser while signed in:
- `/api/v1/me`

Expected:
```json
{"ok":true,"user":{"email":"iraqidanish@gmail.com"}}
```

## 4) Backup procedure
1. Open `/admin`
2. Use:
   - `Download Backup JSON`
   - `Upload Current Data` (writes latest local state to D1)
3. Store backup JSON in at least one external location.

## 5) Restore procedure
1. Open `/admin`
2. Use `Upload Backup File`
3. Verify with D1 query from step 2.

## 6) Common checks when data looks stale
1. Hard refresh browser.
2. Confirm `_headers` sent no-cache for:
   - `/assets/app.module.js`
   - `/assets/app.ui.js`
   - `/assets/pwa-install.js`
3. Re-run step 2 query and confirm `updated_at` advances after save.

## 7) Admin access path
- Admin route: `/admin`
- If it fails, verify Cloudflare Zero Trust policy covers:
  - `gearnest.pages.dev/admin*`
  - `gearnest.pages.dev/api/*`
