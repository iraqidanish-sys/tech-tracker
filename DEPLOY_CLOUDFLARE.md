# Deploy GearNest to Cloudflare Pages

## 1) Push latest code to GitHub
Run from `/Users/raven/Documents/tech-tracker`:

```bash
git add .
git commit -m "Split app assets and add Cloudflare Pages config"
git push origin main
```

## 2) Create a Cloudflare Pages project
1. Open Cloudflare Dashboard -> Workers & Pages -> Create -> Pages -> Connect to Git.
2. Select repository: `iraqidanish-sys/tech-tracker`.
3. Branch: `main`.
4. Build settings:
   - Framework preset: `None`
   - Build command: *(leave empty)*
   - Build output directory: `/`

## 3) Custom domain (optional)
1. In the new Pages project, open `Custom domains`.
2. Add your domain and follow DNS prompts.

## 4) Verify PWA behavior
After deploy, open site once and check:
- Service worker registers without errors.
- Install flow appears in supported browsers.
- App works offline after first load.

## Notes
- `_headers` enables cache and security headers.
- `_redirects` keeps SPA routes working (fallback to `index.html`).
- Because static asset filenames are not hashed yet, cache durations are conservative.
