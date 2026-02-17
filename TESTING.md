# GearNest Automated Tests

## One-time setup

```bash
cd "/Users/raven/Documents/tech-tracker"
npm install
npm run test:install
```

## Run smoke tests locally

```bash
npm test
```

This starts a local static server at `http://127.0.0.1:4173` automatically and runs Playwright smoke tests.

## Run against deployed URL

```bash
BASE_URL="https://gearnest.pages.dev" npm test
```

## Useful commands

```bash
npm run test:headed
npm run test:report
```
