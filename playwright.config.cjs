const { defineConfig } = require('@playwright/test');

const localBaseURL = 'http://127.0.0.1:4173';
const baseURL = process.env.BASE_URL || localBaseURL;

module.exports = defineConfig({
  testDir: './tests',
  timeout: 45 * 1000,
  expect: {
    timeout: 10 * 1000
  },
  fullyParallel: true,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure'
  },
  webServer: process.env.BASE_URL
    ? undefined
    : {
        command: 'python3 -m http.server 4173 --bind 127.0.0.1',
        port: 4173,
        reuseExistingServer: !process.env.CI,
        timeout: 120 * 1000
      }
});
