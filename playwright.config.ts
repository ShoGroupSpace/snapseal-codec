import { defineConfig } from '@playwright/test';
export default defineConfig({ testDir: './tests/browser', timeout: 180_000, workers: 1, retries: 0, use: { browserName: 'chromium', headless: true }, reporter: 'list' });
