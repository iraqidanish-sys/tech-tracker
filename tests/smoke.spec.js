const { test, expect } = require('@playwright/test');
const { buildSnapshot, mockCloudflareApis } = require('./support/mock-cloudflare');

test.describe('GearNest smoke suite', () => {
  test('loads dashboard shell for authenticated user', async ({ page }) => {
    await mockCloudflareApis(page, {
      snapshot: buildSnapshot(),
      picture: 'http://127.0.0.1:4173/icons/icon-192.png'
    });

    await page.goto('/');

    await expect(page.locator('#loadingScreen')).toBeHidden();
    await expect(page.locator('#mainApp')).toBeVisible();
    await expect(page.locator('#dashboard.section.active')).toBeVisible();
    await expect(page.locator('#dashboard h1', { hasText: 'Dashboard' })).toBeVisible();
    await expect(page.locator('#dash-total-games')).toBeVisible();
    await expect(page.locator('#userAvatar img')).toBeVisible();
    await expect(page.locator('#userAvatar img')).toHaveAttribute('src', /icon-192\.png/);
  });

  test('renders Metacritic score chip and score detail link for games', async ({ page }) => {
    const snapshot = buildSnapshot({
      data: {
        games: [
          {
            firestoreId: 'gm_test_elden',
            title: 'Elden Ring',
            platform: 'PlayStation 5',
            genre: 'RPG',
            condition: 'New',
            buyPrice: 3999,
            buyDate: '2025-01-01',
            sellPrice: null,
            sellDate: null,
            status: 'owned',
            notes: '',
            metacriticScore: '96',
            metacriticUrl: 'https://www.metacritic.com/game/elden-ring/',
            imageUrl: '',
            timestamp: 1735689600000
          }
        ]
      }
    });

    await mockCloudflareApis(page, { snapshot });
    await page.goto('/');

    await page.evaluate(() => window.showSection('games'));
    const card = page.locator('#games-list .item-card').first();
    await expect(card).toBeVisible();

    const chip = card.locator('.metacritic-chip').first();
    await expect(chip).toContainText('MC 96');
    await expect(chip).toHaveAttribute('href', /metacritic\.com/);

    await card.click();
    await expect(card).toContainText('Metacritic');
    await expect(card).toContainText('MC 96');
    await expect(card).not.toContainText('Open link');
  });

  test('quick fill catalog can populate game fields and reset them', async ({ page }) => {
    const snapshot = buildSnapshot({
      settings: {
        gameMetadataCatalog: [
          {
            title: 'Elden Ring',
            platform: 'PlayStation 5',
            genre: 'RPG',
            metacriticScore: '96',
            metacriticUrl: 'https://www.metacritic.com/game/elden-ring/',
            imageUrl: 'https://example.com/elden-ring-cover.jpg'
          },
          {
            title: 'Spider-Man 2',
            platform: 'PlayStation 5',
            genre: 'Action',
            metacriticScore: '90',
            metacriticUrl: 'https://www.metacritic.com/game/marvels-spider-man-2/',
            imageUrl: 'https://example.com/spiderman2-cover.jpg'
          }
        ]
      }
    });

    await mockCloudflareApis(page, { snapshot });
    await page.goto('/');

    await page.evaluate(() => window.showSection('games'));
    await page.locator('[data-toggle="games-add-wrapper"]').click();
    await expect(page.locator('#games-add-wrapper')).toHaveClass(/open/);

    const searchInput = page.locator('#gm-catalog-search');
    await searchInput.click();
    await searchInput.fill('Elden');

    const result = page.locator('#gm-catalog-results .game-catalog-result', { hasText: 'Elden Ring' }).first();
    await expect(result).toBeVisible();
    await result.click();

    await expect(page.locator('#gm-title')).toHaveValue('Elden Ring');
    await expect(page.locator('#gm-metacritic-score')).toHaveValue('96');
    await expect(page.locator('#gm-metacritic-url')).toHaveValue(/metacritic\.com/);

    await page.locator('#gm-catalog-search-wrap button', { hasText: 'Reset' }).click();

    await expect(page.locator('#gm-title')).toHaveValue('');
    await expect(page.locator('#gm-metacritic-score')).toHaveValue('');
    await expect(page.locator('#gm-metacritic-url')).toHaveValue('');
  });
});
