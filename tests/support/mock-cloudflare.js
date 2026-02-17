function buildSnapshot(overrides = {}) {
  const snapshot = {
    data: {
      gadgets: [],
      games: [],
      digitalPurchases: []
    },
    settings: {
      currency: '₹',
      gadgetCategories: [
        'Phone',
        'Laptop',
        'Smartwatch',
        'Audio',
        'Camera',
        'Gaming',
        'Accessories',
        'Storage',
        'Monitor',
        'Keyboard/Mouse',
        'Chargers',
        'Other'
      ],
      gamePlatforms: [
        'PlayStation 5',
        'PlayStation 4',
        'Xbox Series X/S',
        'Nintendo Switch',
        'PC',
        'Other'
      ],
      gameGenres: [
        'Action',
        'Adventure',
        'RPG',
        'Sports',
        'Racing',
        'Puzzle',
        'Strategy',
        'Horror',
        'Simulation',
        'Shooter',
        'Fighting',
        'Music',
        'Platform'
      ],
      digitalTypes: [
        'Game Subscription',
        'Streaming Service',
        'Cloud Storage',
        'Music Subscription',
        'E-Book/Audiobook',
        'Productivity Tool',
        'Online Course',
        'Other'
      ],
      customIcons: [],
      gameMetadataCatalog: []
    }
  };

  if (overrides && typeof overrides === 'object') {
    if (overrides.data && typeof overrides.data === 'object') {
      snapshot.data = { ...snapshot.data, ...overrides.data };
    }
    if (overrides.settings && typeof overrides.settings === 'object') {
      snapshot.settings = { ...snapshot.settings, ...overrides.settings };
    }
  }

  return snapshot;
}

async function mockCloudflareApis(page, options = {}) {
  const email = String(options.email || 'qa@gearnest.dev').trim();
  const name = String(options.name || 'QA User').trim();
  const picture = String(options.picture || '').trim();
  let snapshot = options.snapshot || buildSnapshot();

  const json = (payload) => ({
    status: 200,
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  await page.route('**/api/v1/me**', async (route) => {
    await route.fulfill(
      json({
        ok: true,
        user: {
          email,
          name,
          picture
        }
      })
    );
  });

  await page.route('**/api/v1/snapshot**', async (route) => {
    const request = route.request();
    const method = request.method().toUpperCase();

    if (method === 'GET') {
      await route.fulfill(
        json({
          ok: true,
          snapshot
        })
      );
      return;
    }

    if (method === 'POST') {
      try {
        const payload = JSON.parse(request.postData() || '{}');
        if (payload && payload.snapshot && typeof payload.snapshot === 'object') {
          snapshot = payload.snapshot;
        }
      } catch {
        // ignore parse errors in tests
      }

      const counts = {
        gadgets: Array.isArray(snapshot?.data?.gadgets) ? snapshot.data.gadgets.length : 0,
        games: Array.isArray(snapshot?.data?.games) ? snapshot.data.games.length : 0,
        digitalPurchases: Array.isArray(snapshot?.data?.digitalPurchases) ? snapshot.data.digitalPurchases.length : 0
      };

      await route.fulfill(
        json({
          ok: true,
          counts
        })
      );
      return;
    }

    await route.fulfill({
      status: 405,
      body: 'Method Not Allowed'
    });
  });
}

module.exports = {
  buildSnapshot,
  mockCloudflareApis
};
