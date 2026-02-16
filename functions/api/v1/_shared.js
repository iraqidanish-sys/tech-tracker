const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'CDN-Cache-Control': 'no-store'
};

const DEFAULT_SNAPSHOT = {
  version: 1,
  source: 'cloudflare',
  exportedAt: '',
  user: {
    uid: '',
    email: ''
  },
  data: {
    gadgets: [],
    games: [],
    digitalPurchases: []
  },
  settings: {
    currency: '₹',
    gadgetCategories: [],
    gamePlatforms: [],
    gameGenres: [],
    digitalTypes: [],
    customIcons: [],
    gameMetadataCatalog: []
  }
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...headers }
  });
}

function normalizeEmail(input = '') {
  return String(input || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getAccessEmail(request, env = {}) {
  const cfCandidates = [
    request.headers.get('cf-access-authenticated-user-email'),
    request.headers.get('CF-Access-Authenticated-User-Email')
  ];

  for (const raw of cfCandidates) {
    const email = normalizeEmail(raw || '');
    if (isValidEmail(email)) return email;
  }

  const allowDevHeader = String(env.ALLOW_DEV_EMAIL_HEADER || '').toLowerCase() === 'true';
  const url = new URL(request.url);
  const isLocalHost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (!allowDevHeader && !isLocalHost) {
    return '';
  }

  const devHeaderEmail = normalizeEmail(request.headers.get('x-authenticated-user-email') || '');
  if (isValidEmail(devHeaderEmail)) return devHeaderEmail;
  return '';
}

function getAdminEmails(env) {
  const raw = String(env.ADMIN_EMAILS || '').trim();
  if (!raw) return [];
  return raw
    .split(',')
    .map((entry) => normalizeEmail(entry))
    .filter(Boolean);
}

function isAdminEmail(email, env) {
  const clean = normalizeEmail(email);
  if (!clean) return false;
  return getAdminEmails(env).includes(clean);
}

function ensureDb(env) {
  if (!env || !env.GEARNEST_DB) {
    throw new Error('Missing D1 binding: GEARNEST_DB');
  }
  return env.GEARNEST_DB;
}

function arrayOrEmpty(value) {
  return Array.isArray(value) ? value : [];
}

function objectOrEmpty(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function normalizeSnapshot(input) {
  const root = objectOrEmpty(input);
  const user = objectOrEmpty(root.user);
  const data = objectOrEmpty(root.data);
  const settings = objectOrEmpty(root.settings);

  const snapshot = {
    ...DEFAULT_SNAPSHOT,
    ...root,
    user: {
      ...DEFAULT_SNAPSHOT.user,
      ...user
    },
    data: {
      ...DEFAULT_SNAPSHOT.data,
      ...data,
      gadgets: arrayOrEmpty(data.gadgets),
      games: arrayOrEmpty(data.games),
      digitalPurchases: arrayOrEmpty(data.digitalPurchases)
    },
    settings: {
      ...DEFAULT_SNAPSHOT.settings,
      ...settings,
      gadgetCategories: arrayOrEmpty(settings.gadgetCategories),
      gamePlatforms: arrayOrEmpty(settings.gamePlatforms),
      gameGenres: arrayOrEmpty(settings.gameGenres),
      digitalTypes: arrayOrEmpty(settings.digitalTypes),
      customIcons: arrayOrEmpty(settings.customIcons),
      gameMetadataCatalog: arrayOrEmpty(settings.gameMetadataCatalog)
    }
  };

  if (!snapshot.exportedAt) {
    snapshot.exportedAt = new Date().toISOString();
  }

  return snapshot;
}

async function parseJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function readSnapshotByEmail(db, email) {
  const row = await db
    .prepare('SELECT payload_json, source, version, updated_at FROM user_snapshots WHERE email = ?')
    .bind(email)
    .first();

  if (!row) return null;

  let parsed = null;
  try {
    parsed = JSON.parse(row.payload_json);
  } catch {
    parsed = null;
  }

  return {
    snapshot: normalizeSnapshot(parsed || {}),
    source: row.source,
    version: Number(row.version || 1),
    updatedAt: row.updated_at || ''
  };
}

async function upsertSnapshotByEmail(db, email, snapshot, source = 'cloudflare-api') {
  const normalized = normalizeSnapshot(snapshot);
  const payload = JSON.stringify(normalized);

  await db
    .prepare(
      `INSERT INTO user_snapshots (email, payload_json, source, version, updated_at)
       VALUES (?, ?, ?, ?, datetime('now'))
       ON CONFLICT(email) DO UPDATE SET
         payload_json = excluded.payload_json,
         source = excluded.source,
         version = excluded.version,
         updated_at = datetime('now')`
    )
    .bind(email, payload, String(source || 'cloudflare-api'), Number(normalized.version || 1))
    .run();

  return normalized;
}

async function readAppConfig(db) {
  const row = await db
    .prepare('SELECT payload_json, updated_by, updated_at FROM app_config WHERE config_key = ?')
    .bind('app-config')
    .first();

  if (!row) {
    return {
      config: {
        gadgetCategories: [],
        gamePlatforms: [],
        gameGenres: [],
        digitalTypes: [],
        customIcons: [],
        gameMetadataCatalog: []
      },
      updatedBy: '',
      updatedAt: ''
    };
  }

  let parsed = {};
  try {
    parsed = JSON.parse(row.payload_json || '{}');
  } catch {
    parsed = {};
  }

  const clean = {
    gadgetCategories: arrayOrEmpty(parsed.gadgetCategories),
    gamePlatforms: arrayOrEmpty(parsed.gamePlatforms),
    gameGenres: arrayOrEmpty(parsed.gameGenres),
    digitalTypes: arrayOrEmpty(parsed.digitalTypes),
    customIcons: arrayOrEmpty(parsed.customIcons),
    gameMetadataCatalog: arrayOrEmpty(parsed.gameMetadataCatalog)
  };

  return {
    config: clean,
    updatedBy: row.updated_by || '',
    updatedAt: row.updated_at || ''
  };
}

async function upsertAppConfig(db, config, updatedBy = '') {
  const payload = {
    gadgetCategories: arrayOrEmpty(config?.gadgetCategories),
    gamePlatforms: arrayOrEmpty(config?.gamePlatforms),
    gameGenres: arrayOrEmpty(config?.gameGenres),
    digitalTypes: arrayOrEmpty(config?.digitalTypes),
    customIcons: arrayOrEmpty(config?.customIcons),
    gameMetadataCatalog: arrayOrEmpty(config?.gameMetadataCatalog)
  };

  await db
    .prepare(
      `INSERT INTO app_config (config_key, payload_json, updated_by, updated_at)
       VALUES ('app-config', ?, ?, datetime('now'))
       ON CONFLICT(config_key) DO UPDATE SET
         payload_json = excluded.payload_json,
         updated_by = excluded.updated_by,
         updated_at = datetime('now')`
    )
    .bind(JSON.stringify(payload), normalizeEmail(updatedBy))
    .run();

  return payload;
}

export {
  DEFAULT_SNAPSHOT,
  ensureDb,
  getAccessEmail,
  isAdminEmail,
  json,
  normalizeEmail,
  normalizeSnapshot,
  parseJsonBody,
  readAppConfig,
  readSnapshotByEmail,
  upsertAppConfig,
  upsertSnapshotByEmail
};
