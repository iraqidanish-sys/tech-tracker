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

const ITEM_COLLECTION_MAP = Object.freeze({
  gadgets: 'gadgets',
  games: 'games',
  digitalPurchases: 'digitalPurchases'
});

const ITEM_COLLECTION_NAMES = Object.keys(ITEM_COLLECTION_MAP);

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

function normalizeCollectionName(input = '') {
  const clean = String(input || '').trim();
  if (!clean) return '';
  return ITEM_COLLECTION_MAP[clean] || '';
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

async function ensureUserItemsTable(db) {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS user_items (
         email TEXT NOT NULL,
         collection_name TEXT NOT NULL,
         item_id TEXT NOT NULL,
         payload_json TEXT NOT NULL,
         updated_at TEXT NOT NULL DEFAULT (datetime('now')),
         PRIMARY KEY (email, collection_name, item_id)
       )`
    )
    .run();

  await db
    .prepare(
      `CREATE INDEX IF NOT EXISTS idx_user_items_email_collection_updated
       ON user_items(email, collection_name, updated_at DESC)`
    )
    .run();
}

function normalizeItemPayload(raw = {}, fallbackId = '') {
  const source = objectOrEmpty(raw);
  const cleanId = String(source.firestoreId || fallbackId || '').trim();
  const payload = {
    ...source,
    firestoreId: cleanId
  };
  return payload;
}

async function readItemsByEmail(db, email, options = {}) {
  const collection = normalizeCollectionName(options.collection || '');
  const baseQuery = collection
    ? 'SELECT collection_name, item_id, payload_json, updated_at FROM user_items WHERE email = ? AND collection_name = ? ORDER BY updated_at DESC'
    : 'SELECT collection_name, item_id, payload_json, updated_at FROM user_items WHERE email = ? ORDER BY updated_at DESC';

  const stmt = collection
    ? db.prepare(baseQuery).bind(email, collection)
    : db.prepare(baseQuery).bind(email);

  const result = await stmt.all();
  const rows = Array.isArray(result?.results) ? result.results : [];
  const grouped = {
    gadgets: [],
    games: [],
    digitalPurchases: []
  };

  let latestUpdatedAt = '';
  for (const row of rows) {
    const rowCollection = normalizeCollectionName(row.collection_name || '');
    if (!rowCollection) continue;

    let parsed = {};
    try {
      parsed = JSON.parse(row.payload_json || '{}');
    } catch {
      parsed = {};
    }

    const cleanId = String(row.item_id || '').trim();
    if (!cleanId) continue;

    grouped[rowCollection].push(normalizeItemPayload(parsed, cleanId));
    if (!latestUpdatedAt && row.updated_at) {
      latestUpdatedAt = row.updated_at;
    }
  }

  const counts = {
    gadgets: grouped.gadgets.length,
    games: grouped.games.length,
    digitalPurchases: grouped.digitalPurchases.length
  };

  return {
    data: grouped,
    counts,
    totalCount: counts.gadgets + counts.games + counts.digitalPurchases,
    updatedAt: latestUpdatedAt
  };
}

async function upsertItemByEmail(db, email, collectionName, itemId, payload) {
  const collection = normalizeCollectionName(collectionName);
  const cleanItemId = String(itemId || '').trim();
  if (!collection) {
    throw new Error('Invalid collection name');
  }
  if (!cleanItemId) {
    throw new Error('Missing item id');
  }

  const normalizedPayload = normalizeItemPayload(payload, cleanItemId);
  await db
    .prepare(
      `INSERT INTO user_items (email, collection_name, item_id, payload_json, updated_at)
       VALUES (?, ?, ?, ?, datetime('now'))
       ON CONFLICT(email, collection_name, item_id) DO UPDATE SET
         payload_json = excluded.payload_json,
         updated_at = datetime('now')`
    )
    .bind(email, collection, cleanItemId, JSON.stringify(normalizedPayload))
    .run();

  return normalizedPayload;
}

async function upsertItemsByEmail(db, email, collectionName, items = []) {
  const collection = normalizeCollectionName(collectionName);
  if (!collection) {
    throw new Error('Invalid collection name');
  }

  const rows = Array.isArray(items) ? items : [];
  const saved = [];
  for (const row of rows) {
    const item = objectOrEmpty(row);
    const itemId = String(item.firestoreId || '').trim();
    if (!itemId) continue;
    const stored = await upsertItemByEmail(db, email, collection, itemId, item);
    saved.push(stored);
  }
  return saved;
}

async function deleteItemByEmail(db, email, collectionName, itemId) {
  const collection = normalizeCollectionName(collectionName);
  const cleanItemId = String(itemId || '').trim();
  if (!collection) {
    throw new Error('Invalid collection name');
  }
  if (!cleanItemId) {
    throw new Error('Missing item id');
  }

  await db
    .prepare('DELETE FROM user_items WHERE email = ? AND collection_name = ? AND item_id = ?')
    .bind(email, collection, cleanItemId)
    .run();
}

function extractSnapshotItems(snapshot, collectionName) {
  const collection = normalizeCollectionName(collectionName);
  if (!collection) return [];
  const root = objectOrEmpty(snapshot);
  const data = objectOrEmpty(root.data);
  const rows = arrayOrEmpty(data[collection]);
  return rows
    .map((row) => normalizeItemPayload(row, row && row.firestoreId ? row.firestoreId : ''))
    .filter((row) => String(row.firestoreId || '').trim());
}

async function migrateSnapshotItemsToTable(db, email, snapshot) {
  let inserted = 0;
  for (const collection of ITEM_COLLECTION_NAMES) {
    const items = extractSnapshotItems(snapshot, collection);
    if (items.length === 0) continue;
    const saved = await upsertItemsByEmail(db, email, collection, items);
    inserted += saved.length;
  }
  return inserted;
}

export {
  DEFAULT_SNAPSHOT,
  ITEM_COLLECTION_NAMES,
  deleteItemByEmail,
  ensureDb,
  ensureUserItemsTable,
  extractSnapshotItems,
  getAccessEmail,
  isAdminEmail,
  json,
  migrateSnapshotItemsToTable,
  normalizeCollectionName,
  normalizeEmail,
  normalizeItemPayload,
  normalizeSnapshot,
  parseJsonBody,
  readAppConfig,
  readItemsByEmail,
  readSnapshotByEmail,
  upsertItemByEmail,
  upsertItemsByEmail,
  upsertAppConfig,
  upsertSnapshotByEmail
};
