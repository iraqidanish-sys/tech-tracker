import {
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
  upsertSnapshotByEmail
} from './_shared.js';

function unauthorized() {
  return json(
    {
      ok: false,
      error: 'missing_access_identity',
      message: 'Cloudflare Access identity header not found. Protect /api/* in Zero Trust.'
    },
    401
  );
}

export async function onRequest({ request, env }) {
  const method = request.method.toUpperCase();
  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  const email = normalizeEmail(getAccessEmail(request, env));
  if (!email) return unauthorized();

  const db = ensureDb(env);

  if (method === 'GET') {
    const stored = await readSnapshotByEmail(db, email);
    const appConfig = await readAppConfig(db);

    const snapshot = stored ? stored.snapshot : { ...DEFAULT_SNAPSHOT };
    snapshot.user.email = email;
    snapshot.settings = {
      ...snapshot.settings,
      ...appConfig.config,
      gadgetCategories: Array.isArray(appConfig.config.gadgetCategories) ? appConfig.config.gadgetCategories : snapshot.settings.gadgetCategories,
      gamePlatforms: Array.isArray(appConfig.config.gamePlatforms) ? appConfig.config.gamePlatforms : snapshot.settings.gamePlatforms,
      gameGenres: Array.isArray(appConfig.config.gameGenres) ? appConfig.config.gameGenres : snapshot.settings.gameGenres,
      digitalTypes: Array.isArray(appConfig.config.digitalTypes) ? appConfig.config.digitalTypes : snapshot.settings.digitalTypes,
      customIcons: Array.isArray(appConfig.config.customIcons) ? appConfig.config.customIcons : snapshot.settings.customIcons,
      gameMetadataCatalog: Array.isArray(appConfig.config.gameMetadataCatalog) ? appConfig.config.gameMetadataCatalog : snapshot.settings.gameMetadataCatalog
    };

    return json({
      ok: true,
      backend: 'cloudflare-d1',
      source: stored?.source || 'default',
      updatedAt: stored?.updatedAt || '',
      snapshot
    });
  }

  if (method === 'PUT' || method === 'POST') {
    const body = await parseJsonBody(request);
    if (!body || typeof body !== 'object') {
      return json({ ok: false, error: 'invalid_json' }, 400);
    }

    const incoming = body.snapshot && typeof body.snapshot === 'object' ? body.snapshot : body;
    const normalized = normalizeSnapshot(incoming);
    normalized.user.email = email;

    const stored = await upsertSnapshotByEmail(db, email, normalized, body.source || 'migration');

    const counts = {
      gadgets: Array.isArray(stored.data?.gadgets) ? stored.data.gadgets.length : 0,
      games: Array.isArray(stored.data?.games) ? stored.data.games.length : 0,
      digitalPurchases: Array.isArray(stored.data?.digitalPurchases) ? stored.data.digitalPurchases.length : 0
    };

    const includeAppConfig = body.includeAppConfig === true;
    if (includeAppConfig && isAdminEmail(email, env)) {
      const appConfigPayload = {
        gadgetCategories: Array.isArray(stored.settings?.gadgetCategories) ? stored.settings.gadgetCategories : [],
        gamePlatforms: Array.isArray(stored.settings?.gamePlatforms) ? stored.settings.gamePlatforms : [],
        gameGenres: Array.isArray(stored.settings?.gameGenres) ? stored.settings.gameGenres : [],
        digitalTypes: Array.isArray(stored.settings?.digitalTypes) ? stored.settings.digitalTypes : [],
        customIcons: Array.isArray(stored.settings?.customIcons) ? stored.settings.customIcons : [],
        gameMetadataCatalog: Array.isArray(stored.settings?.gameMetadataCatalog) ? stored.settings.gameMetadataCatalog : []
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
        .bind(JSON.stringify(appConfigPayload), email)
        .run();
    }

    return json({
      ok: true,
      backend: 'cloudflare-d1',
      message: 'Snapshot stored successfully.',
      counts
    });
  }

  return json({ ok: false, error: 'method_not_allowed' }, 405);
}
