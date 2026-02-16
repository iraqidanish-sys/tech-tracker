import {
  ensureDb,
  getAccessEmail,
  isAdminEmail,
  json,
  normalizeEmail,
  parseJsonBody,
  readAppConfig,
  upsertAppConfig
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

function forbidden() {
  return json(
    {
      ok: false,
      error: 'admin_required',
      message: 'Admin access required.'
    },
    403
  );
}

export async function onRequest({ request, env }) {
  const method = request.method.toUpperCase();
  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  const email = normalizeEmail(getAccessEmail(request, env));
  if (!email) return unauthorized();

  const db = ensureDb(env);

  if (method === 'GET') {
    const result = await readAppConfig(db);
    return json({
      ok: true,
      config: result.config,
      updatedBy: result.updatedBy,
      updatedAt: result.updatedAt
    });
  }

  if (method === 'PUT' || method === 'POST') {
    if (!isAdminEmail(email, env)) return forbidden();

    const body = await parseJsonBody(request);
    if (!body || typeof body !== 'object') {
      return json({ ok: false, error: 'invalid_json' }, 400);
    }

    const config = body.config && typeof body.config === 'object' ? body.config : body;
    const stored = await upsertAppConfig(db, config, email);

    return json({
      ok: true,
      message: 'App config updated.',
      config: stored
    });
  }

  return json({ ok: false, error: 'method_not_allowed' }, 405);
}
