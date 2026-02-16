import { getAccessEmail, json, normalizeEmail } from './_shared.js';

export async function onRequest({ request, env }) {
  const email = normalizeEmail(getAccessEmail(request, env));

  if (!email) {
    return json(
      {
        ok: false,
        error: 'missing_access_identity',
        message: 'Cloudflare Access identity header not found. Protect /api/* in Zero Trust.'
      },
      401
    );
  }

  return json({
    ok: true,
    user: {
      email
    }
  });
}
