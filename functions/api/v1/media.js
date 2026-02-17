import { getAccessEmail, json, normalizeEmail } from './_shared.js';

const MAX_UPLOAD_BYTES = 8 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 20000;

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

function noBucketConfigured() {
  return json(
    {
      ok: false,
      error: 'media_bucket_not_configured',
      message: 'R2 bucket binding GEARNEST_MEDIA is not configured yet.'
    },
    501
  );
}

function badRequest(message) {
  return json({ ok: false, error: 'bad_request', message }, 400);
}

function sanitizeMediaKey(input = '') {
  const raw = String(input || '').trim();
  if (!raw) return '';
  if (raw.includes('..') || raw.includes('\\')) return '';
  return raw.replace(/^\/+/, '');
}

function sanitizeEmailPath(input = '') {
  const clean = String(input || '').trim().toLowerCase();
  if (!clean) return 'anonymous';
  return clean.replace(/[^a-z0-9._-]/g, '_');
}

function inferExtension(contentType = '') {
  const normalized = String(contentType || '').toLowerCase().split(';')[0].trim();
  if (!normalized) return 'jpg';
  if (normalized === 'image/jpeg') return 'jpg';
  if (normalized === 'image/png') return 'png';
  if (normalized === 'image/webp') return 'webp';
  if (normalized === 'image/gif') return 'gif';
  if (normalized === 'image/avif') return 'avif';
  if (normalized === 'image/svg+xml') return 'svg';
  return 'jpg';
}

function isBlockedHostname(hostname = '') {
  const clean = String(hostname || '').trim().toLowerCase();
  if (!clean) return true;

  if (clean === 'localhost' || clean === '::1' || clean.endsWith('.localhost')) {
    return true;
  }

  if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) {
    const octets = clean.split('.').map((value) => Number(value));
    if (octets[0] === 10) return true;
    if (octets[0] === 127) return true;
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    if (octets[0] === 169 && octets[1] === 254) return true;
  }

  return false;
}

async function fetchWithTimeout(url, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal
    });
  } finally {
    clearTimeout(timer);
  }
}

function decodeDataUrlImage(dataUrl = '') {
  const raw = String(dataUrl || '').trim();
  const match = raw.match(/^data:(image\/[a-z0-9.+-]+);base64,([a-z0-9+/=]+)$/i);
  if (!match) {
    throw new Error('Unsupported data URL format.');
  }

  const mimeType = String(match[1] || '').toLowerCase();
  const base64Data = match[2] || '';
  const binary = atob(base64Data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return {
    bytes,
    contentType: mimeType
  };
}

function isAllowedImageType(contentType = '') {
  const clean = String(contentType || '').toLowerCase();
  return clean.startsWith('image/');
}

function buildMediaUrl(request, key, env) {
  const publicBase = String(env.PUBLIC_MEDIA_BASE_URL || '').trim().replace(/\/+$/, '');
  if (publicBase) {
    return `${publicBase}/${key}`;
  }
  const origin = new URL(request.url).origin;
  return `${origin}/api/v1/media?key=${encodeURIComponent(key)}`;
}

async function resolveUploadSource(source = '') {
  const raw = String(source || '').trim();
  if (!raw) {
    throw new Error('Missing source image.');
  }

  if (raw.startsWith('data:image/')) {
    return decodeDataUrlImage(raw);
  }

  let parsed = null;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error('Image source must be a valid URL or data URL.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP(S) image URLs are allowed.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Image URL cannot include credentials.');
  }
  if (isBlockedHostname(parsed.hostname)) {
    throw new Error('Image URL host is blocked.');
  }

  const response = await fetchWithTimeout(parsed.toString());
  if (!response.ok) {
    throw new Error(`Could not download image (${response.status}).`);
  }

  const contentType = String(response.headers.get('content-type') || '').toLowerCase().split(';')[0].trim();
  if (!isAllowedImageType(contentType)) {
    throw new Error('URL does not point to an image.');
  }

  const buffer = await response.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  return {
    bytes,
    contentType
  };
}

export async function onRequest({ request, env }) {
  const method = request.method.toUpperCase();
  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  const email = normalizeEmail(getAccessEmail(request, env));
  if (!email) return unauthorized();

  const bucket = env && env.GEARNEST_MEDIA ? env.GEARNEST_MEDIA : null;
  if (!bucket) return noBucketConfigured();

  if (method === 'GET') {
    const key = sanitizeMediaKey(new URL(request.url).searchParams.get('key') || '');
    if (!key) {
      return badRequest('Missing media key.');
    }

    const object = await bucket.get(key);
    if (!object) {
      return json({ ok: false, error: 'not_found', message: 'Media file not found.' }, 404);
    }

    const ownerEmail = normalizeEmail(object.customMetadata?.ownerEmail || '');
    if (ownerEmail && ownerEmail !== email) {
      return json({ ok: false, error: 'forbidden', message: 'Access denied for this media object.' }, 403);
    }

    const headers = new Headers();
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    if (object.httpMetadata?.contentType) {
      headers.set('Content-Type', object.httpMetadata.contentType);
    }
    if (object.httpEtag) {
      headers.set('ETag', object.httpEtag);
    }

    return new Response(object.body, { status: 200, headers });
  }

  if (method === 'POST' || method === 'PUT') {
    let body = null;
    try {
      body = await request.json();
    } catch {
      body = null;
    }
    if (!body || typeof body !== 'object') {
      return badRequest('Invalid JSON body.');
    }

    const source = String(body.source || body.sourceUrl || body.dataUrl || '').trim();
    if (!source) {
      return badRequest('Missing source image.');
    }

    try {
      const resolved = await resolveUploadSource(source);
      const bytes = resolved.bytes;
      const contentType = resolved.contentType || 'image/jpeg';

      if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
        return badRequest('Image payload is empty.');
      }
      if (bytes.length > MAX_UPLOAD_BYTES) {
        return badRequest('Image is too large. Maximum supported size is 8MB.');
      }

      const dayPrefix = new Date().toISOString().slice(0, 10);
      const extension = inferExtension(contentType);
      const key = `${sanitizeEmailPath(email)}/${dayPrefix}/${Date.now()}-${crypto.randomUUID()}.${extension}`;

      await bucket.put(key, bytes, {
        httpMetadata: {
          contentType
        },
        customMetadata: {
          ownerEmail: email
        }
      });

      return json({
        ok: true,
        key,
        contentType,
        size: bytes.length,
        url: buildMediaUrl(request, key, env)
      });
    } catch (error) {
      return badRequest(error instanceof Error ? error.message : 'Unable to process image source.');
    }
  }

  return json({ ok: false, error: 'method_not_allowed' }, 405);
}
