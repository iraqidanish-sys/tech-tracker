import { getAccessEmail, isAdminEmail, json, normalizeEmail } from './_shared.js';

function parseCookies(cookieHeader = '') {
  const header = String(cookieHeader || '');
  if (!header) return {};
  return header.split(';').reduce((acc, pair) => {
    const trimmed = pair.trim();
    if (!trimmed) return acc;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex <= 0) return acc;
    const rawKey = trimmed.slice(0, eqIndex).trim();
    const rawValue = trimmed.slice(eqIndex + 1).trim();
    if (!rawKey) return acc;
    acc[rawKey] = rawValue;
    return acc;
  }, {});
}

function getAccessJwtToken(request) {
  const headerCandidates = [
    request.headers.get('cf-access-jwt-assertion'),
    request.headers.get('CF-Access-Jwt-Assertion')
  ];

  for (const candidate of headerCandidates) {
    const clean = String(candidate || '').trim();
    if (clean) return clean;
  }

  const cookieHeader = request.headers.get('cookie') || request.headers.get('Cookie') || '';
  const cookies = parseCookies(cookieHeader);
  const cookieNames = Object.keys(cookies);
  const tokenCookieName = cookieNames.find((name) => {
    const lower = String(name || '').toLowerCase();
    return lower === 'cf_authorization' || lower.startsWith('cf_authorization_');
  });

  if (!tokenCookieName) return '';
  return String(cookies[tokenCookieName] || '').trim();
}

function decodeBase64Url(input = '') {
  try {
    const normalized = String(input || '')
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    return atob(padded);
  } catch {
    return '';
  }
}

function parseAccessJwtClaims(request) {
  const token = getAccessJwtToken(request);
  const parts = String(token).split('.');
  if (parts.length < 2) return {};

  const rawPayload = decodeBase64Url(parts[1]);
  if (!rawPayload) return {};

  try {
    const parsed = JSON.parse(rawPayload);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function sanitizeImageUrl(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    if (parsed.username || parsed.password) return '';
    return parsed.toString();
  } catch {
    return '';
  }
}

function findImageLikeClaim(input) {
  if (!input || typeof input !== 'object') return '';
  const entries = Object.entries(input);
  for (const [key, value] of entries) {
    if (typeof value !== 'string') continue;
    const keyLower = String(key || '').toLowerCase();
    if (keyLower.includes('picture') || keyLower.includes('avatar') || keyLower.includes('photo') || keyLower.includes('image')) {
      const clean = value.trim();
      if (clean) return clean;
    }
  }
  return '';
}

function pickFirstString(candidates = []) {
  for (const value of candidates) {
    const clean = String(value || '').trim();
    if (clean) return clean;
  }
  return '';
}

export async function onRequest({ request, env }) {
  const requestUrl = new URL(request.url);
  const redirectTargetRaw = requestUrl.searchParams.get('redirect') || '';
  const hasSafeRedirect = redirectTargetRaw.startsWith('/') && !redirectTargetRaw.startsWith('//');
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

  if (hasSafeRedirect) {
    return Response.redirect(new URL(redirectTargetRaw, requestUrl.origin).toString(), 302);
  }

  const claims = parseAccessJwtClaims(request);
  const idpClaims = claims && typeof claims.identity_provider_claims === 'object' && claims.identity_provider_claims
    ? claims.identity_provider_claims
    : {};

  const displayName = pickFirstString([
    claims.name,
    [claims.given_name, claims.family_name].filter(Boolean).join(' ').trim(),
    claims.given_name,
    claims.preferred_username,
    idpClaims.name,
    [idpClaims.given_name, idpClaims.family_name].filter(Boolean).join(' ').trim(),
    idpClaims.given_name
  ]);

  const pictureCandidate = pickFirstString([
    claims.picture,
    claims.avatar,
    claims.photo,
    claims.photoURL,
    claims.profile_picture,
    claims.user_picture,
    idpClaims.picture,
    idpClaims.avatar,
    idpClaims.photo,
    idpClaims.photoURL,
    idpClaims.profile_picture,
    idpClaims.user_picture,
    findImageLikeClaim(idpClaims),
    findImageLikeClaim(claims)
  ]);
  const picture = sanitizeImageUrl(pictureCandidate);

  return json({
    ok: true,
    user: {
      email,
      name: displayName,
      picture,
      isAdmin: isAdminEmail(email, env)
    }
  });
}
