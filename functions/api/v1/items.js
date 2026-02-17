import {
  ITEM_COLLECTION_NAMES,
  deleteItemByEmail,
  ensureDb,
  ensureUserItemsTable,
  getAccessEmail,
  json,
  migrateSnapshotItemsToTable,
  normalizeCollectionName,
  normalizeEmail,
  parseJsonBody,
  readItemsByEmail,
  readSnapshotByEmail,
  upsertItemByEmail,
  upsertItemsByEmail
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

function badRequest(message) {
  return json(
    {
      ok: false,
      error: 'bad_request',
      message
    },
    400
  );
}

function objectOrEmpty(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

function getCollectionFromRequest(request, body = {}) {
  const url = new URL(request.url);
  return normalizeCollectionName(url.searchParams.get('collection') || body.collection || '');
}

function buildCounts(data = {}) {
  return {
    gadgets: Array.isArray(data.gadgets) ? data.gadgets.length : 0,
    games: Array.isArray(data.games) ? data.games.length : 0,
    digitalPurchases: Array.isArray(data.digitalPurchases) ? data.digitalPurchases.length : 0
  };
}

function pickDeleteItemIds(request, body = {}) {
  const url = new URL(request.url);
  const bodyIds = Array.isArray(body.itemIds)
    ? body.itemIds
    : (body.itemId ? [body.itemId] : []);
  const queryId = url.searchParams.get('itemId') || '';
  const allIds = bodyIds.concat(queryId ? [queryId] : []);
  return allIds
    .map((value) => String(value || '').trim())
    .filter(Boolean);
}

export async function onRequest({ request, env }) {
  const method = request.method.toUpperCase();
  if (method === 'OPTIONS') return new Response(null, { status: 204 });

  const email = normalizeEmail(getAccessEmail(request, env));
  if (!email) return unauthorized();

  const db = ensureDb(env);
  await ensureUserItemsTable(db);

  if (method === 'GET') {
    const collection = getCollectionFromRequest(request);
    let result = await readItemsByEmail(db, email, { collection });
    let migratedFromSnapshot = false;
    let migratedCount = 0;

    if (result.totalCount === 0) {
      const snapshotRow = await readSnapshotByEmail(db, email);
      if (snapshotRow && snapshotRow.snapshot) {
        migratedCount = await migrateSnapshotItemsToTable(db, email, snapshotRow.snapshot);
        if (migratedCount > 0) {
          result = await readItemsByEmail(db, email, { collection });
          migratedFromSnapshot = true;
        }
      }
    }

    const data = collection
      ? { [collection]: result.data[collection] || [] }
      : result.data;
    const counts = collection
      ? { [collection]: Array.isArray(data[collection]) ? data[collection].length : 0 }
      : buildCounts(result.data);

    return json({
      ok: true,
      backend: 'cloudflare-d1-items',
      collection: collection || 'all',
      migratedFromSnapshot,
      migratedCount,
      updatedAt: result.updatedAt || '',
      counts,
      data
    });
  }

  if (method === 'PUT' || method === 'POST') {
    const body = await parseJsonBody(request);
    if (!body || typeof body !== 'object') {
      return badRequest('Invalid JSON body.');
    }

    const collection = getCollectionFromRequest(request, body);
    if (!collection || !ITEM_COLLECTION_NAMES.includes(collection)) {
      return badRequest('Invalid collection. Use gadgets, games, or digitalPurchases.');
    }

    const root = objectOrEmpty(body);
    if (Array.isArray(root.items)) {
      const candidateItems = root.items
        .map((row) => objectOrEmpty(row))
        .map((item) => {
          const itemId = String(item.firestoreId || item.itemId || '').trim();
          if (!itemId) return null;
          return {
            ...item,
            firestoreId: itemId
          };
        })
        .filter(Boolean);

      const storedItems = await upsertItemsByEmail(db, email, collection, candidateItems);
      return json({
        ok: true,
        backend: 'cloudflare-d1-items',
        collection,
        saved: storedItems.length,
        items: storedItems
      });
    }

    const inputItem = objectOrEmpty(root.item && typeof root.item === 'object' ? root.item : root);
    const itemId = String(root.itemId || inputItem.firestoreId || inputItem.itemId || '').trim();
    if (!itemId) {
      return badRequest('Missing itemId/firestoreId for upsert.');
    }

    const stored = await upsertItemByEmail(db, email, collection, itemId, {
      ...inputItem,
      firestoreId: itemId
    });

    return json({
      ok: true,
      backend: 'cloudflare-d1-items',
      collection,
      saved: 1,
      item: stored
    });
  }

  if (method === 'DELETE') {
    const body = await parseJsonBody(request);
    const root = objectOrEmpty(body);
    const collection = getCollectionFromRequest(request, root);
    if (!collection || !ITEM_COLLECTION_NAMES.includes(collection)) {
      return badRequest('Invalid collection. Use gadgets, games, or digitalPurchases.');
    }

    const ids = pickDeleteItemIds(request, root);
    if (ids.length === 0) {
      return badRequest('Missing itemId (or itemIds) for delete.');
    }

    for (const itemId of ids) {
      await deleteItemByEmail(db, email, collection, itemId);
    }

    return json({
      ok: true,
      backend: 'cloudflare-d1-items',
      collection,
      deleted: ids.length
    });
  }

  return json({ ok: false, error: 'method_not_allowed' }, 405);
}
