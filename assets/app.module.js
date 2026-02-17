import {
    createSVGIcon,
    getDefaultDigitalTypes,
    getDefaultGadgetCategories,
    getDefaultGameGenres,
    getDefaultGamePlatforms
} from './icon-catalog.js';

// Production Mode - Disable Console Logging
        if (window.location.hostname !== "localhost" && window.location.hostname !== "127.0.0.1") {
            console.log = function() {};
            console.debug = function() {};
        }

        // Cloudflare-native build (Firebase auth/data fallback removed)


        // ============================================
        // ENCRYPTION MANAGER CLASS - AES-256-GCM
        // ============================================
        class EncryptionManager {
            constructor() {
                this.encryptionKey = null;
                this.isUnlocked = false;
            }

            async deriveKeyFromPassword(password, salt) {
                const encoder = new TextEncoder();
                const passwordBuffer = encoder.encode(password);

                const keyMaterial = await window.crypto.subtle.importKey(
                    'raw', passwordBuffer, 'PBKDF2', false, ['deriveBits', 'deriveKey']
                );

                return await window.crypto.subtle.deriveKey(
                    {
                        name: 'PBKDF2',
                        salt: salt,
                        iterations: 100000,
                        hash: 'SHA-256'
                    },
                    keyMaterial,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
            }

            generateSalt() {
                return window.crypto.getRandomValues(new Uint8Array(16));
            }

            async encrypt(plaintext) {
                if (!this.encryptionKey) {
                    throw new Error('Encryption key not set');
                }

                const encoder = new TextEncoder();
                const data = encoder.encode(JSON.stringify(plaintext));
                const iv = window.crypto.getRandomValues(new Uint8Array(12));

                const encryptedData = await window.crypto.subtle.encrypt(
                    { name: 'AES-GCM', iv: iv },
                    this.encryptionKey,
                    data
                );

                const combined = new Uint8Array(iv.length + encryptedData.byteLength);
                combined.set(iv);
                combined.set(new Uint8Array(encryptedData), iv.length);

                return this.arrayBufferToBase64(combined);
            }

            async decrypt(encryptedBase64) {
                if (!this.encryptionKey) {
                    throw new Error('Encryption key not set');
                }

                try {
                    const combined = this.base64ToArrayBuffer(encryptedBase64);
                    const iv = combined.slice(0, 12);
                    const encryptedData = combined.slice(12);

                    const decryptedData = await window.crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv: iv },
                        this.encryptionKey,
                        encryptedData
                    );

                    const decoder = new TextDecoder();
                    return JSON.parse(decoder.decode(decryptedData));
                } catch (error) {
                    throw new Error('Failed to decrypt. Wrong password or corrupted data.');
                }
            }

            arrayBufferToBase64(buffer) {
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                return btoa(binary);
            }

            base64ToArrayBuffer(base64) {
                const binary = atob(base64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                return bytes;
            }

            async setupNewUser(password) {
                const salt = this.generateSalt();
                this.encryptionKey = await this.deriveKeyFromPassword(password, salt);
                this.isUnlocked = true;

                const saltBase64 = this.arrayBufferToBase64(salt);
                localStorage.setItem('encryptionSalt_' + currentUserUID, saltBase64);
                localStorage.setItem('encryptionEnabled_' + currentUserUID, 'true');

                return true;
            }

            async unlockExistingUser(password) {
                const saltBase64 = localStorage.getItem('encryptionSalt_' + currentUserUID);
                if (!saltBase64) {
                    throw new Error('No encryption salt found');
                }

                const salt = this.base64ToArrayBuffer(saltBase64);
                this.encryptionKey = await this.deriveKeyFromPassword(password, salt);
                this.isUnlocked = true;

                return true;
            }

            isEncryptionEnabled() {
                if (!currentUserUID) return false;
                return localStorage.getItem('encryptionEnabled_' + currentUserUID) === 'true';
            }

            lockData() {
                this.encryptionKey = null;
                this.isUnlocked = false;
            }
        }

        // Initialize global encryption manager
        const encryptionManager = new EncryptionManager();
        window.encryptionManager = encryptionManager;

        // Helper functions for encryption
        window.encryptData = async function(data) {

            if (!encryptionManager.isUnlocked) {
                return data;
            }

            try {
                const encrypted = await encryptionManager.encrypt(data);
                const result = {
                    encrypted: true,
                    data: encrypted,
                    timestamp: Date.now()
                };
                return result;
            } catch (error) {
                return data;
            }
        };

        window.decryptData = async function(encryptedDoc) {

            // If data is null or undefined, return as-is
            if (!encryptedDoc) {
                return encryptedDoc;
            }

            // If data is not marked as encrypted, return as-is
            if (!encryptedDoc.encrypted) {
                return encryptedDoc;
            }

            // If data IS encrypted but user hasn't unlocked yet
            if (!encryptionManager.isUnlocked) {
                // Return unencrypted placeholder or the encrypted doc
                return encryptedDoc;
            }

            // Try to decrypt
            try {
                const decrypted = await encryptionManager.decrypt(encryptedDoc.data);
                return decrypted;
            } catch (error) {
                // If decryption fails, this might be old unencrypted data
                // Return it without the encrypted wrapper
                if (encryptedDoc.data) {
                    // Try to parse if it's a string
                    try {
                        return JSON.parse(encryptedDoc.data);
                    } catch {
                        // If not valid JSON, return the original doc without encrypted flag
                        const { encrypted, ...originalData } = encryptedDoc;
                        return originalData;
                    }
                }
                // Last resort: return as-is
                return encryptedDoc;
            }
        };

        // Safety timeout - hide loading screen after 5 seconds if session bootstrap fails
        setTimeout(() => {
            const loadingScreen = document.getElementById('loadingScreen');
            if (loadingScreen && loadingScreen.style.display !== 'none') {
                loadingScreen.style.display = 'none';
                document.getElementById('loginScreen').style.display = 'flex';
            }
        }, 5000);
        // Global user state
        let currentUser = null;
        let currentUserUID = null;
        let currentCurrency = '₹';  // ← ADD THIS LINE
        let dataBackendMode = 'cloudflare';
        let cloudflareIdentityPromise = null;
        let cloudflareSnapshotCache = null;
        let cloudflareSaveChain = Promise.resolve();
        let cloudflareItemsApiSupported = true;
        let cloudflareMediaApiSupported = true;
        let cloudflareSyncQueue = [];
        let cloudflareSyncQueueOwner = '';
        let cloudflareSyncQueuePromise = null;
        let cloudflareSyncRetryTimer = null;

        // ========== ADMIN CONFIGURATION ==========
const ADMIN_EMAILS = [
    'iraqidanish@gmail.com',  // ← REPLACE WITH YOUR ACTUAL EMAIL
].map((email) => String(email || '').trim().toLowerCase()).filter(Boolean);

function normalizeEmail(value) {
    return String(value || '').trim().toLowerCase();
}

function isCloudflareBackendActive() {
    return dataBackendMode === 'cloudflare';
}

function generateLocalItemId(prefix = 'item') {
    return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

const CLOUDFLARE_API_TIMEOUTS = Object.freeze({
    identity: 10000,
    snapshotRead: 15000,
    snapshotWrite: 20000
});

const CLOUDFLARE_SYNC_QUEUE_KEY_PREFIX = 'gearnest_sync_queue_v1_';
const CLOUDFLARE_SYNC_RETRY_BASE_MS = 1200;
const CLOUDFLARE_SYNC_RETRY_MAX_MS = 45000;

function isRequestTimeoutError(error) {
    if (!error) return false;
    const message = String(error.message || '').toLowerCase();
    return message.includes('timed out') || message.includes('abort');
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        return await fetch(url, {
            ...options,
            signal: controller.signal
        });
    } catch (error) {
        if (error && error.name === 'AbortError') {
            throw new Error('Request timed out. Please check your connection and try again.');
        }
        throw error;
    } finally {
        clearTimeout(timer);
    }
}

function createApiError(message, status = 0, code = '') {
    const error = new Error(message || 'Request failed');
    error.status = Number(status || 0);
    if (code) {
        error.code = code;
    }
    return error;
}

function getCloudflareSyncQueueStorageKey(email = '') {
    const cleanEmail = normalizeEmail(email);
    if (!cleanEmail) return '';
    return `${CLOUDFLARE_SYNC_QUEUE_KEY_PREFIX}${cleanEmail}`;
}

function clearCloudflareSyncRetryTimer() {
    if (!cloudflareSyncRetryTimer) return;
    clearTimeout(cloudflareSyncRetryTimer);
    cloudflareSyncRetryTimer = null;
}

function persistCloudflareSyncQueueToStorage() {
    if (!cloudflareSyncQueueOwner) return;
    const key = getCloudflareSyncQueueStorageKey(cloudflareSyncQueueOwner);
    if (!key) return;

    try {
        localStorage.setItem(key, JSON.stringify(cloudflareSyncQueue));
    } catch {
        // Ignore storage errors to avoid blocking saves.
    }
}

function loadCloudflareSyncQueueFromStorage(email = '') {
    const key = getCloudflareSyncQueueStorageKey(email);
    if (!key) return [];

    try {
        const raw = localStorage.getItem(key);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];
        return parsed
            .map((entry) => ({
                action: entry && entry.action === 'delete' ? 'delete' : 'upsert',
                collectionName: String(entry.collectionName || '').trim(),
                itemId: String(entry.itemId || '').trim(),
                item: entry && typeof entry.item === 'object' && !Array.isArray(entry.item) ? entry.item : null,
                attempts: Number(entry.attempts || 0),
                nextAttemptAt: Number(entry.nextAttemptAt || 0),
                lastError: String(entry.lastError || '')
            }))
            .filter((entry) => {
                if (!entry.collectionName || !entry.itemId) return false;
                if (!['gadgets', 'games', 'digitalPurchases'].includes(entry.collectionName)) return false;
                if (entry.action === 'upsert' && (!entry.item || typeof entry.item !== 'object')) return false;
                return true;
            });
    } catch {
        return [];
    }
}

function ensureCloudflareSyncQueueHydrated() {
    const email = normalizeEmail((currentUser && currentUser.email) || '');
    if (!email) {
        cloudflareSyncQueueOwner = '';
        cloudflareSyncQueue = [];
        clearCloudflareSyncRetryTimer();
        return;
    }

    if (cloudflareSyncQueueOwner === email) return;

    cloudflareSyncQueueOwner = email;
    cloudflareSyncQueue = loadCloudflareSyncQueueFromStorage(email);
    clearCloudflareSyncRetryTimer();
}

function scheduleCloudflareSyncRetry(delayMs) {
    clearCloudflareSyncRetryTimer();
    const waitMs = Math.max(300, Number(delayMs || 0));
    cloudflareSyncRetryTimer = setTimeout(() => {
        cloudflareSyncRetryTimer = null;
        void processCloudflareSyncQueue();
    }, waitMs);
}

function isRetryableSyncError(error) {
    const status = Number(error && error.status ? error.status : 0);
    if (!status) return true;
    if (status >= 500) return true;
    if (status === 408 || status === 429 || status === 401) return true;
    return false;
}

function normalizeSyncQueueOperation(rawOperation) {
    const op = rawOperation && typeof rawOperation === 'object' ? rawOperation : {};
    const action = op.action === 'delete' ? 'delete' : 'upsert';
    const collectionName = String(op.collectionName || '').trim();
    const itemId = String(op.itemId || '').trim();
    if (!['gadgets', 'games', 'digitalPurchases'].includes(collectionName)) return null;
    if (!itemId) return null;

    const normalized = {
        action,
        collectionName,
        itemId,
        attempts: 0,
        nextAttemptAt: 0,
        lastError: ''
    };

    if (action === 'upsert') {
        const item = op.item && typeof op.item === 'object' && !Array.isArray(op.item) ? op.item : null;
        if (!item) return null;
        normalized.item = {
            ...item,
            firestoreId: itemId
        };
    }

    return normalized;
}

function enqueueCloudflareSyncOperation(rawOperation) {
    const operation = normalizeSyncQueueOperation(rawOperation);
    if (!operation) return;
    ensureCloudflareSyncQueueHydrated();

    const key = `${operation.collectionName}:${operation.itemId}`;
    cloudflareSyncQueue = cloudflareSyncQueue.filter((existing) => {
        const existingKey = `${existing.collectionName}:${existing.itemId}`;
        return existingKey !== key;
    });
    cloudflareSyncQueue.push(operation);
    persistCloudflareSyncQueueToStorage();
    void processCloudflareSyncQueue();
}

async function requestCloudflareItemsApi(method, body = null) {
    const fetchOptions = {
        method,
        cache: 'no-store',
        credentials: 'same-origin'
    };
    if (body && method !== 'GET') {
        fetchOptions.headers = {
            'Content-Type': 'application/json'
        };
        fetchOptions.body = JSON.stringify(body);
    }

    const response = await fetchWithTimeout('/api/v1/items', fetchOptions, CLOUDFLARE_API_TIMEOUTS.snapshotWrite);
    if (response.status === 404 || response.status === 405) {
        cloudflareItemsApiSupported = false;
        throw createApiError('Item API unavailable on this deployment.', response.status, 'items_api_unavailable');
    }

    let payload = null;
    try {
        payload = await response.json();
    } catch {
        payload = null;
    }

    if (!response.ok) {
        const message = payload && payload.message
            ? payload.message
            : `Item API request failed (${response.status}).`;
        throw createApiError(message, response.status, payload && payload.error ? payload.error : '');
    }

    cloudflareItemsApiSupported = true;
    return payload || {};
}

async function fetchCloudflareItemsDataRoot() {
    if (!cloudflareItemsApiSupported) return null;
    try {
        const payload = await requestCloudflareItemsApi('GET');
        const data = payload && payload.data && typeof payload.data === 'object'
            ? payload.data
            : {};
        return {
            gadgets: Array.isArray(data.gadgets) ? data.gadgets : [],
            games: Array.isArray(data.games) ? data.games : [],
            digitalPurchases: Array.isArray(data.digitalPurchases) ? data.digitalPurchases : []
        };
    } catch (error) {
        if (error && error.code === 'items_api_unavailable') {
            return null;
        }
        throw error;
    }
}

async function executeCloudflareSyncOperation(operation) {
    if (!operation) return;
    if (operation.action === 'delete') {
        await requestCloudflareItemsApi('DELETE', {
            collection: operation.collectionName,
            itemId: operation.itemId
        });
        return;
    }

    await requestCloudflareItemsApi('PUT', {
        collection: operation.collectionName,
        itemId: operation.itemId,
        item: operation.item
    });
}

async function processCloudflareSyncQueue(options = {}) {
    ensureCloudflareSyncQueueHydrated();
    if (!isCloudflareBackendActive()) return;
    if (!cloudflareSyncQueueOwner) return;

    if (cloudflareSyncQueuePromise) {
        if (options && options.waitForIdle) {
            await cloudflareSyncQueuePromise;
        }
        return;
    }

    cloudflareSyncQueuePromise = (async () => {
        clearCloudflareSyncRetryTimer();
        while (cloudflareSyncQueue.length > 0) {
            const current = cloudflareSyncQueue[0];
            const now = Date.now();
            if (current.nextAttemptAt && current.nextAttemptAt > now) {
                scheduleCloudflareSyncRetry(current.nextAttemptAt - now);
                break;
            }

            try {
                await executeCloudflareSyncOperation(current);
                cloudflareSyncQueue.shift();
                persistCloudflareSyncQueueToStorage();
            } catch (error) {
                if (error && error.code === 'items_api_unavailable') {
                    cloudflareItemsApiSupported = false;
                    // Fall back to legacy full snapshot persistence for compatibility.
                    await persistCloudflareSnapshot({ source: 'cloudflare-web-fallback' });
                    cloudflareSyncQueue = [];
                    persistCloudflareSyncQueueToStorage();
                    break;
                }

                if (!isRetryableSyncError(error)) {
                    cloudflareSyncQueue.shift();
                    persistCloudflareSyncQueueToStorage();
                    continue;
                }

                current.attempts = Number(current.attempts || 0) + 1;
                const waitMs = Math.min(
                    CLOUDFLARE_SYNC_RETRY_MAX_MS,
                    CLOUDFLARE_SYNC_RETRY_BASE_MS * Math.pow(2, Math.max(0, current.attempts - 1))
                );
                current.nextAttemptAt = Date.now() + waitMs;
                current.lastError = String(error && error.message ? error.message : 'Sync failed');
                cloudflareSyncQueue[0] = current;
                persistCloudflareSyncQueueToStorage();
                scheduleCloudflareSyncRetry(waitMs);
                break;
            }
        }
    })().finally(() => {
        cloudflareSyncQueuePromise = null;
    });

    if (options && options.waitForIdle) {
        await cloudflareSyncQueuePromise;
    }
}

async function saveCloudflareCollectionItemsBatch(collectionName, items, options = {}) {
    const rows = Array.isArray(items) ? items : [];
    if (rows.length === 0) return 0;

    try {
        await requestCloudflareItemsApi('PUT', {
            collection: collectionName,
            items: rows
        });
        return rows.length;
    } catch (error) {
        rows.forEach((item) => {
            const itemId = item && item.firestoreId ? String(item.firestoreId).trim() : '';
            if (!itemId) return;
            enqueueCloudflareSyncOperation({
                action: 'upsert',
                collectionName,
                itemId,
                item
            });
        });

        if (options && options.waitForSync) {
            await processCloudflareSyncQueue({ waitForIdle: true });
        }
        return rows.length;
    }
}

async function uploadImageToCloudflareMedia(sourceInput) {
    const source = String(sourceInput || '').trim();
    if (!source) return '';
    if (!cloudflareMediaApiSupported) return source;

    // Keep native URL/data URL behavior when media API is not configured.
    if (!source.startsWith('data:image/') && !/^https?:\/\//i.test(source)) {
        return source;
    }

    try {
        const response = await fetchWithTimeout('/api/v1/media', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            cache: 'no-store',
            credentials: 'same-origin',
            body: JSON.stringify({ source })
        }, CLOUDFLARE_API_TIMEOUTS.snapshotWrite + 8000);

        if (response.status === 501 || response.status === 404 || response.status === 405) {
            cloudflareMediaApiSupported = false;
            return source;
        }

        if (!response.ok) {
            return source;
        }

        const payload = await response.json();
        const mediaUrl = payload && payload.url ? String(payload.url).trim() : '';
        const sanitized = sanitizeURL(mediaUrl);
        cloudflareMediaApiSupported = true;
        return sanitized || source;
    } catch {
        return source;
    }
}

window.uploadImageToCloudflareMedia = uploadImageToCloudflareMedia;
window.forceCloudflareSync = async function() {
    await processCloudflareSyncQueue({ waitForIdle: true });
};

window.addEventListener('online', function() {
    void processCloudflareSyncQueue();
});

document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        void processCloudflareSyncQueue();
    }
});

function buildCloudflarePseudoUser(email, profile = {}) {
    const normalized = normalizeEmail(email);
    if (!normalized) return null;
    const cleanDisplayName = String(profile.displayName || '').trim();
    const cleanPhotoURL = String(profile.photoURL || '').trim();
    const isAdminUser = profile.isAdmin === true;
    const displayName = cleanDisplayName || normalized.split('@')[0] || 'user';
    return {
        uid: `cf:${normalized}`,
        email: normalized,
        displayName,
        photoURL: cleanPhotoURL,
        isAdmin: isAdminUser
    };
}

async function fetchCloudflareIdentity() {
    try {
        const response = await fetchWithTimeout(`/api/v1/me?t=${Date.now()}`, {
            method: 'GET',
            cache: 'no-store',
            credentials: 'same-origin'
        }, CLOUDFLARE_API_TIMEOUTS.identity);
        if (!response.ok) return null;
        const payload = await response.json();
        const userPayload = payload && payload.user && typeof payload.user === 'object' ? payload.user : {};
        const email = normalizeEmail(userPayload.email || '');
        const displayName = String(userPayload.name || userPayload.displayName || userPayload.fullName || '').trim();
        const photoURL = sanitizeURL(String(userPayload.picture || userPayload.photoURL || userPayload.avatar || userPayload.image || ''));
        const isAdminUser = userPayload.isAdmin === true;
        return buildCloudflarePseudoUser(email, { displayName, photoURL, isAdmin: isAdminUser });
    } catch {
        return null;
    }
}

function hideAdminNavItems() {
    const adminNav = document.getElementById('admin-nav');
    if (adminNav) adminNav.style.display = 'none';
    const adminBottomNav = document.getElementById('admin-bottom-nav');
    if (adminBottomNav) adminBottomNav.style.display = 'none';
    const profileMenuAdmin = document.getElementById('profileMenuAdmin');
    if (profileMenuAdmin) profileMenuAdmin.style.display = 'none';
}

function getDefaultUserAvatarMarkup() {
    return '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#e2e8f0" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round" style="width:66%;height:66%;"><circle cx="12" cy="8" r="3.2"></circle><path d="M5.8 18.2a6.2 6.2 0 0 1 12.4 0"></path></svg>';
}

function setDefaultUserAvatar(target) {
    if (!target) return;
    target.innerHTML = getDefaultUserAvatarMarkup();
}

function applySignedInUserUI(user) {
    document.getElementById('loginScreen').style.display = 'none';
    document.getElementById('mainApp').style.display = 'block';
    document.getElementById('userInfo').style.display = 'block';

    const displayName = user.displayName || user.email.split('@')[0];
    document.getElementById('userEmail').textContent = user.email;

    const userAvatar = document.getElementById('userAvatar');
    if (userAvatar) {
        const avatarUrl = sanitizeURL(user.photoURL || '');
        if (avatarUrl) {
            const avatarImg = document.createElement('img');
            avatarImg.src = avatarUrl;
            avatarImg.alt = displayName;
            avatarImg.addEventListener('error', () => setDefaultUserAvatar(userAvatar));
            userAvatar.innerHTML = '';
            userAvatar.appendChild(avatarImg);
        } else {
            setDefaultUserAvatar(userAvatar);
        }
    }

    if (window.updateProfileMenu) window.updateProfileMenu(user);

    if (isAdmin(user)) {
        const adminNav = document.getElementById('admin-nav');
        if (adminNav) adminNav.style.display = 'block';
        const adminBottomNav = document.getElementById('admin-bottom-nav');
        if (adminBottomNav) adminBottomNav.style.display = 'flex';
        const profileMenuAdmin = document.getElementById('profileMenuAdmin');
        if (profileMenuAdmin) profileMenuAdmin.style.display = 'flex';
    } else {
        hideAdminNavItems();
    }
}

async function fetchCloudflareSnapshot(options = {}) {
    const forceRefresh = options && options.forceRefresh === true;
    if (!forceRefresh && cloudflareSnapshotCache) {
        return cloudflareSnapshotCache;
    }

    const response = await fetchWithTimeout(`/api/v1/snapshot?t=${Date.now()}`, {
        method: 'GET',
        cache: 'no-store',
        credentials: 'same-origin'
    }, CLOUDFLARE_API_TIMEOUTS.snapshotRead);

    let payload = null;
    try {
        payload = await response.json();
    } catch {
        payload = null;
    }

    if (!response.ok) {
        const message = payload && payload.message
            ? payload.message
            : 'Unable to load Cloudflare snapshot.';
        throw new Error(message);
    }

    const snapshot = payload && payload.snapshot && typeof payload.snapshot === 'object'
        ? payload.snapshot
        : {};
    cloudflareSnapshotCache = snapshot;
    return snapshot;
}

async function persistCloudflareSnapshot(options = {}) {
    if (!isCloudflareBackendActive()) return null;

    const source = options && options.source ? String(options.source) : 'cloudflare-web-live';
    const includeAppConfig = options && options.includeAppConfig === true && isAdmin(currentUser);
    const includeGlobalSettings = options && options.includeGlobalSettings === true;

    const saveTask = async function() {
        const snapshotPayload = buildCloudflareMigrationSnapshot(source, {
            includeGlobalSettings: includeGlobalSettings || includeAppConfig
        });
        snapshotPayload.source = source;
        await uploadSnapshotToCloudflare(snapshotPayload, { includeAppConfig });
        cloudflareSnapshotCache = snapshotPayload;
        return snapshotPayload;
    };

    cloudflareSaveChain = cloudflareSaveChain
        .catch(() => null)
        .then(saveTask);

    return cloudflareSaveChain;
}

async function saveCloudflareCollectionItem(collectionName, item, existingId = '') {
    const prefixMap = {
        gadgets: 'g',
        games: 'gm',
        digitalPurchases: 'd'
    };
    const firestoreId = existingId || generateLocalItemId(prefixMap[collectionName] || 'item');
    const payload = { firestoreId, ...item };
    upsertLocalCollectionItem(collectionName, payload);

    if (!isCloudflareBackendActive()) {
        return firestoreId;
    }

    if (cloudflareItemsApiSupported === false) {
        await persistCloudflareSnapshot({ source: 'cloudflare-web-live' });
        return firestoreId;
    }

    enqueueCloudflareSyncOperation({
        action: 'upsert',
        collectionName,
        itemId: firestoreId,
        item: payload
    });
    return firestoreId;
}

async function deleteCloudflareCollectionItem(collectionName, firestoreId) {
    removeLocalCollectionItem(collectionName, firestoreId);
    if (!isCloudflareBackendActive()) return;

    if (cloudflareItemsApiSupported === false) {
        await persistCloudflareSnapshot({ source: 'cloudflare-web-live' });
        return;
    }

    enqueueCloudflareSyncOperation({
        action: 'delete',
        collectionName,
        itemId: firestoreId
    });
}

function isAdmin(user) {
    if (!user || !user.email) return false;
    if (user.isAdmin === true) return true;
    return ADMIN_EMAILS.includes(normalizeEmail(user.email));
}

function requireAdminAccess(actionText = 'perform this action') {
    if (isAdmin(currentUser)) return true;
    alert(`Admin access is required to ${actionText}.`);
    return false;
}

function normalizeAppPath(pathname = window.location.pathname) {
    const rawPath = String(pathname || '/').split('?')[0].split('#')[0];
    const cleanPath = rawPath.replace(/\/+$/, '');
    return cleanPath || '/';
}

function isAdminRoutePath(pathname = window.location.pathname) {
    return normalizeAppPath(pathname) === '/admin';
}

function syncPathForSection(section) {
    const targetPath = section === 'admin' ? '/admin' : '/';
    if (normalizeAppPath() !== targetPath) {
        window.history.replaceState({}, '', targetPath);
    }
}

window.openAdminPanel = function() {
    if (!currentUser) {
        window.location.assign('/admin');
        return;
    }

    if (!isAdmin(currentUser)) {
        alert('Admin access only.');
        return;
    }

    if (typeof window.showSection === 'function') {
        window.showSection('admin');
    }
};

// ========== INPUT SANITIZATION ==========

// Sanitize HTML content (for rich text fields like notes)
function sanitizeHTML(dirty) {
    if (!dirty) return '';
    return DOMPurify.sanitize(dirty, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
        ALLOWED_ATTR: ['href'],
        ALLOW_DATA_ATTR: false
    });
}

// Sanitize plain text (for titles, names, categories)
function sanitizeText(text) {
    if (!text) return '';
    const temp = document.createElement('div');
    temp.textContent = text;
    return temp.innerHTML.replace(/<[^>]*>/g, '');
}

function normalizeLabel(value) {
    if (value == null) return '';
    return String(value)
        .replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\uFE0F]/gu, '')
        .replace(/\s+/g, ' ')
        .trim();
}

window.normalizeLabel = normalizeLabel;

// Sanitize URLs (for icon URLs and links)
function sanitizeURL(url) {
    if (!url) return '';
    const trimmed = url.trim();

    // Allow data: URLs for base64 encoded images
    if (trimmed.startsWith('data:image/')) {
        if (trimmed.match(/^data:image\/(png|jpeg|jpg|gif|webp);base64,/i)) {
            return trimmed;
        }
        return '';
    }

    // Allow valid http/https URLs.
    // URL image picker already verifies image-load success before save.
    if (!trimmed.match(/^https?:\/\//i)) {
        return '';
    }

    try {
        const parsed = new URL(trimmed);

        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return '';
        }

        // Disallow embedded credentials in URL for safety.
        if (parsed.username || parsed.password) {
            return '';
        }

        return parsed.href;
    } catch (e) {
        return '';
    }
}

window.sanitizeURL = sanitizeURL;

// CORS proxy helper - bypasses CORS restrictions for external images
function getCORSProxyURL(imageUrl) {
    if (!imageUrl) return '';
    
    // Don't proxy data URLs
    if (imageUrl.startsWith('data:')) {
        return imageUrl;
    }
    
    // If already from a CORS-friendly source, return as-is
    const corsFriendly = [
        'images.unsplash.com',
        'i.imgur.com',
        'imgur.com',
        'res.cloudinary.com',
        'firebasestorage.googleapis.com',
        'corsproxy.io' // Don't proxy the proxy!
    ];
    
    try {
        const url = new URL(imageUrl);
        if (corsFriendly.some(domain => url.hostname.includes(domain))) {
            return imageUrl; // No proxy needed
        }
        
        // Use CORS proxy for potentially blocked domains
        return `https://corsproxy.io/?${encodeURIComponent(imageUrl)}`;
    } catch {
        return imageUrl;
    }
}

window.getCORSProxyURL = getCORSProxyURL;

const SETTINGS_ACCORDION_HEIGHT_FALLBACK_MS = 340;

function shouldReduceMotion() {
    return Boolean(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

function getSettingsAccordionBody(panel) {
    if (!panel || panel.tagName === 'DETAILS') return null;
    return panel.querySelector(':scope > .settings-accordion-body');
}

function cleanupSettingsAccordionBodyAnimation(body) {
    if (!body) return;

    if (body._settingsAccordionFrame) {
        cancelAnimationFrame(body._settingsAccordionFrame);
        body._settingsAccordionFrame = null;
    }

    if (body._settingsAccordionTimer) {
        clearTimeout(body._settingsAccordionTimer);
        body._settingsAccordionTimer = null;
    }

    if (body._settingsAccordionTransitionEnd) {
        body.removeEventListener('transitionend', body._settingsAccordionTransitionEnd);
        body._settingsAccordionTransitionEnd = null;
    }
}

function animateSettingsAccordionBody(panel, expand) {
    const body = getSettingsAccordionBody(panel);
    if (!body) return;

    cleanupSettingsAccordionBodyAnimation(body);

    if (shouldReduceMotion()) {
        body.style.height = expand ? 'auto' : '0px';
        return;
    }

    const startHeight = body.getBoundingClientRect().height;
    const targetHeight = expand ? body.scrollHeight : 0;

    body.style.height = `${startHeight}px`;
    body.offsetHeight; // Force reflow so the transition starts reliably.

    body._settingsAccordionFrame = requestAnimationFrame(() => {
        body.style.height = `${targetHeight}px`;
    });

    const finalize = (event) => {
        if (event && event.target !== body) return;
        if (event && event.propertyName !== 'height') return;

        cleanupSettingsAccordionBodyAnimation(body);
        body.style.height = expand ? 'auto' : '0px';
    };

    body._settingsAccordionTransitionEnd = finalize;
    body.addEventListener('transitionend', finalize);
    body._settingsAccordionTimer = setTimeout(finalize, SETTINGS_ACCORDION_HEIGHT_FALLBACK_MS);
}

function collapseSettingsAccordionPanel(panel) {
    if (!panel) return;
    if (panel.tagName === 'DETAILS') {
        panel.open = false;
        return;
    }

    panel.classList.remove('is-open');
    animateSettingsAccordionBody(panel, false);
    const trigger = panel.querySelector(':scope > .settings-accordion-trigger');
    if (trigger) {
        trigger.setAttribute('aria-expanded', 'false');
    }
}

function expandSettingsAccordionPanel(panel) {
    if (!panel) return;
    if (panel.tagName === 'DETAILS') {
        panel.open = true;
        return;
    }

    panel.classList.add('is-open');
    animateSettingsAccordionBody(panel, true);
    const trigger = panel.querySelector(':scope > .settings-accordion-trigger');
    if (trigger) {
        trigger.setAttribute('aria-expanded', 'true');
    }
}

function collapseSiblingAccordionPanels(panel) {
    if (!panel) return;
    const group = panel.dataset.accordionGroup;
    if (!group) return;

    document
        .querySelectorAll(`.settings-accordion-panel[data-accordion-group="${group}"]`)
        .forEach((candidate) => {
            if (candidate === panel) return;
            collapseSettingsAccordionPanel(candidate);
        });
}

function toggleSettingsAccordionPanel(panel) {
    if (!panel) return;

    const isOpen = panel.tagName === 'DETAILS'
        ? panel.open
        : panel.classList.contains('is-open');

    if (isOpen) {
        collapseSettingsAccordionPanel(panel);
        return;
    }

    collapseSiblingAccordionPanels(panel);
    expandSettingsAccordionPanel(panel);
}

function initializeSettingsAccordionPanels() {
    document
        .querySelectorAll('.settings-accordion-panel[data-accordion-group]')
        .forEach((panel) => {
            if (panel.dataset.accordionReady === '1') return;

            if (panel.tagName === 'DETAILS') {
                const summary = panel.querySelector(':scope > summary');
                if (summary) {
                    summary.addEventListener('click', (event) => {
                        event.preventDefault();
                        toggleSettingsAccordionPanel(panel);
                    });
                }
                panel.open = false;
                panel.dataset.accordionReady = '1';
                return;
            }

            const heading = panel.querySelector(':scope > h3');
            if (!heading) {
                panel.dataset.accordionReady = '1';
                return;
            }

            const trigger = document.createElement('button');
            trigger.type = 'button';
            trigger.className = 'settings-accordion-trigger';
            trigger.setAttribute('aria-expanded', 'false');

            const label = document.createElement('span');
            label.className = 'settings-accordion-trigger-label';
            label.innerHTML = heading.innerHTML;
            trigger.appendChild(label);

            const icon = document.createElement('span');
            icon.className = 'settings-accordion-trigger-icon';
            icon.setAttribute('aria-hidden', 'true');
            icon.textContent = '+';
            trigger.appendChild(icon);

            const body = document.createElement('div');
            body.className = 'settings-accordion-body';

            let next = heading.nextSibling;
            while (next) {
                const current = next;
                next = next.nextSibling;
                body.appendChild(current);
            }

            heading.replaceWith(trigger);
            panel.appendChild(body);
            panel.classList.remove('is-open');
            body.style.height = '0px';
            panel.dataset.accordionReady = '1';

            trigger.addEventListener('click', () => {
                toggleSettingsAccordionPanel(panel);
            });
        });
}

// Sanitize numeric inputs
function sanitizeNumber(value, defaultValue = 0) {
    const num = parseFloat(value);
    return isNaN(num) || !isFinite(num) ? defaultValue : num;
}

        // INSERT initializeUser() RIGHT HERE
async function initializeUser(user) {
    try {
        currentUserUID = user.uid;
        await loadSettings();

        // ============================================
        // ENCRYPTION FLOW - Check if user has encryption enabled
        // ============================================
        if (encryptionManager.isEncryptionEnabled()) {
            // User has encryption - show unlock modal
            const modal = document.getElementById('unlockModal');
            modal.style.display = 'flex';
            modal.classList.add('active');
            // Data will be loaded after successful unlock
        } else {
            // No encryption - load data normally
            await loadData();
        }
    } catch (err) {
    }
}
        // Global variables
        var gadgets = [];
        var games = [];
        var digitalPurchases = [];
        var currentFilter = 'all';
        var currentGadgetFilter = 'all';
        var currentDigitalFilter = 'all';
        var deleteCallback = null;
        var pendingCsvImport = null;

        // Ensure modals are hidden on page load
        document.addEventListener('DOMContentLoaded', function() {
            const deleteModal = document.getElementById('deleteModal');
            if (deleteModal) {
                deleteModal.classList.remove('active');
                deleteModal.style.display = 'none';
            }
            initializeSettingsAccordionPanels();
        });

        // Settings (loaded from Cloudflare snapshot)
        var gadgetCategories = [];
        var gamePlatforms = [];
        var gameGenres = [];
        var digitalTypes = [];
        var customIcons = []; // New: Store custom platform icons
        var gameMetadataCatalog = [];
        var gameMetadataEditingIndex = -1;

       // Authentication State Management (Cloudflare Access)
async function bootstrapCloudflareSession() {
    try {
        dataBackendMode = 'cloudflare';
        cloudflareSnapshotCache = null;

        if (!cloudflareIdentityPromise) {
            cloudflareIdentityPromise = fetchCloudflareIdentity();
        }
        const cloudflareUser = await cloudflareIdentityPromise;
        if (!cloudflareUser) {
            cloudflareIdentityPromise = null;
        }

        if (!cloudflareUser) {
            currentUser = null;
            currentUserUID = null;
            hideAdminNavItems();
            ensureCloudflareSyncQueueHydrated();

            const loginScreen = document.getElementById('loginScreen');
            const mainApp = document.getElementById('mainApp');

            if (loginScreen) {
                loginScreen.style.display = 'flex';
                loginScreen.style.visibility = 'visible';
                loginScreen.style.opacity = '1';
                if (isAdminRoutePath()) {
                    const errorDiv = document.getElementById('loginError');
                    if (errorDiv) {
                        errorDiv.textContent = 'Admin area: sign in with your admin account to continue.';
                        errorDiv.style.display = 'block';
                    }
                }
            }

            if (mainApp) {
                mainApp.style.display = 'none';
            }
            return;
        }

        currentUser = cloudflareUser;
        currentUserUID = cloudflareUser.uid;
        applySignedInUserUI(cloudflareUser);
        ensureCloudflareSyncQueueHydrated();
        void processCloudflareSyncQueue();

        if (isAdminRoutePath()) {
            if (isAdmin(cloudflareUser)) {
                if (typeof window.showSection === 'function') {
                    window.showSection('admin');
                }
            } else {
                alert('This account is not an admin. Sign in with your admin email in Cloudflare Access.');
                window.history.replaceState({}, '', '/');
                if (typeof window.showSection === 'function') {
                    window.showSection('dashboard');
                }
            }
        }

        await initializeUser(cloudflareUser);
    } catch (error) {
        const loginScreen = document.getElementById('loginScreen');
        const mainApp = document.getElementById('mainApp');
        if (loginScreen) loginScreen.style.display = 'flex';
        if (mainApp) mainApp.style.display = 'none';
    } finally {
        const loadingScreen = document.getElementById('loadingScreen');
        if (loadingScreen) loadingScreen.style.display = 'none';
    }
}

bootstrapCloudflareSession();

        // Sign Out
        setTimeout(() => {
            const signOutBtn = document.getElementById('signOutBtn');
            if (signOutBtn) {
                signOutBtn.addEventListener('click', async () => {
            try {
                // Clear encryption key on sign out
                encryptionManager.lockData();
                document.body.classList.remove('encrypted');

                if (isCloudflareBackendActive()) {
                    const returnTo = encodeURIComponent(`${window.location.origin}/`);
                    window.location.href = `/cdn-cgi/access/logout?returnTo=${returnTo}`;
                    return;
                }
            } catch (error) {
                alert('Failed to sign out: ' + error.message);
            }
        });
            }
        }, 100);

        // Mobile menu toggle
        window.toggleMobileMenu = function() {
            document.getElementById('sidebar').classList.toggle('mobile-open');
        };

      // Load user data from backend
async function loadData() {

    if (!currentUserUID) return;

    try {
        const mapSnapshotItems = async function(items, prefix, includeStatusFix) {
            const rows = Array.isArray(items) ? items : [];
            return Promise.all(rows.map(async (row) => {
                const raw = row && typeof row === 'object' ? row : {};
                try {
                    const data = (raw && raw.encrypted && encryptionManager.isUnlocked)
                        ? await decryptData(raw)
                        : raw;
                    if (includeStatusFix && !data.status) {
                        data.status = (data.sellPrice && data.sellDate) ? 'sold' : 'owned';
                    }
                    return {
                        firestoreId: raw.firestoreId || generateLocalItemId(prefix),
                        ...data
                    };
                } catch {
                    return {
                        firestoreId: raw.firestoreId || generateLocalItemId(prefix),
                        ...raw
                    };
                }
            }));
        };

        let dataRoot = await fetchCloudflareItemsDataRoot();
        if (!dataRoot) {
            const snapshot = await fetchCloudflareSnapshot();
            dataRoot = snapshot && typeof snapshot === 'object' && snapshot.data && typeof snapshot.data === 'object'
                ? snapshot.data
                : {};
        }

        const [loadedGadgets, loadedGames, loadedDigitalPurchases] = await Promise.all([
            mapSnapshotItems(dataRoot.gadgets, 'g', true),
            mapSnapshotItems(dataRoot.games, 'gm', true),
            mapSnapshotItems(dataRoot.digitalPurchases, 'd', false)
        ]);

        gadgets = loadedGadgets
            .map(g => ({ ...g, category: normalizeLabel(g.category || 'Other') || 'Other' }))
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        games = loadedGames
            .map(g => {
                const normalizedImageUrl = sanitizeURL(g.imageUrl || g.coverImageUrl || g.coverUrl || '');
                const normalizedGame = {
                    ...g,
                    platform: normalizeLabel(g.platform || 'Other') || 'Other',
                    genre: normalizeLabel(g.genre || 'Action') || 'Action',
                    condition: normalizeLabel(g.condition || 'New/Sealed') || 'New/Sealed',
                    metacriticScore: normalizeMetacriticScore(g.metacriticScore || g.metaCriticScore || g.metacritic || g.metaScore || ''),
                    metacriticUrl: sanitizeURL(g.metacriticUrl || g.metaCriticUrl || g.metacriticLink || g.metaUrl || ''),
                    imageUrl: normalizedImageUrl || null
                };
                return applyCatalogFallbackToGameRecord(normalizedGame);
            })
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        digitalPurchases = loadedDigitalPurchases
            .map(d => ({ ...d, type: normalizeLabel(d.type || 'Other') || 'Other' }))
            .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

        updateAll();

    } catch (error) {

        // More detailed error message
        let errorMsg = 'Error loading data. ';
        if (error && error.message && error.message.includes('missing_access_identity')) {
            errorMsg += 'Cloudflare Access session not found. Please sign in again.';
        } else if (error.message && error.message.includes('locked')) {
            errorMsg += 'Please unlock your data first.';
        } else {
            errorMsg += 'Please refresh the page. If the problem persists, clear your browser cache.';
        }

        alert(errorMsg);
    }
}

        function sortByTimestampDesc(items) {
            return items.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
        }

        function upsertLocalCollectionItem(collectionName, item) {
            if (!item || !item.firestoreId) return;

            if (collectionName === 'gadgets') {
                const idx = gadgets.findIndex(g => g.firestoreId === item.firestoreId);
                if (idx === -1) gadgets.push(item);
                else gadgets[idx] = item;
                sortByTimestampDesc(gadgets);
            } else if (collectionName === 'games') {
                const idx = games.findIndex(g => g.firestoreId === item.firestoreId);
                if (idx === -1) games.push(item);
                else games[idx] = item;
                sortByTimestampDesc(games);
            } else if (collectionName === 'digitalPurchases') {
                const idx = digitalPurchases.findIndex(d => d.firestoreId === item.firestoreId);
                if (idx === -1) digitalPurchases.push(item);
                else digitalPurchases[idx] = item;
                sortByTimestampDesc(digitalPurchases);
            }

            updateAll();
        }

        function removeLocalCollectionItem(collectionName, firestoreId) {
            if (!firestoreId) return;

            if (collectionName === 'gadgets') {
                gadgets = gadgets.filter(g => g.firestoreId !== firestoreId);
            } else if (collectionName === 'games') {
                games = games.filter(g => g.firestoreId !== firestoreId);
            } else if (collectionName === 'digitalPurchases') {
                digitalPurchases = digitalPurchases.filter(d => d.firestoreId !== firestoreId);
            }

            updateAll();
        }

        function normalizeMetacriticScore(value) {
            const raw = String(value == null ? '' : value).trim();
            if (!raw) return '';
            const parsed = parseFloat(raw.replace(/[^\d.]/g, ''));
            if (!Number.isFinite(parsed)) return '';
            const clamped = Math.max(0, Math.min(100, parsed));
            const rounded = Math.round(clamped * 10) / 10;
            return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1).replace(/\.0$/, '');
        }

        function buildGameMetadataKey(title, platform) {
            return `${normalizeLabel(title || '').toLowerCase()}|${normalizeLabel(platform || '').toLowerCase()}`;
        }

        function normalizeGameMetadataEntry(entry) {
            if (!entry || typeof entry !== 'object') return null;
            const title = normalizeLabel(entry.title || '');
            if (!title) return null;

            const platform = normalizeLabel(entry.platform || 'Other') || 'Other';
            const genre = normalizeLabel(entry.genre || '');
            const metacriticScore = normalizeMetacriticScore(entry.metacriticScore || '');
            const metacriticUrl = sanitizeURL(entry.metacriticUrl || '');
            const imageUrl = sanitizeURL(entry.imageUrl || '');

            return {
                title,
                platform,
                genre,
                metacriticScore,
                metacriticUrl,
                imageUrl
            };
        }

        function normalizeGameMetadataCatalog(list) {
            if (!Array.isArray(list)) return [];
            const map = new Map();

            list.forEach(row => {
                const normalized = normalizeGameMetadataEntry(row);
                if (!normalized) return;
                const key = buildGameMetadataKey(normalized.title, normalized.platform);
                map.set(key, normalized);
            });

            return Array.from(map.values()).sort((a, b) => {
                const titleCompare = a.title.localeCompare(b.title);
                if (titleCompare !== 0) return titleCompare;
                return a.platform.localeCompare(b.platform);
            });
        }

        function findBestGameMetadataMatch(title, platform, options = {}) {
            const targetTitle = normalizeLabel(title || '').toLowerCase();
            const targetPlatform = normalizeLabel(platform || '').toLowerCase();
            if (!targetTitle || gameMetadataCatalog.length === 0) return null;

            const exactByTitle = gameMetadataCatalog.filter(entry => normalizeLabel(entry.title || '').toLowerCase() === targetTitle);
            if (exactByTitle.length === 0) {
                if (options.allowPartial === true) {
                    const partial = gameMetadataCatalog.find(entry => normalizeLabel(entry.title || '').toLowerCase().includes(targetTitle));
                    return partial || null;
                }
                return null;
            }

            if (targetPlatform) {
                const exactPlatform = exactByTitle.find(entry => normalizeLabel(entry.platform || '').toLowerCase() === targetPlatform);
                if (exactPlatform) return exactPlatform;
            }

            return exactByTitle[0] || null;
        }

       // Load GLOBAL Settings from backend
async function loadSettings() {

    try {
        const snapshot = await fetchCloudflareSnapshot();
        const settings = snapshot && snapshot.settings && typeof snapshot.settings === 'object'
            ? snapshot.settings
            : {};

        currentCurrency = settings.currency || currentCurrency || '₹';
        gadgetCategories = (settings.gadgetCategories || getDefaultGadgetCategories())
            .map(normalizeLabel)
            .filter(Boolean);
        gamePlatforms = (settings.gamePlatforms || getDefaultGamePlatforms())
            .map(normalizeLabel)
            .filter(Boolean);
        gameGenres = (settings.gameGenres || getDefaultGameGenres())
            .map(normalizeLabel)
            .filter(Boolean);
        digitalTypes = (settings.digitalTypes || getDefaultDigitalTypes())
            .map(normalizeLabel)
            .filter(Boolean);
        customIcons = (settings.customIcons || [])
            .map(icon => ({ ...icon, platform: normalizeLabel(icon.platform || '') }))
            .filter(icon => icon.platform && icon.iconUrl);
        gameMetadataCatalog = normalizeGameMetadataCatalog(settings.gameMetadataCatalog || []);

        if (gadgetCategories.length === 0) gadgetCategories = getDefaultGadgetCategories();
        if (gamePlatforms.length === 0) gamePlatforms = getDefaultGamePlatforms();
        if (gameGenres.length === 0) gameGenres = getDefaultGameGenres();
        if (digitalTypes.length === 0) digitalTypes = getDefaultDigitalTypes();

        updateAllDropdowns();
        renderSettingsLists();
        renderCustomIcons();

        // Update encryption status display
        if (typeof updateEncryptionStatus === 'function') {
            updateEncryptionStatus();
        }

    } catch (error) {
    }
}

                // Create/update settings document
                async function saveSettings(options = {}) {

    try {

        const includeGameMetadataCatalog = options && options.includeGameMetadataCatalog === true;
        if (includeGameMetadataCatalog) {
            gameMetadataCatalog = normalizeGameMetadataCatalog(gameMetadataCatalog);
        }

        await persistCloudflareSnapshot({
            source: 'cloudflare-web-settings',
            includeAppConfig: true
        });

        updateAllDropdowns();
        renderSettingsLists();
        renderCustomIcons();

    } catch (error) {
        alert('Error saving settings. Please try again.');
    }
}

        // Update all dropdowns with current settings
        function updateAllDropdowns() {
            // Main form dropdowns
            updateDropdown('g-category', gadgetCategories);
            updateDropdown('gm-platform', gamePlatforms);
            updateDropdown('gm-genre', gameGenres);
            updateDropdown('d-type', digitalTypes);

            // Populate condition dropdowns
            const gadgetConditions = ['New', 'Like New', 'Good', 'Fair', 'Poor'];
            const gameConditions = ['New', 'Like New', 'Good', 'Fair', 'Poor', 'Digital'];
            updateDropdown('g-condition', gadgetConditions);
            updateDropdown('gm-condition', gameConditions);

            // Edit modal dropdowns
            updateDropdown('edit-g-category', gadgetCategories);
            updateDropdown('edit-g-condition', gadgetConditions);
            updateDropdown('edit-gm-platform', gamePlatforms);
            updateDropdown('edit-gm-genre', gameGenres);
            updateDropdown('edit-d-type', digitalTypes);
            updateDropdown('edit-gm-condition', gameConditions);

            updateIconPlatformDropdown();
            createCustomPlatformDropdown(); // Create visual dropdown with icons
            refreshGameMetadataCatalogUI();
        }

        function createCustomPlatformDropdown() {
            const wrapper = document.getElementById('platform-select-wrapper');
            const select = document.getElementById('gm-platform');
            if (!wrapper || !select) return;

            // Remove existing custom dropdown if any
            const existing = wrapper.querySelector('.custom-select-trigger');
            if (existing) {
                existing.remove();
                wrapper.querySelector('.custom-select-options')?.remove();
            }

            // Get current value
            const currentValue = select.value || gamePlatforms[0];
            const currentIcon = getCustomIconForPlatform(currentValue);
            const displayText = removeEmojiFromText(currentValue);

            // Create trigger
            const trigger = document.createElement('div');
            trigger.className = 'custom-select-trigger';
            trigger.innerHTML = currentIcon
                ? '<img src="' + currentIcon.iconUrl + '" class="custom-select-icon" alt="' + currentValue + '">' + displayText
                : displayText;

            // Create options container
            const optionsContainer = document.createElement('div');
            optionsContainer.className = 'custom-select-options';

            gamePlatforms.forEach(platform => {
                const option = document.createElement('div');
                option.className = 'custom-select-option';
                if (platform === currentValue) option.classList.add('selected');

                const icon = getCustomIconForPlatform(platform);
                const text = removeEmojiFromText(platform);

                option.innerHTML = icon
                    ? '<img src="' + icon.iconUrl + '" class="custom-select-icon" alt="' + platform + '">' + text
                    : text;

                option.onclick = () => {
                    select.value = platform;
                    trigger.innerHTML = icon
                        ? '<img src="' + icon.iconUrl + '" class="custom-select-icon" alt="' + platform + '">' + text
                        : text;
                    optionsContainer.classList.remove('active');
                    trigger.classList.remove('active');
                    optionsContainer.querySelectorAll('.custom-select-option').forEach(opt => opt.classList.remove('selected'));
                    option.classList.add('selected');
                    if (typeof window.updateGameCatalogSearchHint === 'function') {
                        window.updateGameCatalogSearchHint();
                    }
                };

                optionsContainer.appendChild(option);
            });

            // Toggle dropdown
            trigger.onclick = () => {
                trigger.classList.toggle('active');
                optionsContainer.classList.toggle('active');
            };

            // Close on outside click (cleanup previous handler to avoid listener leaks)
            if (wrapper._outsideClickHandler) {
                document.removeEventListener('click', wrapper._outsideClickHandler);
            }
            wrapper._outsideClickHandler = function(e) {
                if (!wrapper.contains(e.target)) {
                    trigger.classList.remove('active');
                    optionsContainer.classList.remove('active');
                }
            };
            document.addEventListener('click', wrapper._outsideClickHandler);

            wrapper.insertBefore(trigger, select);
            wrapper.appendChild(optionsContainer);
        }

        function getCustomIconForPlatform(platform) {
            // Try exact match
            let icon = customIcons.find(icon => icon.platform === platform);
            if (icon) return icon;

            // Try fuzzy match
            const cleanPlatform = platform.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();
            return customIcons.find(icon => {
                const cleanIcon = icon.platform.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();
                return cleanIcon === cleanPlatform;
            });
        }

        function removeEmojiFromText(text) {
            return text.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();
        }

        function updateIconPlatformDropdown() {
            const select = document.getElementById('icon-platform-name');
            if (!select) return;

            const currentValue = select.value;
            select.innerHTML = '<option value="">Select a platform...</option>';

            gamePlatforms.forEach(platform => {
                const opt = document.createElement('option');
                opt.value = platform;
                opt.textContent = platform;
                select.appendChild(opt);
            });

            // Restore previous selection if it still exists
            if (gamePlatforms.includes(currentValue)) {
                select.value = currentValue;
            }

            // Create visual custom dropdown
            createCustomIconPlatformDropdown();
        }

        function createCustomIconPlatformDropdown() {
            const wrapper = document.getElementById('icon-platform-select-wrapper');
            const select = document.getElementById('icon-platform-name');
            if (!wrapper || !select) return;

            // Remove existing custom dropdown if any
            const existing = wrapper.querySelector('.custom-select-trigger');
            if (existing) {
                existing.remove();
                wrapper.querySelector('.custom-select-options')?.remove();
            }

            // Get current value
            const currentValue = select.value;
            const currentIcon = currentValue ? getCustomIconForPlatform(currentValue) : null;
            const displayText = currentValue ? removeEmojiFromText(currentValue) : 'Select a platform...';

            // Create trigger
            const trigger = document.createElement('div');
            trigger.className = 'custom-select-trigger';
            trigger.innerHTML = (currentIcon && currentValue)
                ? '<img src="' + currentIcon.iconUrl + '" class="custom-select-icon" alt="' + currentValue + '">' + displayText + '<span class="custom-select-arrow">▼</span>'
                : displayText + '<span class="custom-select-arrow">▼</span>';

            // Create options container
            const optionsContainer = document.createElement('div');
            optionsContainer.className = 'custom-select-options';

            // Add empty option
            const emptyOption = document.createElement('div');
            emptyOption.className = 'custom-select-option';
            if (!currentValue) emptyOption.classList.add('selected');
            emptyOption.textContent = 'Select a platform...';
            emptyOption.onclick = () => {
                select.value = '';
                trigger.innerHTML = 'Select a platform...<span class="custom-select-arrow">▼</span>';
                optionsContainer.classList.remove('active');
                trigger.classList.remove('active');
                optionsContainer.querySelectorAll('.custom-select-option').forEach(opt => opt.classList.remove('selected'));
                emptyOption.classList.add('selected');
            };
            optionsContainer.appendChild(emptyOption);

            gamePlatforms.forEach(platform => {
                const option = document.createElement('div');
                option.className = 'custom-select-option';
                if (platform === currentValue) option.classList.add('selected');

                const icon = getCustomIconForPlatform(platform);
                const text = removeEmojiFromText(platform);

                option.innerHTML = icon
                    ? '<img src="' + icon.iconUrl + '" class="custom-select-icon" alt="' + platform + '">' + text
                    : text;

                option.onclick = () => {
                    select.value = platform;
                    trigger.innerHTML = icon
                        ? '<img src="' + icon.iconUrl + '" class="custom-select-icon" alt="' + platform + '">' + text + '<span class="custom-select-arrow">▼</span>'
                        : text + '<span class="custom-select-arrow">▼</span>';
                    optionsContainer.classList.remove('active');
                    trigger.classList.remove('active');
                    optionsContainer.querySelectorAll('.custom-select-option').forEach(opt => opt.classList.remove('selected'));
                    option.classList.add('selected');
                };

                optionsContainer.appendChild(option);
            });

            // Toggle dropdown
            trigger.onclick = () => {
                trigger.classList.toggle('active');
                optionsContainer.classList.toggle('active');
            };

            // Close on outside click (cleanup previous handler to avoid listener leaks)
            if (wrapper._outsideClickHandler) {
                document.removeEventListener('click', wrapper._outsideClickHandler);
            }
            wrapper._outsideClickHandler = function(e) {
                if (!wrapper.contains(e.target)) {
                    trigger.classList.remove('active');
                    optionsContainer.classList.remove('active');
                }
            };
            document.addEventListener('click', wrapper._outsideClickHandler);

            wrapper.insertBefore(trigger, select);
            wrapper.appendChild(optionsContainer);
        }

        function updateDropdown(id, options) {
            const select = document.getElementById(id);
            if (!select) return;

            const currentValue = select.value;
            select.innerHTML = '';

            options.forEach(option => {
                const opt = document.createElement('option');
                opt.value = option;

                // For platform dropdown, add icon indicator
                if (id === 'gm-platform') {
                    const customIcon = customIcons.find(icon => {
                        // Try exact match
                        if (icon.platform === option) return true;
                        // Try fuzzy match (without emoji)
                        const cleanOption = option.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();
                        const cleanIcon = icon.platform.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();
                        return cleanIcon === cleanOption;
                    });

                    if (customIcon) {
                        opt.textContent = 'Custom Icon: ' + normalizeLabel(option);
                    } else {
                        opt.textContent = option;
                    }
                } else {
                    opt.textContent = option;
                }

                select.appendChild(opt);
            });

            // Restore previous selection if it still exists
            if (options.includes(currentValue)) {
                select.value = currentValue;
            }
        }

        // Render settings lists
        function renderSettingsLists() {
            renderList('gadget-categories-list', gadgetCategories, 'gadgetCategory');
            renderList('game-platforms-list', gamePlatforms, 'gamePlatform');
            renderList('game-genres-list', gameGenres, 'gameGenre');
            renderList('digital-types-list', digitalTypes, 'digitalType');
            renderGameMetadataCatalogManager();
            const statusEl = document.getElementById('settings-gmc-editor-status');
            if (gameMetadataEditingIndex < 0 && statusEl && !statusEl.textContent) {
                setGameMetadataEditorStatus('Ready to add new catalog entries.');
            }
        }

        function renderList(containerId, items, type) {
            const container = document.getElementById(containerId);
            if (!container) return;

            container.innerHTML = items.map((item, index) => {
                let displayContent = '';

                // Remove emojis from text for display
                const cleanText = item.replace(/[\u{1F300}-\u{1F9FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]|[\u0000-\u001F\u007F-\u009F\u2000-\u206F\uE000-\uF8FF\uD800-\uDFFF]/gu, '').trim();

                // Check if this is a game platform and has a custom uploaded icon
                if (type === 'gamePlatform') {
                    const customIcon = getCustomIconForPlatform(item);
                    if (customIcon) {
                        // Show custom uploaded icon
                        displayContent = `<span class="icon-img-wrap-sm"><img src="${customIcon.iconUrl}" alt="${cleanText}"></span> <span style="font-size:13px;font-weight:600;">${cleanText}</span>`;
                    } else {
                        // Use SVG icon
                        const animationDelay = (index * 0.1) % 1;
                        displayContent = `${createSVGIcon(item, animationDelay)} <span style="font-size:13px;font-weight:600;margin-left:6px;">${cleanText}</span>`;
                    }
                } else {
                    // Use SVG icon for all other types (gadgets, genres, digital types)
                    const animationDelay = (index * 0.1) % 1;
                    displayContent = `${createSVGIcon(item, animationDelay)} <span style="font-size:13px;font-weight:600;margin-left:6px;">${cleanText}</span>`;
                }

                return `
                    <div class="settings-list-item">
                        ${displayContent}
                        <button onclick="window.remove${type.charAt(0).toUpperCase() + type.slice(1)}('${item.replace(/'/g, "\\'")}')" style="background:linear-gradient(135deg, #ef4444 0%, #dc2626 100%);border:none;color:white;padding:4px 10px;border-radius:6px;cursor:pointer;font-size:13px;margin-left:auto;font-weight:600;transition:all 0.2s ease;box-shadow:0 2px 6px rgba(239, 68, 68, 0.3);" onmouseover="this.style.transform='scale(1.05)';this.style.boxShadow='0 4px 12px rgba(239, 68, 68, 0.5)'" onmouseout="this.style.transform='scale(1)';this.style.boxShadow='0 2px 6px rgba(239, 68, 68, 0.3)'">×</button>
                    </div>
                `;
            }).join('');
        }

        function setGameMetadataEditorState(index = -1) {
            gameMetadataEditingIndex = Number.isInteger(index) ? index : -1;
            const saveBtn = document.getElementById('settings-gmc-save-btn');
            if (saveBtn) {
                saveBtn.textContent = gameMetadataEditingIndex >= 0 ? 'Save Changes' : 'Add Entry';
            }
        }

        function setGameMetadataEditorStatus(message, muted = true) {
            const statusEl = document.getElementById('settings-gmc-editor-status');
            if (!statusEl) return;
            statusEl.textContent = message || '';
            statusEl.style.color = muted ? 'var(--text-muted)' : 'var(--text-secondary)';
        }

        function readGameMetadataEditorInputs() {
            return {
                title: document.getElementById('settings-gmc-title'),
                platform: document.getElementById('settings-gmc-platform'),
                genre: document.getElementById('settings-gmc-genre'),
                score: document.getElementById('settings-gmc-score'),
                url: document.getElementById('settings-gmc-url'),
                image: document.getElementById('settings-gmc-image')
            };
        }

        function getGameMetadataEditorEntry() {
            const fields = readGameMetadataEditorInputs();
            return normalizeGameMetadataEntry({
                title: fields.title ? fields.title.value : '',
                platform: fields.platform ? fields.platform.value : '',
                genre: fields.genre ? fields.genre.value : '',
                metacriticScore: fields.score ? fields.score.value : '',
                metacriticUrl: fields.url ? fields.url.value : '',
                imageUrl: fields.image ? fields.image.value : ''
            });
        }

        window.clearGameMetadataCatalogEditor = function() {
            if (!requireAdminAccess('manage game metadata catalog')) return;
            const fields = readGameMetadataEditorInputs();
            Object.values(fields).forEach(input => {
                if (input) input.value = '';
            });
            setGameMetadataEditorState(-1);
            setGameMetadataEditorStatus('Ready to add new catalog entries.');
        };

        window.renderGameMetadataCatalogManager = function() {
            const listEl = document.getElementById('settings-game-metadata-list');
            const searchInput = document.getElementById('settings-game-metadata-search');
            if (!listEl) return;

            if (!isAdmin(currentUser)) {
                listEl.innerHTML = '<div class="settings-gmc-empty">Admin access required.</div>';
                return;
            }

            if (gameMetadataEditingIndex >= gameMetadataCatalog.length) {
                setGameMetadataEditorState(-1);
            }

            const query = normalizeLabel(searchInput ? searchInput.value : '').toLowerCase();
            const rows = gameMetadataCatalog
                .map((entry, index) => ({ entry, index }))
                .filter(row => {
                    if (!query) return true;
                    const haystack = [
                        normalizeLabel(row.entry.title || '').toLowerCase(),
                        normalizeLabel(row.entry.platform || '').toLowerCase(),
                        normalizeLabel(row.entry.genre || '').toLowerCase(),
                        normalizeLabel(row.entry.metacriticScore || '').toLowerCase()
                    ].join(' ');
                    return haystack.includes(query);
                });

            if (rows.length === 0) {
                const emptyLabel = gameMetadataCatalog.length === 0
                    ? 'No catalog entries yet. Import CSV or add one above.'
                    : 'No entries match this search.';
                listEl.innerHTML = `<div class="settings-gmc-empty">${sanitizeText(emptyLabel)}</div>`;
                return;
            }

            listEl.innerHTML = rows.map(({ entry, index }) => {
                const metaParts = [entry.platform];
                if (entry.genre) metaParts.push(entry.genre);
                if (entry.metacriticScore) metaParts.push(`MC ${entry.metacriticScore}`);
                const metaLine = metaParts.join(' | ');
                const activeClass = index === gameMetadataEditingIndex ? ' settings-gmc-card--active' : '';

                return `
                    <div class="settings-gmc-card${activeClass}">
                        <div class="settings-gmc-title">${sanitizeText(entry.title)}</div>
                        <div class="settings-gmc-meta">${sanitizeText(metaLine)}</div>
                        <div class="settings-gmc-actions">
                            <button type="button" class="settings-gmc-btn settings-gmc-btn-edit" onclick="editGameMetadataCatalogEntry(${index})">Edit</button>
                            <button type="button" class="settings-gmc-btn settings-gmc-btn-delete" onclick="deleteGameMetadataCatalogEntry(${index})">Delete</button>
                        </div>
                    </div>
                `;
            }).join('');
        };

        window.editGameMetadataCatalogEntry = function(index) {
            if (!requireAdminAccess('edit game metadata catalog entries')) return;
            const entry = gameMetadataCatalog[index];
            if (!entry) return;
            const fields = readGameMetadataEditorInputs();
            if (fields.title) fields.title.value = entry.title || '';
            if (fields.platform) fields.platform.value = entry.platform || '';
            if (fields.genre) fields.genre.value = entry.genre || '';
            if (fields.score) fields.score.value = entry.metacriticScore || '';
            if (fields.url) fields.url.value = entry.metacriticUrl || '';
            if (fields.image) fields.image.value = entry.imageUrl || '';
            setGameMetadataEditorState(index);
            setGameMetadataEditorStatus(`Editing: ${entry.title} | ${entry.platform}`, false);
            if (fields.title) fields.title.focus();
        };

        window.deleteGameMetadataCatalogEntry = async function(index) {
            if (!requireAdminAccess('delete game metadata catalog entries')) return;
            const entry = gameMetadataCatalog[index];
            if (!entry) return;
            if (!confirm(`Delete catalog entry: ${entry.title} (${entry.platform})?`)) return;

            gameMetadataCatalog.splice(index, 1);
            gameMetadataCatalog = normalizeGameMetadataCatalog(gameMetadataCatalog);

            if (gameMetadataEditingIndex === index) {
                window.clearGameMetadataCatalogEditor();
            } else if (gameMetadataEditingIndex > index) {
                setGameMetadataEditorState(gameMetadataEditingIndex - 1);
            }

            await saveSettings({ includeGameMetadataCatalog: true });
            setGameMetadataEditorStatus('Catalog entry deleted.', false);
        };

        window.saveGameMetadataCatalogEntry = async function() {
            if (!requireAdminAccess('save game metadata catalog entries')) return;
            const candidate = getGameMetadataEditorEntry();
            if (!candidate) {
                alert('Title is required to save a catalog entry.');
                return;
            }

            const incomingKey = buildGameMetadataKey(candidate.title, candidate.platform);
            const duplicateIndex = gameMetadataCatalog.findIndex((entry, idx) => {
                if (idx === gameMetadataEditingIndex) return false;
                return buildGameMetadataKey(entry.title, entry.platform) === incomingKey;
            });

            if (duplicateIndex >= 0) {
                if (!confirm('An entry with the same title and platform already exists. Replace it?')) {
                    return;
                }
                gameMetadataCatalog[duplicateIndex] = candidate;
                if (gameMetadataEditingIndex >= 0 && gameMetadataEditingIndex !== duplicateIndex) {
                    gameMetadataCatalog.splice(gameMetadataEditingIndex, 1);
                }
            } else if (gameMetadataEditingIndex >= 0 && gameMetadataCatalog[gameMetadataEditingIndex]) {
                gameMetadataCatalog[gameMetadataEditingIndex] = candidate;
            } else {
                gameMetadataCatalog.push(candidate);
            }

            gameMetadataCatalog = normalizeGameMetadataCatalog(gameMetadataCatalog);
            await saveSettings({ includeGameMetadataCatalog: true });
            window.clearGameMetadataCatalogEditor();
            setGameMetadataEditorStatus('Catalog entry saved.', false);
        };

        // Add/Remove functions for each setting type
        window.addGadgetCategory = async function() {
            const input = document.getElementById('new-gadget-category');
            const value = normalizeLabel(input.value);

            if (value && !gadgetCategories.includes(value)) {
                gadgetCategories.push(value);
                input.value = '';
                await saveSettings();
            }
        };

        window.removeGadgetCategory = async function(category) {
            if (confirm(`Remove category: ${category}?`)) {
                gadgetCategories = gadgetCategories.filter(c => c !== category);
                await saveSettings();
            }
        };

        window.addGamePlatform = async function() {
            const input = document.getElementById('new-game-platform');
            const value = normalizeLabel(input.value);

            if (value && !gamePlatforms.includes(value)) {
                gamePlatforms.push(value);
                input.value = '';
                await saveSettings();
            }
        };

        window.removeGamePlatform = async function(platform) {
            if (confirm(`Remove platform: ${platform}?`)) {
                gamePlatforms = gamePlatforms.filter(p => p !== platform);
                await saveSettings();
            }
        };

        window.addGameGenre = async function() {
            const input = document.getElementById('new-game-genre');
            const value = normalizeLabel(input.value);

            if (value && !gameGenres.includes(value)) {
                gameGenres.push(value);
                input.value = '';
                await saveSettings();
            }
        };

        window.removeGameGenre = async function(genre) {
            if (confirm(`Remove genre: ${genre}?`)) {
                gameGenres = gameGenres.filter(g => g !== genre);
                await saveSettings();
            }
        };

        window.addDigitalType = async function() {
            const input = document.getElementById('new-digital-type');
            const value = normalizeLabel(input.value);

            if (value && !digitalTypes.includes(value)) {
                digitalTypes.push(value);
                input.value = '';
                await saveSettings();
            }
        };

        window.removeDigitalType = async function(type) {
            if (confirm(`Remove type: ${type}?`)) {
                digitalTypes = digitalTypes.filter(t => t !== type);
                await saveSettings();
            }
        };

        // Custom Icon Functions
        let currentIconPreview = null;

        function handleIconUpload(event) {
            const file = event.target.files[0];
            if (!file) return;

            if (!file.type.startsWith('image/')) {
                alert('Please upload an image file');
                return;
            }

            const reader = new FileReader();
            reader.onload = (e) => {
                currentIconPreview = e.target.result;
                showIconPreview(currentIconPreview);
            };
            reader.readAsDataURL(file);
        }

        function handleIconURL(event) {
            const url = event.target.value.trim();
            if (url) {
                currentIconPreview = url;
                showIconPreview(url);
            } else {
                hideIconPreview();
            }
        }

        function showIconPreview(src) {
            const preview = document.getElementById('icon-preview');
            const img = document.getElementById('icon-preview-img');

            if (preview && img) {
                img.src = src;
                img.onerror = () => {
                    alert('Failed to load image. Please check the URL or file.');
                    hideIconPreview();
                };
                preview.style.display = 'block';
            }
        }

        function hideIconPreview() {
            const preview = document.getElementById('icon-preview');
            if (preview) {
                preview.style.display = 'none';
            }
            currentIconPreview = null;
        }

        window.saveCustomIcon = async function() {
            const selectElement = document.getElementById('icon-platform-name');
            const platformName = selectElement.value;


            if (!platformName) {
                alert('Please select a platform');
                return;
            }

            if (!currentIconPreview) {
                alert('Please upload an icon or provide a URL');
                return;
            }

            // Check if icon already exists for this platform
            const existingIndex = customIcons.findIndex(icon => icon.platform === platformName);

            const newIcon = {
                platform: platformName,
                iconUrl: currentIconPreview,
                timestamp: Date.now()
            };


            if (existingIndex >= 0) {
                if (confirm(`An icon already exists for "${platformName}". Replace it?`)) {
                    customIcons[existingIndex] = newIcon;
                } else {
                    return;
                }
            } else {
                customIcons.push(newIcon);
            }

            await saveSettings();


            // Clear inputs
            document.getElementById('icon-platform-name').value = '';
            document.getElementById('icon-upload').value = '';
            document.getElementById('icon-url').value = '';
            hideIconPreview();

            alert(`Icon for "${platformName}" saved successfully!`);
        };

        window.removeCustomIcon = async function(platform) {
            if (confirm(`Remove custom icon for "${platform}"?`)) {
                customIcons = customIcons.filter(icon => icon.platform !== platform);
                await saveSettings();
            }
        };

        function renderCustomIcons() {
            const iconsGrid = document.getElementById('icons-grid');
            if (!iconsGrid) return;


            if (customIcons.length === 0) {
                iconsGrid.innerHTML = '<p style="color: rgba(255,255,255,0.4); text-align: center; padding: 20px; width:100%;">No custom icons yet. Add one above!</p>';
                return;
            }

            iconsGrid.innerHTML = customIcons.map((icon, index) => `
                <div style="width:90px;flex:0 0 90px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:12px;padding:12px 8px;text-align:center;overflow:hidden;">
                    <div class="icon-img-wrap" style="margin:0 auto 8px;">
                        <img src="${icon.iconUrl}" alt="${icon.platform}">
                    </div>
                    <div style="font-size:11px;color:rgba(255,255,255,0.8);margin-bottom:8px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${icon.platform}</div>
                    <button onclick="window.removeCustomIconByIndex(${index})" style="background:rgba(239,68,68,0.8);border:none;padding:4px 8px;border-radius:6px;color:white;font-size:10px;cursor:pointer;font-weight:600;width:100%;">Remove</button>
                </div>
            `).join('');
        }

        window.removeCustomIconByIndex = async function(index) {
            const icon = customIcons[index];
            if (!icon) return;

            if (confirm(`Remove custom icon for "${icon.platform}"?`)) {
                customIcons.splice(index, 1);
                await saveSettings();
            }
        };

        function getPlatformDisplay(platform) {

            customIcons.forEach((icon, index) => {
            });

            // Try exact match first
            let customIcon = customIcons.find(icon => icon.platform === platform);

            // If no exact match, try fuzzy match (remove emojis and special chars and compare)
            if (!customIcon) {
                // Remove emojis and extra spaces
                const cleanPlatform = platform.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();

                customIcon = customIcons.find(icon => {
                    const cleanIcon = icon.platform.replace(/[\u0000-\u001F\u007F-\u009F\u2000-\u206F\u2700-\u27BF\uE000-\uF8FF\uD800-\uDFFF]/g, '').replace(/\s+/g, ' ').trim();
                    const matches = cleanIcon === cleanPlatform;
                    return matches;
                });
            }


            if (customIcon) {
                // Remove emoji from platform name when displaying with custom icon
                const platformWithoutEmoji = normalizeLabel(platform);
                return '<span style="display:inline-flex;align-items:center;gap:5px;"><span class="icon-img-wrap-sm"><img src="' + customIcon.iconUrl + '" alt="' + platform + '"></span>' + platformWithoutEmoji + '</span>';
            }
            return normalizeLabel(platform); // Return plain text if no custom icon
        }

        function getPlatformIcon(platform) {
            const customIcon = customIcons.find(icon => icon.platform === platform);
            if (customIcon) {
                return `<span class="icon-img-wrap-sm"><img src="${customIcon.iconUrl}" alt="${platform}"></span>`;
            }
            return '';
        }

        function collapseAllAddForms() {
            document.querySelectorAll('.add-form-collapsible.open').forEach(wrapper => {
                wrapper.classList.remove('open');
                if (wrapper.id) {
                    const btn = document.querySelector(`[data-toggle="${wrapper.id}"]`);
                    if (btn) btn.classList.remove('open');
                }
            });
        }

        function resetGameAddFormDraftOnSectionLeave() {
            if (window.editingGameId) return;
            const form = document.getElementById('game-form');
            if (!form) return;

            form.reset();
            const buyDateInput = document.getElementById('gm-buy-date');
            if (buyDateInput) buyDateInput.valueAsDate = new Date();

            setGameCoverPreview('gm', '', 'Click to add cover');
            const searchInput = document.getElementById('gm-catalog-search');
            if (searchInput) searchInput.value = '';
            gameCatalogLastApplied = null;
            gameCatalogLastSearchQuery = '';
            if (typeof window.closeGameCatalogResults === 'function') {
                window.closeGameCatalogResults();
            }
            if (typeof window.updateGameCatalogSearchHint === 'function') {
                window.updateGameCatalogSearchHint();
            }
        }
        window.resetGameAddFormDraftOnSectionLeave = resetGameAddFormDraftOnSectionLeave;

        // Section navigation
    window.showSection = function(section, el) {
    const previousActiveSection = document.querySelector('.section.active');
    const previousSectionId = previousActiveSection ? previousActiveSection.id : '';

    if (section === 'admin' && !isAdmin(currentUser)) {
        alert('Admin access only.');
        section = 'dashboard';
    }

    if (previousSectionId && previousSectionId !== section) {
        collapseAllAddForms();
        if (previousSectionId === 'games') {
            resetGameAddFormDraftOnSectionLeave();
        }
    }

    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const sectionElement = document.getElementById(section);
    if (sectionElement) {
        sectionElement.classList.add('active');
    }

    if (el) el.classList.add('active');

    // Sync desktop nav
    document.querySelectorAll('.desktop-nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.section === section) item.classList.add('active');
    });

    // Sync bottom nav
    document.querySelectorAll('.bottom-nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.section === section) item.classList.add('active');
    });

    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) sidebar.classList.remove('mobile-open');
    }

    if (section === 'admin') {
        syncPathForSection('admin');
    } else {
        syncPathForSection(section);
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
};

      // Gadget form handler (with sanitization)
document.getElementById('gadget-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    // Get submit button and show loading
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn ? submitBtn.textContent : '';
    
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Saving...';
    }

    try {
        const sellPrice = document.getElementById('g-sell-price').value;
        const sellDate = document.getElementById('g-sell-date').value;
        const imageUrl = document.getElementById('g-final-image-url').value;
        const condition = document.getElementById('g-condition').value;

        const gadget = {
            name: sanitizeText(document.getElementById('g-name').value),
            category: sanitizeText(document.getElementById('g-category').value),
            price: sanitizeNumber(parseFloat(document.getElementById('g-price').value)),
            date: document.getElementById('g-date').value,
            sellPrice: sellPrice ? sanitizeNumber(parseFloat(sellPrice)) : null,
            sellDate: sellDate || null,
            notes: sanitizeHTML(document.getElementById('g-notes').value),
            status: (sellPrice && sellDate) ? 'sold' : 'owned',
            imageUrl: imageUrl ? sanitizeURL(imageUrl) : null,
            condition: condition ? sanitizeText(condition) : null,
            timestamp: Date.now()
        };

        const gadgetToSave = await encryptData(gadget);
        
        // Check payload size before saving (keep under ~1MB for safety)
        const gadgetSize = new Blob([JSON.stringify(gadgetToSave)]).size;
        if (gadgetSize > 900000) { // 900KB to be safe
            throw new Error('Image is too large. Please use a smaller image.');
        }

        if (window.editingGadgetId) {
            // UPDATE existing gadget
            const editingGadgetId = window.editingGadgetId;
            await saveCloudflareCollectionItem('gadgets', gadget, editingGadgetId);
            window.editingGadgetId = null;
            if (submitBtn) submitBtn.textContent = 'Add to Collection';
        } else {
            // ADD new gadget
            await saveCloudflareCollectionItem('gadgets', gadget);
        }
        e.target.reset();
        document.getElementById('g-date').valueAsDate = new Date();

        // Reset image preview
        document.getElementById('g-final-image-url').value = '';
        const container = document.getElementById('g-image-preview-container');
        if (container) {
            container.innerHTML = `
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:#10b981;flex-shrink:0;"><rect x="7.2" y="2.5" width="9.6" height="19" rx="2.2"/><path d="M10 5.5h4"/><circle cx="12" cy="18.1" r="0.8" fill="currentColor" stroke="none"/><path d="M3.3 9.8h2.8"/><path d="M3.3 14.2h2.8"/><path d="M17.9 9.8h2.8"/><path d="M17.9 14.2h2.8"/></svg>
                <div style="font-size: 13px; color: var(--text-muted);">Click to add image</div>
            `;
        }
        
        // Re-enable button
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = originalBtnText;
        }

        // Close the add form
        const wrapper = document.getElementById('gadgets-add-wrapper');
        const btn = document.querySelector('[data-toggle="gadgets-add-wrapper"]');
        if (wrapper) { wrapper.classList.remove('open'); }
        if (btn) { btn.classList.remove('open'); }

    } catch (error) {
        // Re-enable button
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = originalBtnText;
        }
        
        // Show specific error message
        if (error.message && error.message.includes('too large')) {
            alert(error.message);
        } else if (isRequestTimeoutError(error)) {
            alert('Save is taking too long (network timeout). Please retry once your connection is stable.');
        } else if (error.code === 'permission-denied') {
            alert('Permission denied. Please check your login status.');
        } else {
            alert('Error adding gadget. Please try again.');
        }
    }
});

        // Gadget filter
        window.filterGadgets = function(event, filter) {
            currentGadgetFilter = filter;
            document.querySelectorAll('#gadgets .filter-chip').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            renderGadgets();
        };

        // Calculate ownership duration
        function calculateOwnershipDuration(buyDate, sellDate) {
            const start = new Date(buyDate);
            const end = sellDate ? new Date(sellDate) : new Date();

            const diffTime = Math.abs(end - start);
            const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));

            if (diffDays === 0) return 'Same day';
            if (diffDays === 1) return '1 day';
            if (diffDays < 30) return `${diffDays} days`;

            const diffMonths = Math.floor(diffDays / 30);
            const remainingDays = diffDays % 30;

            if (diffMonths === 1 && remainingDays === 0) return '1 month';
            if (diffMonths === 1) return `1 month, ${remainingDays} day${remainingDays > 1 ? 's' : ''}`;
            if (remainingDays === 0) return `${diffMonths} months`;
            return `${diffMonths} months, ${remainingDays} day${remainingDays > 1 ? 's' : ''}`;
        }

        // Global image-fit mode for card media
        const CARD_IMAGE_FIT_STORAGE_KEY = 'gearnest_card_image_fit_mode_v3';
        const CARD_IMAGE_FIT_MODES = {
            cover: 'cover',
            contain: 'contain'
        };
        let currentCardImageFitMode = CARD_IMAGE_FIT_MODES.cover;

        function normalizeCardImageFitMode(mode) {
            return mode === CARD_IMAGE_FIT_MODES.cover ? CARD_IMAGE_FIT_MODES.cover : CARD_IMAGE_FIT_MODES.contain;
        }

        function getSavedCardImageFitMode() {
            try {
                const saved = localStorage.getItem(CARD_IMAGE_FIT_STORAGE_KEY);
                return normalizeCardImageFitMode(saved);
            } catch (error) {
                return CARD_IMAGE_FIT_MODES.cover;
            }
        }

        function syncCardImageFitModeUI() {
            const coverBtn = document.getElementById('image-fit-cover-btn');
            const containBtn = document.getElementById('image-fit-contain-btn');
            const status = document.getElementById('image-fit-mode-status');
            const isContain = currentCardImageFitMode === CARD_IMAGE_FIT_MODES.contain;

            if (coverBtn) coverBtn.classList.toggle('active', !isContain);
            if (containBtn) containBtn.classList.toggle('active', isContain);
            if (status) {
                status.textContent = isContain
                    ? 'Contain mode keeps the full image visible with subtle padding.'
                    : 'Cover mode fills the frame and center-crops edges.';
            }
        }

        function setCardImageFitMode(mode, options = {}) {
            const fitMode = normalizeCardImageFitMode(mode);
            const persist = options.persist !== false;
            const rerender = options.rerender !== false;

            currentCardImageFitMode = fitMode;

            if (persist) {
                try {
                    localStorage.setItem(CARD_IMAGE_FIT_STORAGE_KEY, fitMode);
                } catch (error) {
                }
            }

            syncCardImageFitModeUI();

            if (rerender) {
                updateAll();
            }
        }

        window.setCardImageFitMode = setCardImageFitMode;

        document.addEventListener('DOMContentLoaded', function() {
            const coverBtn = document.getElementById('image-fit-cover-btn');
            const containBtn = document.getElementById('image-fit-contain-btn');

            if (coverBtn) {
                coverBtn.addEventListener('click', function() {
                    setCardImageFitMode(CARD_IMAGE_FIT_MODES.cover);
                });
            }

            if (containBtn) {
                containBtn.addEventListener('click', function() {
                    setCardImageFitMode(CARD_IMAGE_FIT_MODES.contain);
                });
            }

            setCardImageFitMode(getSavedCardImageFitMode(), { persist: false, rerender: false });
            window.updateGameCatalogSearchHint();

            document.addEventListener('click', function(event) {
                const searchWrap = document.getElementById('gm-catalog-search-wrap');
                if (!searchWrap || searchWrap.contains(event.target)) return;
                if (typeof window.closeGameCatalogResults === 'function') {
                    window.closeGameCatalogResults();
                }
            });
        });

        function getCardImageMarkup(imageUrl, altText, placeholderMarkup = '', options = {}) {
            const fitMode = normalizeCardImageFitMode(options.fitMode || currentCardImageFitMode);
            const shouldProxy = options.useProxy === true;
            const imageClass = fitMode === 'contain' ? 'product-image product-image--contain' : 'product-image product-image--cover';
            const safeSrc = imageUrl ? sanitizeURL(imageUrl) : '';

            if (safeSrc) {
                const resolvedSrc = shouldProxy ? getCORSProxyURL(safeSrc) : safeSrc;
                const fallbackSrc = safeSrc.replace(/'/g, "%27");
                const fallbackAttr = shouldProxy && resolvedSrc !== safeSrc
                    ? ` onerror="if(!this.dataset.fallbackDone){this.dataset.fallbackDone='1';this.src='${fallbackSrc}';}"`
                    : '';
                return `<img src="${resolvedSrc}" alt="${sanitizeText(altText || 'Item image')}" class="${imageClass}" loading="lazy"${fallbackAttr}>`;
            }

            return `<div class="product-image-placeholder" style="color:#10b981; display:flex; align-items:center; justify-content:center;">${placeholderMarkup}</div>`;
        }

        function getGamepadPlaceholderSvg(options = {}) {
            const sizeValue = Number(options.size);
            const strokeValue = Number(options.strokeWidth);
            const size = Number.isFinite(sizeValue) && sizeValue > 0 ? sizeValue : 30;
            const strokeWidth = Number.isFinite(strokeValue) && strokeValue > 0 ? strokeValue : 1.9;
            const style = typeof options.style === 'string' && options.style.trim() ? ` style="${options.style}"` : '';

            return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round"${style}><path d="M6.5 9.5h11a4.5 4.5 0 0 1 4.33 5.72l-.48 1.63A2.25 2.25 0 0 1 19.2 18.5h-1.08a2.5 2.5 0 0 1-2.17-1.26l-.74-1.28h-6.42l-.74 1.28A2.5 2.5 0 0 1 5.88 18.5H4.8a2.25 2.25 0 0 1-2.15-1.65l-.48-1.63A4.5 4.5 0 0 1 6.5 9.5Z"/><path d="M9 12.15v2.7"/><path d="M7.65 13.5h2.7"/><circle cx="15.8" cy="12.7" r="0.95" fill="currentColor" stroke="none"/><circle cx="18.1" cy="14.3" r="0.95" fill="currentColor" stroke="none"/></svg>`;
        }

        function getGadgetPlaceholderSvg(options = {}) {
            const sizeValue = Number(options.size);
            const strokeValue = Number(options.strokeWidth);
            const size = Number.isFinite(sizeValue) && sizeValue > 0 ? sizeValue : 30;
            const strokeWidth = Number.isFinite(strokeValue) && strokeValue > 0 ? strokeValue : 1.9;
            const style = typeof options.style === 'string' && options.style.trim() ? ` style="${options.style}"` : '';

            return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round"${style}><rect x="7.2" y="2.5" width="9.6" height="19" rx="2.2"/><path d="M10 5.5h4"/><circle cx="12" cy="18.1" r="0.8" fill="currentColor" stroke="none"/><path d="M3.3 9.8h2.8"/><path d="M3.3 14.2h2.8"/><path d="M17.9 9.8h2.8"/><path d="M17.9 14.2h2.8"/></svg>`;
        }

        function getDigitalPlaceholderSvg(options = {}) {
            const sizeValue = Number(options.size);
            const strokeValue = Number(options.strokeWidth);
            const size = Number.isFinite(sizeValue) && sizeValue > 0 ? sizeValue : 30;
            const strokeWidth = Number.isFinite(strokeValue) && strokeValue > 0 ? strokeValue : 1.9;
            const style = typeof options.style === 'string' && options.style.trim() ? ` style="${options.style}"` : '';

            return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round"${style}><rect x="2.5" y="4" width="19" height="16" rx="2.5"/><path d="M2.5 8.5h19"/><circle cx="6.1" cy="6.2" r="0.7" fill="currentColor" stroke="none"/><circle cx="9.1" cy="6.2" r="0.7" fill="currentColor" stroke="none"/><path d="m8.4 15.2 2.5 2.5 4.8-5"/></svg>`;
        }

        function getOwnedSoldBadgeMarkup(status, options = {}) {
            const normalizedStatus = status === 'sold' ? 'sold' : 'owned';
            const compactClass = options.compact === true ? ' status-badge--mini' : '';

            if (normalizedStatus === 'sold') {
                return `<span class="status-badge status-sold${compactClass}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>SOLD</span>`;
            }

            return `<span class="status-badge status-owned${compactClass}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>OWNED</span>`;
        }

        function getGameGenreIconSvg(genre, options = {}) {
            const sizeValue = Number(options.size);
            const strokeValue = Number(options.strokeWidth);
            const size = Number.isFinite(sizeValue) && sizeValue > 0 ? sizeValue : 11;
            const strokeWidth = Number.isFinite(strokeValue) && strokeValue > 0 ? strokeValue : 1.9;
            const cleanGenre = normalizeLabel(genre || '').toLowerCase();
            let paths = '<path d="M5.5 7.5h13a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-5l-3.5 3v-3h-4.5a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2z"/>';

            if (cleanGenre.includes('racing')) {
                paths = '<path d="M4 6h16v12H4z"/><path d="M4 10h16"/><path d="M8 6v4"/><path d="M12 10v8"/>';
            } else if (cleanGenre.includes('sports')) {
                paths = '<circle cx="12" cy="12" r="8"/><path d="M12 4v16"/><path d="M4 12h16"/><path d="M6.5 6.5l11 11"/><path d="M17.5 6.5l-11 11"/>';
            } else if (cleanGenre.includes('rpg') || cleanGenre.includes('adventure') || cleanGenre.includes('role')) {
                paths = '<circle cx="12" cy="12" r="9"/><path d="m12 8 3 4-3 4-3-4z"/><path d="M12 3v2"/><path d="M12 19v2"/><path d="M3 12h2"/><path d="M19 12h2"/>';
            } else if (cleanGenre.includes('action') || cleanGenre.includes('shooter') || cleanGenre.includes('fighting')) {
                paths = '<circle cx="12" cy="12" r="7"/><path d="M12 5v3"/><path d="M12 16v3"/><path d="M5 12h3"/><path d="M16 12h3"/>';
            } else if (cleanGenre.includes('puzzle') || cleanGenre.includes('strategy')) {
                paths = '<rect x="4" y="4" width="7.5" height="7.5" rx="1"/><rect x="12.5" y="4" width="7.5" height="7.5" rx="1"/><rect x="4" y="12.5" width="7.5" height="7.5" rx="1"/><path d="M12.5 16h7.5"/><path d="M16.25 12.5v7.5"/>';
            } else if (cleanGenre.includes('horror')) {
                paths = '<path d="M4 12s3-5 8-5 8 5 8 5-3 5-8 5-8-5-8-5z"/><circle cx="12" cy="12" r="2.5"/>';
            } else if (cleanGenre.includes('simulation')) {
                paths = '<line x1="5" y1="7" x2="19" y2="7"/><line x1="5" y1="12" x2="19" y2="12"/><line x1="5" y1="17" x2="19" y2="17"/><circle cx="9" cy="7" r="1.5"/><circle cx="15" cy="12" r="1.5"/><circle cx="11" cy="17" r="1.5"/>';
            } else if (cleanGenre.includes('music')) {
                paths = '<path d="M10 18V6l9-2v12"/><circle cx="7" cy="18" r="3"/><circle cx="19" cy="16" r="3"/>';
            } else if (cleanGenre.includes('platform')) {
                paths = '<rect x="4" y="14" width="6" height="6" rx="1"/><rect x="10" y="10" width="6" height="10" rx="1"/><rect x="16" y="6" width="4" height="14" rx="1"/>';
            }

            return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${strokeWidth}" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;
        }

        function getGameGenreBadgeMarkup(genre, options = {}) {
            const cleanGenre = normalizeLabel(genre || '');
            if (!cleanGenre) return '';
            const compactClass = options.compact === true ? ' game-genre-chip--compact' : '';
            return `<span class="item-category game-genre-chip${compactClass}">${getGameGenreIconSvg(cleanGenre)}<span>${sanitizeText(cleanGenre)}</span></span>`;
        }

        function getMetacriticBadgeMarkup(score, url, options = {}) {
            const cleanScore = normalizeMetacriticScore(score || '');
            if (!cleanScore) return '';
            const compactClass = options.compact === true ? ' metacritic-chip--compact' : '';
            const scoreMarkup = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 16h4l3-8 2 5h7"/></svg><span>MC ${sanitizeText(cleanScore)}</span>`;
            const safeUrl = sanitizeURL(url || '');
            if (safeUrl) {
                return `<a class="item-category metacritic-chip${compactClass}" href="${safeUrl}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation();">${scoreMarkup}</a>`;
            }
            return `<span class="item-category metacritic-chip${compactClass}">${scoreMarkup}</span>`;
        }

        function getMetacriticDetailMarkup(score, url) {
            const cleanScore = normalizeMetacriticScore(score || '');
            const safeUrl = sanitizeURL(url || '');
            if (!cleanScore && !safeUrl) return '';

            if (safeUrl) {
                const anchorText = cleanScore ? `MC ${cleanScore}` : 'Metacritic';
                return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation();" style="color:#fbbf24;text-decoration:none;">${sanitizeText(anchorText)}</a>`;
            }

            return sanitizeText(`MC ${cleanScore}`);
        }

        function getGameCoverPlaceholderMarkup(labelText) {
            const safeLabel = sanitizeText(labelText || 'Click to add cover');
            return `
                ${getGamepadPlaceholderSvg({ size: 22, strokeWidth: 2, style: 'color:#10b981;flex-shrink:0;' })}
                <div style="font-size: 13px; color: var(--text-muted);">${safeLabel}</div>
            `;
        }

        function setGameCoverPreview(prefix, imageUrl, labelText = 'Image added') {
            if (!prefix) return;
            const hiddenInput = document.getElementById(`${prefix}-final-image-url`);
            const container = document.getElementById(`${prefix}-image-preview-container`);
            const safeSrc = sanitizeURL(imageUrl || '');

            if (hiddenInput) hiddenInput.value = safeSrc;
            if (!container) return;

            if (safeSrc) {
                container.innerHTML = `
                    <img src="${safeSrc}" style="width: 40px; height: 40px; border-radius: 6px; object-fit: cover;">
                    <div style="font-size: 13px; color: var(--text-primary); flex: 1;">${sanitizeText(labelText)}</div>
                `;
            } else {
                container.innerHTML = getGameCoverPlaceholderMarkup('Click to add cover');
            }
        }

        function applyCatalogEntryToGameForm(entry) {
            if (!entry) return;

            const titleInput = document.getElementById('gm-title');
            const platformSelect = document.getElementById('gm-platform');
            const genreSelect = document.getElementById('gm-genre');
            const scoreInput = document.getElementById('gm-metacritic-score');
            const urlInput = document.getElementById('gm-metacritic-url');

            if (titleInput && entry.title) titleInput.value = entry.title;

            if (platformSelect && entry.platform) {
                if (!Array.from(platformSelect.options).some(option => option.value === entry.platform)) {
                    const opt = document.createElement('option');
                    opt.value = entry.platform;
                    opt.textContent = entry.platform;
                    platformSelect.appendChild(opt);
                }
                platformSelect.value = entry.platform;
                createCustomPlatformDropdown();
            }

            if (genreSelect && entry.genre) {
                if (!Array.from(genreSelect.options).some(option => option.value === entry.genre)) {
                    const opt = document.createElement('option');
                    opt.value = entry.genre;
                    opt.textContent = entry.genre;
                    genreSelect.appendChild(opt);
                }
                genreSelect.value = entry.genre;
            }

            if (scoreInput && entry.metacriticScore) scoreInput.value = entry.metacriticScore;
            if (urlInput && entry.metacriticUrl) urlInput.value = entry.metacriticUrl;
            if (entry.imageUrl) setGameCoverPreview('gm', entry.imageUrl, 'Cover from catalog');

            gameCatalogLastApplied = {
                title: normalizeLabel(entry.title || ''),
                platform: normalizeLabel(entry.platform || ''),
                genre: normalizeLabel(entry.genre || ''),
                metacriticScore: normalizeLabel(entry.metacriticScore || ''),
                metacriticUrl: sanitizeURL(entry.metacriticUrl || ''),
                imageUrl: sanitizeURL(entry.imageUrl || '')
            };
        }

        function applyCatalogFallbackToGameRecord(record) {
            const game = { ...record };
            const match = findBestGameMetadataMatch(game.title, game.platform);
            if (!match) return game;

            if (!game.metacriticScore && match.metacriticScore) {
                game.metacriticScore = match.metacriticScore;
            }
            if (!game.metacriticUrl && match.metacriticUrl) {
                game.metacriticUrl = match.metacriticUrl;
            }
            if (!game.imageUrl && match.imageUrl) {
                game.imageUrl = match.imageUrl;
            }
            return game;
        }

        let gameCatalogSearchResults = [];
        let gameCatalogDropdownOpen = false;
        let gameCatalogLastApplied = null;
        let gameCatalogLastSearchQuery = '';

        function buildGameCatalogSearchResults(query, limit = 24) {
            const cleanQuery = normalizeLabel(query || '').toLowerCase();
            if (gameMetadataCatalog.length === 0) return [];

            const ranked = gameMetadataCatalog
                .map(entry => {
                    const title = normalizeLabel(entry.title || '').toLowerCase();
                    const platform = normalizeLabel(entry.platform || '').toLowerCase();
                    const genre = normalizeLabel(entry.genre || '').toLowerCase();
                    let rank = 99;

                    if (!cleanQuery) {
                        rank = 10;
                    } else if (title === cleanQuery) {
                        rank = 0;
                    } else if (title.startsWith(cleanQuery)) {
                        rank = 1;
                    } else if (title.includes(cleanQuery)) {
                        rank = 2;
                    } else if (platform.includes(cleanQuery)) {
                        rank = 3;
                    } else if (genre.includes(cleanQuery)) {
                        rank = 4;
                    }

                    return { entry, rank };
                })
                .filter(item => item.rank < 99)
                .sort((a, b) => {
                    if (a.rank !== b.rank) return a.rank - b.rank;
                    const titleCompare = a.entry.title.localeCompare(b.entry.title);
                    if (titleCompare !== 0) return titleCompare;
                    return a.entry.platform.localeCompare(b.entry.platform);
                });

            if (!cleanQuery) {
                return gameMetadataCatalog.slice(0, limit);
            }

            return ranked.slice(0, limit).map(item => item.entry);
        }

        function renderGameCatalogResults(forceOpen = false) {
            const searchInput = document.getElementById('gm-catalog-search');
            const listEl = document.getElementById('gm-catalog-results');
            if (!searchInput || !listEl) return;

            if (forceOpen) {
                gameCatalogDropdownOpen = true;
            }

            const query = normalizeLabel(searchInput.value || '');
            gameCatalogSearchResults = buildGameCatalogSearchResults(query);
            const shouldShow = gameCatalogDropdownOpen;

            if (!shouldShow) {
                listEl.classList.remove('active');
                listEl.innerHTML = '';
                return;
            }

            if (gameMetadataCatalog.length === 0) {
                listEl.innerHTML = '<div class="custom-select-option game-catalog-result-empty">Admin can import metadata in Admin panel to enable game suggestions.</div>';
                listEl.classList.add('active');
                return;
            }

            if (gameCatalogSearchResults.length === 0) {
                listEl.innerHTML = '<div class="custom-select-option game-catalog-result-empty">No matching games found.</div>';
                listEl.classList.add('active');
                return;
            }

            listEl.innerHTML = gameCatalogSearchResults.map((entry, index) => {
                const metaParts = [entry.platform];
                if (entry.genre) metaParts.push(entry.genre);
                if (entry.metacriticScore) metaParts.push(`MC ${entry.metacriticScore}`);
                const selectedClass = index === 0 ? ' selected' : '';
                return `
                    <div class="custom-select-option game-catalog-result${selectedClass}" onclick="selectGameCatalogResult(${index})">
                        <span>${sanitizeText(entry.title)}</span>
                        <span class="game-catalog-result-meta">${sanitizeText(metaParts.join(' | '))}</span>
                    </div>
                `;
            }).join('');
            listEl.classList.add('active');
        }

        function refreshGameMetadataCatalogUI() {
            renderGameCatalogResults();
        }

        window.openGameCatalogResults = function() {
            const searchInput = document.getElementById('gm-catalog-search');
            if (searchInput && document.activeElement !== searchInput) {
                try {
                    searchInput.focus({ preventScroll: true });
                } catch (error) {
                    searchInput.focus();
                }
            }
            gameCatalogDropdownOpen = true;
            renderGameCatalogResults(true);
        };

        window.closeGameCatalogResults = function() {
            gameCatalogDropdownOpen = false;
            const listEl = document.getElementById('gm-catalog-results');
            if (listEl) {
                listEl.classList.remove('active');
                listEl.innerHTML = '';
            }
        };

        window.resetGameCatalogSelection = function(options = {}) {
            const config = options || {};
            const titleInput = document.getElementById('gm-title');
            const platformSelect = document.getElementById('gm-platform');
            const genreSelect = document.getElementById('gm-genre');
            const scoreInput = document.getElementById('gm-metacritic-score');
            const urlInput = document.getElementById('gm-metacritic-url');
            const searchInput = document.getElementById('gm-catalog-search');
            const hiddenImageInput = document.getElementById('gm-final-image-url');

            if (gameCatalogLastApplied) {
                if (titleInput && gameCatalogLastApplied.title && normalizeLabel(titleInput.value || '') === gameCatalogLastApplied.title) {
                    titleInput.value = '';
                }

                if (platformSelect && gameCatalogLastApplied.platform && normalizeLabel(platformSelect.value || '') === gameCatalogLastApplied.platform) {
                    if (platformSelect.options.length > 0) {
                        platformSelect.selectedIndex = 0;
                        createCustomPlatformDropdown();
                    }
                }

                if (genreSelect && gameCatalogLastApplied.genre && normalizeLabel(genreSelect.value || '') === gameCatalogLastApplied.genre) {
                    if (genreSelect.options.length > 0) {
                        genreSelect.selectedIndex = 0;
                    }
                }

                if (scoreInput && gameCatalogLastApplied.metacriticScore && normalizeLabel(scoreInput.value || '') === gameCatalogLastApplied.metacriticScore) {
                    scoreInput.value = '';
                }

                if (urlInput && gameCatalogLastApplied.metacriticUrl && sanitizeURL(urlInput.value || '') === gameCatalogLastApplied.metacriticUrl) {
                    urlInput.value = '';
                }

                const currentImageUrl = sanitizeURL(hiddenImageInput ? hiddenImageInput.value : '');
                if (gameCatalogLastApplied.imageUrl && currentImageUrl === gameCatalogLastApplied.imageUrl) {
                    setGameCoverPreview('gm', '', 'Click to add cover');
                }
            }

            if (!config.keepSearchValue && searchInput) {
                searchInput.value = '';
            }

            gameCatalogLastApplied = null;
            gameCatalogLastSearchQuery = '';
            if (config.keepDropdownOpen) {
                gameCatalogDropdownOpen = true;
                renderGameCatalogResults(true);
            } else {
                window.closeGameCatalogResults();
            }

            if (config.updateHint !== false) {
                window.updateGameCatalogSearchHint();
            }
        };

        window.selectGameCatalogResult = function(index) {
            const entry = gameCatalogSearchResults[index];
            if (!entry) return;
            applyCatalogEntryToGameForm(entry);
            const searchInput = document.getElementById('gm-catalog-search');
            if (searchInput) {
                searchInput.value = entry.title;
            }
            window.closeGameCatalogResults();
            window.updateGameCatalogSearchHint();
        };

        window.handleGameCatalogSearchKey = function(event) {
            if (event.key === 'Escape') {
                window.closeGameCatalogResults();
                return;
            }

            if (event.key === 'Enter') {
                if (gameCatalogSearchResults.length > 0) {
                    event.preventDefault();
                    window.selectGameCatalogResult(0);
                } else {
                    window.applyGameCatalogSearchSelection();
                }
            }
        };

        window.updateGameCatalogSearchHint = function() {
            const hint = document.getElementById('gm-catalog-match-hint');
            const searchInput = document.getElementById('gm-catalog-search');
            const titleInput = document.getElementById('gm-title');
            const platformSelect = document.getElementById('gm-platform');
            const searchQuery = normalizeLabel((searchInput && searchInput.value) || '');

            if (document.activeElement === searchInput) {
                gameCatalogDropdownOpen = true;
            }

            if (searchInput && searchQuery.length === 0 && gameCatalogLastSearchQuery.length > 0 && gameCatalogLastApplied) {
                const keepOpen = document.activeElement === searchInput;
                window.resetGameCatalogSelection({ keepSearchValue: true, updateHint: false, keepDropdownOpen: keepOpen });
            }
            gameCatalogLastSearchQuery = normalizeLabel((searchInput && searchInput.value) || '');

            refreshGameMetadataCatalogUI();
            if (!hint) return;

            const query = normalizeLabel((searchInput && searchInput.value) || (titleInput && titleInput.value) || '');
            if (!query) {
                hint.textContent = gameMetadataCatalog.length > 0
                    ? `Catalog ready. ${gameMetadataCatalog.length} game entries available.`
                    : 'Admin can import the game metadata catalog in Admin panel to enable quick auto-fill.';
                return;
            }

            const match = findBestGameMetadataMatch(query, platformSelect ? platformSelect.value : '', { allowPartial: true });
            if (!match) {
                hint.textContent = 'No catalog match found yet for this title.';
                return;
            }

            const parts = [match.title, match.platform];
            if (match.genre) parts.push(match.genre);
            if (match.metacriticScore) parts.push(`MC ${match.metacriticScore}`);
            if (match.imageUrl) parts.push('Cover URL ready');
            hint.textContent = `Best match: ${parts.join(' | ')}`;
        };

        window.applyGameCatalogSearchSelection = function() {
            const searchInput = document.getElementById('gm-catalog-search');
            const platformSelect = document.getElementById('gm-platform');
            const query = normalizeLabel(searchInput ? searchInput.value : '');
            if (!query) {
                window.updateGameCatalogSearchHint();
                return;
            }

            let match = findBestGameMetadataMatch(query, platformSelect ? platformSelect.value : '', { allowPartial: true });
            if (!match && gameCatalogSearchResults.length > 0) {
                match = gameCatalogSearchResults[0];
            }
            if (!match) {
                window.updateGameCatalogSearchHint();
                return;
            }

            applyCatalogEntryToGameForm(match);
            if (searchInput) searchInput.value = match.title;
            window.closeGameCatalogResults();
            window.updateGameCatalogSearchHint();
        };

        // Render gadgets
        function renderGadgets() {
    const container = document.getElementById('gadgets-list');

    // Filter gadgets based on currentGadgetFilter
    let filtered = gadgets;
    if (currentGadgetFilter === 'owned') filtered = gadgets.filter(g => g.status === 'owned');
    if (currentGadgetFilter === 'sold') filtered = gadgets.filter(g => g.status === 'sold');

    if (filtered.length === 0) {
        container.innerHTML = '<p style="text-align:center;color:#888;">No gadgets in this category yet.</p>';
        return;
    }

    container.innerHTML = filtered.map((g, index) => {
        const profit = g.sellPrice ? g.sellPrice - g.price : 0;
        const profitClass = profit > 0 ? 'profit-positive' : profit < 0 ? 'profit-negative' : '';
        const cardId = `gadget-card-${index}`;
        const duration = calculateOwnershipDuration(g.date, g.sellDate);
        const productImage = g.imageUrl;

        return `
            <div class="item-card" id="${cardId}" onclick="toggleCard('${cardId}')">
                <!-- Main Card Content (Always Visible) -->
                <div class="card-main">
                    <div style="width: 100%;">
                        <!-- Title Above Everything -->
                        <div class="item-title" style="margin-bottom: 12px;">${sanitizeText(g.name)}</div>

                        <!-- Content Row: Image + Info -->
                        <div style="display: flex; gap: 12px; align-items: flex-start;">
                            <!-- Product Image -->
                            ${getCardImageMarkup(productImage, g.name, getGadgetPlaceholderSvg({ size: 30, strokeWidth: 1.8 }), { useProxy: true })}

                            <!-- Info -->
                            <div style="flex: 1; min-width: 0;">
                                <div class="item-meta" style="margin-bottom: 8px;">
                                    <span class="item-category">${sanitizeText(normalizeLabel(g.category || ""))}</span>
                                </div>

                                <!-- Badges Row -->
                                <div class="badge-row">
                                    ${g.status === 'sold' ? `
                                    <span class="status-badge status-sold">
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> SOLD
                                    </span>
                                    <span class="status-badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border-color: rgba(239, 68, 68, 0.3);">
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:3px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Held for ${duration}
                                    </span>
                                    ` : `
                                    <span class="status-badge status-owned">
                                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Owned for ${duration}
                                    </span>
                                    `}
                                    ${g.condition ? `<span class="rating-badge">${g.condition}</span>` : ''}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Expandable Details Section -->
                <div class="card-details">
                    <div class="item-info">
                        <div class="info-row">
                            <span class="info-label">Purchase Price</span>
                            <span class="info-value">${currentCurrency}${sanitizeNumber(g.price).toLocaleString()}</span>
                        </div>
                        ${g.condition ? `
                        <div class="info-row">
                            <span class="info-label">Condition</span>
                            <span class="info-value">${sanitizeText(g.condition)}</span>
                        </div>
                        ` : ''}
                        ${g.sellPrice ? `
                        <div class="info-row">
                            <span class="info-label">Sell Price</span>
                            <span class="info-value">${currentCurrency}${sanitizeNumber(g.sellPrice).toLocaleString()}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Profit/Loss</span>
                            <span class="info-value ${profitClass}">${currentCurrency}${profit.toLocaleString()}</span>
                        </div>
                        ` : ''}
                        <div class="info-row">
                            <span class="info-label">Purchase Date</span>
                            <span class="info-value">${new Date(g.date).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</span>
                        </div>
                        ${g.sellDate ? `
                        <div class="info-row">
                            <span class="info-label">Sell Date</span>
                            <span class="info-value">${new Date(g.sellDate).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</span>
                        </div>
                        ` : ''}
                        ${g.notes ? `
                        <div class="info-row">
                            <span class="info-label">Notes</span>
                            <span class="info-value">${sanitizeHTML(g.notes)}</span>
                        </div>
                        ` : ''}
                    </div>

                    <!-- Action Buttons -->
                    <div style="display: flex; gap: 12px; margin-top: 16px;" onclick="event.stopPropagation();">
                        <button class="btn-edit" onclick="editGadget('${g.firestoreId}')" style="flex: 1;">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>Edit
                        </button>
                        <button class="btn-delete" onclick="deleteGadget('${g.firestoreId}', '${sanitizeText(g.name).replace(/'/g, "\\'")}')" style="flex: 1;">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>Delete
                        </button>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

        // Delete gadget with confirmation
        window.deleteGadget = function(firestoreId, name) {
            document.getElementById('deleteMessage').textContent =
                `Are you sure you want to delete "${name}"? This action cannot be undone.`;
            const modal = document.getElementById('deleteModal');
            modal.classList.add('active');
            modal.style.display = 'flex';

            deleteCallback = async () => {
                try {
                    await deleteCloudflareCollectionItem('gadgets', firestoreId);
                } catch (error) {
                    alert('Error deleting gadget. Please try again.');
                }
            };
        };

        // Edit gadget
        window.editGadget = function(firestoreId) {
            const gadget = gadgets.find(g => g.firestoreId === firestoreId);
            if (!gadget) return;

            // Populate modal form
            document.getElementById('edit-g-name').value = gadget.name;
            document.getElementById('edit-g-category').value = gadget.category;
            document.getElementById('edit-g-price').value = gadget.price;
            document.getElementById('edit-g-date').value = gadget.date;
            document.getElementById('edit-g-sell-price').value = gadget.sellPrice || '';
            document.getElementById('edit-g-sell-date').value = gadget.sellDate || '';
            document.getElementById('edit-g-condition').value = gadget.condition || '';
            document.getElementById('edit-g-notes').value = gadget.notes || '';

            // Populate image if exists
            const imageUrl = gadget.imageUrl || '';
            document.getElementById('edit-g-final-image-url').value = imageUrl;
            const container = document.getElementById('edit-g-image-preview-container');
            if (imageUrl) {
                container.innerHTML = `
                    <img src="${imageUrl}" style="width: 40px; height: 40px; border-radius: 6px; object-fit: cover;">
                    <div style="font-size: 13px; color: var(--text-primary); flex: 1;">Image added</div>
                `;
            } else {
                container.innerHTML = `
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:#10b981;flex-shrink:0;"><rect x="7.2" y="2.5" width="9.6" height="19" rx="2.2"/><path d="M10 5.5h4"/><circle cx="12" cy="18.1" r="0.8" fill="currentColor" stroke="none"/><path d="M3.3 9.8h2.8"/><path d="M3.3 14.2h2.8"/><path d="M17.9 9.8h2.8"/><path d="M17.9 14.2h2.8"/></svg>
                    <div style="font-size: 13px; color: var(--text-muted);">Click to add/change image</div>
                `;
            }

            // Store editing ID
            window.editingGadgetId = firestoreId;

            // Show modal
            const modal = document.getElementById('gadgetEditModal');
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('active'), 10);
        };

        window.closeGadgetEditModal = function() {
            const modal = document.getElementById('gadgetEditModal');
            modal.classList.remove('active');
            setTimeout(() => modal.style.display = 'none', 200);
            window.editingGadgetId = null;
        };

        window.updateGadgetFromModal = async function(e) {
            e.preventDefault();

            // Get submit button and show loading
            const submitBtn = e.target.querySelector('button[type="submit"]');
            const originalBtnText = submitBtn ? submitBtn.innerHTML : '';
            
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = 'Saving...';
            }

            try {
                const hiddenInput = document.getElementById('edit-g-final-image-url');
                const sellPrice = document.getElementById('edit-g-sell-price').value;
                const sellDate = document.getElementById('edit-g-sell-date').value;
                const imageUrl = hiddenInput ? hiddenInput.value : '';
                const condition = document.getElementById('edit-g-condition').value;

                const gadget = {
                    name: sanitizeText(document.getElementById('edit-g-name').value),
                    category: sanitizeText(document.getElementById('edit-g-category').value),
                    price: sanitizeNumber(parseFloat(document.getElementById('edit-g-price').value)),
                    date: document.getElementById('edit-g-date').value,
                    sellPrice: sellPrice ? sanitizeNumber(parseFloat(sellPrice)) : null,
                    sellDate: sellDate || null,
                    notes: sanitizeHTML(document.getElementById('edit-g-notes').value),
                    status: (sellPrice && sellDate) ? 'sold' : 'owned',
                    imageUrl: imageUrl ? sanitizeURL(imageUrl) : null,
                    condition: condition ? sanitizeText(condition) : null,
                    timestamp: Date.now()
                };

                const gadgetToSave = await encryptData(gadget);
                
                // Check payload size before saving (keep under ~1MB for safety)
                const gadgetSize = new Blob([JSON.stringify(gadgetToSave)]).size;
                if (gadgetSize > 900000) { // 900KB to be safe
                    throw new Error('Image is too large. Please use a smaller image.');
                }
                
                const gadgetIdToUpdate = window.editingGadgetId;
                await saveCloudflareCollectionItem('gadgets', gadget, gadgetIdToUpdate);
                closeGadgetEditModal();
            } catch (error) {
                // Re-enable button
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalBtnText;
                }
                
                // Show specific error message
                if (error.message && error.message.includes('too large')) {
                    alert(error.message);
                } else if (isRequestTimeoutError(error)) {
                    alert('Save is taking too long (network timeout). Please retry once your connection is stable.');
                } else if (error.code === 'permission-denied') {
                    alert('Permission denied. Please check your login status.');
                } else {
                    alert('Error updating gadget. Please try again.');
                }
            }
        };

        // Game form handler
        document.getElementById('game-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const sellPrice = document.getElementById('gm-sell-price').value;
            const sellDate = document.getElementById('gm-sell-date').value;
            const imageUrl = document.getElementById('gm-final-image-url').value;

            let game = {
                title: sanitizeText(document.getElementById('gm-title').value),
                platform: sanitizeText(document.getElementById('gm-platform').value),
                genre: sanitizeText(document.getElementById('gm-genre').value),
                buyPrice: sanitizeNumber(parseFloat(document.getElementById('gm-buy-price').value)),
                buyDate: document.getElementById('gm-buy-date').value,
                condition: sanitizeText(document.getElementById('gm-condition').value),
                sellPrice: sellPrice ? sanitizeNumber(parseFloat(sellPrice)) : null,
                sellDate: sellDate || null,
                notes: sanitizeHTML(document.getElementById('gm-notes').value),
                status: (sellPrice && sellDate) ? 'sold' : 'owned',
                imageUrl: imageUrl ? sanitizeURL(imageUrl) : null,
                metacriticScore: normalizeMetacriticScore(document.getElementById('gm-metacritic-score').value),
                metacriticUrl: sanitizeURL(document.getElementById('gm-metacritic-url').value),
                timestamp: Date.now()
            };

            game = applyCatalogFallbackToGameRecord(game);

            try {
                if (window.editingGameId) {

    // UPDATE existing game (do NOT delete)
    const editingGameId = window.editingGameId;
    await saveCloudflareCollectionItem('games', game, editingGameId);

    window.editingGameId = null;
    document.querySelector('#game-form .btn').textContent = 'Add to Collection';

} else {

    // ADD new game
    await saveCloudflareCollectionItem('games', game);
}
e.target.reset();
document.getElementById('gm-buy-date').valueAsDate = new Date();

// Reset image preview
setGameCoverPreview('gm', '', 'Click to add cover');
const searchInput = document.getElementById('gm-catalog-search');
if (searchInput) searchInput.value = '';
gameCatalogLastApplied = null;
gameCatalogLastSearchQuery = '';
window.updateGameCatalogSearchHint();

// Close the add form
const gamesWrapper = document.getElementById('games-add-wrapper');
const gamesBtn = document.querySelector('[data-toggle="games-add-wrapper"]');
if (gamesWrapper) { gamesWrapper.classList.remove('open'); }
if (gamesBtn) { gamesBtn.classList.remove('open'); }

            } catch (error) {
                alert('Error adding game. Please try again.');
            }
        });

        // Filter games
        window.filterGames = function(event, filter) {
            currentFilter = filter;
            document.querySelectorAll('#games .filter-chip').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            renderGames();
        };

        // Render games
        function renderGames() {
            const container = document.getElementById('games-list');
            let filtered = games;

            if (currentFilter === 'owned') filtered = games.filter(g => g.status === 'owned');
            if (currentFilter === 'sold') filtered = games.filter(g => g.status === 'sold');

            if (filtered.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">${getGamepadPlaceholderSvg({ size: 48, strokeWidth: 1.5, style: 'opacity:0.4;' })}</div>
                        <p>No games in this category yet!</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = filtered.map((g, index) => {
                const profit = g.sellPrice ? g.sellPrice - g.buyPrice : 0;
                const profitClass = profit > 0 ? 'profit-positive' : profit < 0 ? 'profit-negative' : '';
                const duration = calculateOwnershipDuration(g.buyDate, g.sellDate);
                const platformDisplay = getPlatformDisplay(g.platform);
                const genreDisplay = normalizeLabel(g.genre || "");
                const metacriticBadge = getMetacriticBadgeMarkup(g.metacriticScore, g.metacriticUrl);
                const metacriticDetails = getMetacriticDetailMarkup(g.metacriticScore, g.metacriticUrl);
                const cardId = `game-card-${index}`;

                return `
                    <div class="item-card" id="${cardId}" onclick="toggleCard('${cardId}')">
                        <!-- Main Card Content (Always Visible) -->
                        <div class="card-main">
                            <div style="width: 100%;">
                                <!-- Title Above Everything -->
                                <div class="item-title" style="margin-bottom: 12px;">${sanitizeText(g.title)}</div>

                                <!-- Content Row: Image + Info -->
                                <div style="display: flex; gap: 12px; align-items: flex-start;">
                                    <!-- Game Cover Image -->
                                    ${getCardImageMarkup(g.imageUrl, g.title, getGamepadPlaceholderSvg({ size: 32, strokeWidth: 1.8 }), { useProxy: true })}

                                    <!-- Info -->
                                    <div style="flex: 1; min-width: 0;">
                                        <div class="item-meta" style="margin-bottom: 8px; display: flex; gap: 8px; flex-wrap: wrap;">
                                            <span class="item-category">${platformDisplay}</span>
                                            ${g.genre ? getGameGenreBadgeMarkup(genreDisplay) : ''}
                                            ${metacriticBadge}
                                        </div>

                                        <!-- Badges Row -->
                                        <div class="badge-row">
                                            ${g.status === 'sold' ? `
                                            <span class="status-badge status-sold">
                                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg> SOLD
                                            </span>
                                            <span class="status-badge" style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border-color: rgba(239, 68, 68, 0.3);">
                                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:3px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>Held for ${duration}
                                            </span>
                                            ` : `
                                            <span class="status-badge status-owned">
                                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg> Owned for ${duration}
                                            </span>
                                            `}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Expandable Details Section -->
                        <div class="card-details">
                            <div class="item-info">
                                <div class="info-row">
                                    <span class="info-label">Buy Price</span>
                                    <span class="info-value">₹${g.buyPrice.toFixed(2)}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Condition</span>
                                    <span class="info-value">${sanitizeText(g.condition)}</span>
                                </div>
                                ${g.sellPrice ? `
                                <div class="info-row">
                                    <span class="info-label">Sell Price</span>
                                    <span class="info-value">₹${g.sellPrice.toFixed(2)}</span>
                                </div>
                                <div class="info-row">
                                    <span class="info-label">Profit/Loss</span>
                                    <span class="info-value ${profitClass}">₹${profit.toFixed(2)}</span>
                                </div>
                                ` : ''}
                                <div class="info-row">
                                    <span class="info-label">Bought</span>
                                    <span class="info-value">${new Date(g.buyDate).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</span>
                                </div>
                                ${g.sellDate ? `
                                <div class="info-row">
                                    <span class="info-label">Sold</span>
                                    <span class="info-value">${new Date(g.sellDate).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</span>
                                </div>
                                ` : ''}
                                ${metacriticDetails ? `
                                <div class="info-row">
                                    <span class="info-label">Metacritic</span>
                                    <span class="info-value">${metacriticDetails}</span>
                                </div>
                                ` : ''}
                                ${g.notes ? `
                                <div class="info-row">
                                    <span class="info-label">Notes</span>
                                    <span class="info-value">${sanitizeHTML(g.notes)}</span>
                                </div>
                                ` : ''}
                            </div>

                            <!-- Action Buttons -->
                            <div style="display: flex; gap: 12px; margin-top: 16px;" onclick="event.stopPropagation();">
                                <button class="btn-edit" onclick="editGame('${g.firestoreId}')" style="flex: 1;">
                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>Edit
                                </button>
                                <button class="btn-delete" onclick="deleteGame('${g.firestoreId}', '${sanitizeText(g.title).replace(/'/g, "\\'")}')" style="flex: 1;">
                                    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>Delete
                                </button>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        // Delete game with confirmation
        window.deleteGame = function(firestoreId, title) {
            document.getElementById('deleteMessage').textContent =
                `Are you sure you want to delete "${title}"? This action cannot be undone.`;
            const modal = document.getElementById('deleteModal');
            modal.classList.add('active');
            modal.style.display = 'flex';

            deleteCallback = async () => {
                try {
                    await deleteCloudflareCollectionItem('games', firestoreId);
                } catch (error) {
                    alert('Error deleting game. Please try again.');
                }
            };
        };

        // Edit game
        window.editGame = function(firestoreId) {
            const game = games.find(g => g.firestoreId === firestoreId);
            if (!game) return;

            // Populate modal form
            document.getElementById('edit-gm-title').value = game.title;
            document.getElementById('edit-gm-platform').value = game.platform;
            document.getElementById('edit-gm-genre').value = normalizeLabel(game.genre || 'Action') || 'Action';
            document.getElementById('edit-gm-buy-price').value = game.buyPrice;
            document.getElementById('edit-gm-buy-date').value = game.buyDate;
            document.getElementById('edit-gm-condition').value = game.condition;
            document.getElementById('edit-gm-sell-price').value = game.sellPrice || '';
            document.getElementById('edit-gm-sell-date').value = game.sellDate || '';
            document.getElementById('edit-gm-notes').value = game.notes || '';
            document.getElementById('edit-gm-metacritic-score').value = normalizeMetacriticScore(game.metacriticScore || '');
            document.getElementById('edit-gm-metacritic-url').value = sanitizeURL(game.metacriticUrl || '');

            // Populate image preview
            const editGmImageUrl = game.imageUrl || '';
            document.getElementById('edit-gm-final-image-url').value = editGmImageUrl;
            const editGmContainer = document.getElementById('edit-gm-image-preview-container');
            if (editGmContainer) {
                if (editGmImageUrl) {
                    editGmContainer.innerHTML = `
                        <img src="${editGmImageUrl}" style="width: 40px; height: 40px; border-radius: 6px; object-fit: cover;">
                        <div style="font-size: 13px; color: var(--text-primary); flex: 1;">Cover added</div>
                    `;
                } else {
                    editGmContainer.innerHTML = `
                        ${getGamepadPlaceholderSvg({ size: 22, strokeWidth: 2, style: 'color:#10b981;flex-shrink:0;' })}
                        <div style="font-size: 13px; color: var(--text-muted);">Click to add/change cover</div>
                    `;
                }
            }

            // Store editing ID
            window.editingGameId = firestoreId;

            // Show modal
            const modal = document.getElementById('gameEditModal');
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('active'), 10);
        };

        window.closeGameEditModal = function() {
            const modal = document.getElementById('gameEditModal');
            modal.classList.remove('active');
            setTimeout(() => modal.style.display = 'none', 200);
            window.editingGameId = null;
        };

        window.updateGameFromModal = async function(e) {
            e.preventDefault();

            const sellPrice = document.getElementById('edit-gm-sell-price').value;
            const sellDate = document.getElementById('edit-gm-sell-date').value;
            const editGmImageUrl = document.getElementById('edit-gm-final-image-url').value;

            let game = {
                title: sanitizeText(document.getElementById('edit-gm-title').value),
                platform: sanitizeText(document.getElementById('edit-gm-platform').value),
                genre: sanitizeText(document.getElementById('edit-gm-genre').value),
                condition: document.getElementById('edit-gm-condition').value,
                buyPrice: sanitizeNumber(parseFloat(document.getElementById('edit-gm-buy-price').value)),
                buyDate: document.getElementById('edit-gm-buy-date').value,
                sellPrice: sellPrice ? sanitizeNumber(parseFloat(sellPrice)) : null,
                sellDate: sellDate || null,
                notes: sanitizeHTML(document.getElementById('edit-gm-notes').value),
                imageUrl: editGmImageUrl ? sanitizeURL(editGmImageUrl) : null,
                metacriticScore: normalizeMetacriticScore(document.getElementById('edit-gm-metacritic-score').value),
                metacriticUrl: sanitizeURL(document.getElementById('edit-gm-metacritic-url').value),
                status: (sellPrice && sellDate) ? 'sold' : 'owned',
                timestamp: Date.now()
            };

            game = applyCatalogFallbackToGameRecord(game);

            try {
                const gameIdToUpdate = window.editingGameId;
                await saveCloudflareCollectionItem('games', game, gameIdToUpdate);
                closeGameEditModal();
            } catch (error) {
                alert('Error updating game. Please try again.');
            }
        };

        // Modal functions
        window.closeDeleteModal = function() {
            const modal = document.getElementById('deleteModal');
            modal.classList.remove('active');
            modal.style.display = 'none';
            deleteCallback = null;
        };

        window.confirmDelete = async function() {
            if (deleteCallback) {
                try {
                    await deleteCallback();
                } catch (error) {
                    alert('Error deleting item. Please try again.');
                } finally {
                    // Always close the modal, even if there's an error
                    window.closeDeleteModal();
                }
            }
        };

        // Update dashboard
        function updateDashboard(options = {}) {
            const skipRecentItems = options.skipRecentItems === true;
            // Gadgets stats (single pass)
            const totalGadgets = gadgets.length;
            let soldGadgetsCount = 0;
            let currentGadgetsValue = 0;
            let gadgetsProfit = 0;
            for (const g of gadgets) {
                const status = g.status || ((g.sellPrice && g.sellDate) ? 'sold' : 'owned');
                const price = sanitizeNumber(g.price);
                if (status === 'sold') {
                    soldGadgetsCount += 1;
                    gadgetsProfit += sanitizeNumber(g.sellPrice) - price;
                } else {
                    currentGadgetsValue += price;
                }
            }

            // Games stats (single pass)
            const totalGames = games.length;
            let soldGamesCount = 0;
            let currentGamesValue = 0;
            let gamesProfit = 0;
            for (const g of games) {
                const status = g.status || ((g.sellPrice && g.sellDate) ? 'sold' : 'owned');
                const buyPrice = sanitizeNumber(g.buyPrice);
                if (status === 'sold') {
                    soldGamesCount += 1;
                    gamesProfit += sanitizeNumber(g.sellPrice) - buyPrice;
                } else {
                    currentGamesValue += buyPrice;
                }
            }

            // Digital purchases stats
            const totalDigital = digitalPurchases.length;
            let digitalSpent = 0;
            for (const d of digitalPurchases) {
                digitalSpent += sanitizeNumber(d.amount);
            }

            // Update dashboard
            document.getElementById('dash-total-gadgets').textContent = totalGadgets;
            document.getElementById('dash-gadgets-value').textContent = `₹${currentGadgetsValue.toFixed(0)}`;
            document.getElementById('dash-gadgets-sold').textContent = soldGadgetsCount;
            document.getElementById('dash-gadgets-profit').textContent = `₹${gadgetsProfit.toFixed(0)}`;

            document.getElementById('dash-total-games').textContent = totalGames;
            document.getElementById('dash-games-value').textContent = `₹${currentGamesValue.toFixed(0)}`;
            document.getElementById('dash-games-sold').textContent = soldGamesCount;
            document.getElementById('dash-games-profit-stat').textContent = `₹${gamesProfit.toFixed(0)}`;

            document.getElementById('dash-total-digital').textContent = totalDigital;
            document.getElementById('dash-digital-spent').textContent = `₹${digitalSpent.toFixed(0)}`;

            // Total profit/loss
            const totalProfit = gadgetsProfit + gamesProfit;
            document.getElementById('dash-total-profit').textContent = `₹${totalProfit.toFixed(0)}`;

            // Color code profit/loss
            const profitElements = [
                document.getElementById('dash-gadgets-profit'),
                document.getElementById('dash-games-profit-stat'),
                document.getElementById('dash-total-profit')
            ];

            profitElements.forEach((el, idx) => {
                const value = idx === 0 ? gadgetsProfit : idx === 1 ? gamesProfit : totalProfit;
                if (value > 0) {
                    el.style.color = '#4CAF50';
                } else if (value < 0) {
                    el.style.color = '#f44336';
                } else {
                    el.style.color = '#00f5ff';
                }
            });

            if (skipRecentItems) {
                return;
            }

            // Recent items (top-6 without sorting full dataset)
            const recentLimit = 6;
            const recent = [];

            const insertRecentItem = function(item) {
                const candidateTimestamp = sanitizeNumber(item && item.timestamp);
                let insertAt = recent.length;

                for (let i = 0; i < recent.length; i++) {
                    const rowTimestamp = sanitizeNumber(recent[i].timestamp);
                    if (candidateTimestamp > rowTimestamp) {
                        insertAt = i;
                        break;
                    }
                }

                if (insertAt >= recentLimit) {
                    return;
                }

                recent.splice(insertAt, 0, item);
                if (recent.length > recentLimit) {
                    recent.pop();
                }
            };

            gadgets.forEach(insertRecentItem);
            games.forEach(insertRecentItem);
            digitalPurchases.forEach(insertRecentItem);

            const recentContainer = document.getElementById('recent-items');
            if (recent.length === 0) {
                recentContainer.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="opacity:0.4;"><path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/></svg></div>
                        <p>Start adding gadgets and games to build your collection!</p>
                    </div>
                `;
            } else {
                recentContainer.innerHTML = recent.map(item => {
                    if (item.title) {
                        // Game item
                        const duration = calculateOwnershipDuration(item.buyDate, item.sellDate);
                        const status = item.status || 'owned';
                        return `
                            <div class="item-card" style="display: flex; gap: 16px; align-items: flex-start;">
                                ${getCardImageMarkup(item.imageUrl, item.title, getGamepadPlaceholderSvg({ size: 30, strokeWidth: 1.8 }))}
                                <div style="flex: 1; min-width: 0;">
                                    <div class="item-title">${item.title}</div>
                                    <div class="item-meta" style="margin-bottom:0;display:flex;gap:6px;flex-wrap:wrap;align-items:center;">
                                        <span class="item-category" style="white-space:nowrap;">${sanitizeText(normalizeLabel(item.platform || ''))}</span>
                                        ${item.genre ? getGameGenreBadgeMarkup(item.genre, { compact: true }) : ''}
                                        ${getMetacriticBadgeMarkup(item.metacriticScore, item.metacriticUrl, { compact: true })}
                                        ${getOwnedSoldBadgeMarkup(status, { compact: true })}
                                    </div>
                                    <div style="margin-top: 15px;">
                                        <div class="info-label">Buy Price</div>
                                        <div class="price-tag">₹${sanitizeNumber(item.buyPrice).toFixed(2)}</div>
                                    </div>
                                    <div style="margin-top: 10px;">
                                        <div class="info-label">${status === 'sold' ? 'Held For' : 'Owned For'}</div>
                                        <div style="color: #00f5ff; font-size: 13px; font-weight: 600; margin-top: 5px; display:flex; align-items:center; gap:4px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${duration}</div>
                                    </div>
                                </div>
                            </div>
                        `;
                    } else if (item.type) {
                        // Digital purchase item
                        return `
                            <div class="item-card" style="display: flex; gap: 16px; align-items: flex-start;">
                                ${getCardImageMarkup(item.imageUrl, item.name, getDigitalPlaceholderSvg({ size: 30, strokeWidth: 1.8 }))}
                                <div style="flex: 1; min-width: 0;">
                                    <div class="item-title">${item.name}</div>
                                    <span class="item-category">${sanitizeText(normalizeLabel(item.type || ""))}</span>
                                    <div style="margin-top: 15px;">
                                        <div class="info-label">Amount</div>
                                        <div class="price-tag">₹${sanitizeNumber(item.amount).toFixed(2)}</div>
                                    </div>
                                    ${item.expiryDate ? `
                                    <div style="margin-top: 10px;">
                                        <div class="info-label">Expires</div>
                                        <div style="color: #ffaa00; font-size: 13px; font-weight: 600; margin-top: 5px;">${new Date(item.expiryDate).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</div>
                                    </div>
                                    ` : ''}
                                </div>
                            </div>
                        `;
                    } else {
                        // Gadget item
                        const duration = calculateOwnershipDuration(item.date, item.sellDate);
                        const status = item.status || 'owned';
                        return `
                            <div class="item-card" style="display: flex; gap: 16px; align-items: flex-start;">
                                ${getCardImageMarkup(item.imageUrl, item.name, getGadgetPlaceholderSvg({ size: 30, strokeWidth: 1.8 }))}
                                <div style="flex: 1; min-width: 0;">
                                    <div class="item-title">${item.name}</div>
                                    <span class="item-category">${sanitizeText(normalizeLabel(item.category || ""))}</span>
                                    ${getOwnedSoldBadgeMarkup(status, { compact: true })}
                                    <div style="margin-top: 15px;">
                                        <div class="info-label">Price</div>
                                        <div class="price-tag">₹${sanitizeNumber(item.price).toFixed(2)}</div>
                                    </div>
                                    <div style="margin-top: 10px;">
                                        <div class="info-label">${status === 'sold' ? 'Held For' : 'Owned For'}</div>
                                        <div style="color: #00f5ff; font-size: 13px; font-weight: 600; margin-top: 5px; display:flex; align-items:center; gap:4px;"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${duration}</div>
                                    </div>
                                </div>
                            </div>
                        `;
                    }
                }).join('');
            }
        }

        let renderPassToken = 0;
        function updateAll() {
            const currentRenderToken = ++renderPassToken;

            const activeSection = document.querySelector('.section.active');
            const activeSectionId = activeSection ? activeSection.id : '';

            // Render dashboard stats immediately. Skip recent-items list unless dashboard is open.
            updateDashboard({ skipRecentItems: activeSectionId !== 'dashboard' });

            if (activeSectionId === 'gadgets') {
                renderGadgets();
            } else if (activeSectionId === 'games') {
                renderGames();
            } else if (activeSectionId === 'digital') {
                renderDigital();
            }

            const renderRemainingSections = function() {
                if (currentRenderToken !== renderPassToken) return;
                if (activeSectionId !== 'gadgets') renderGadgets();
                if (activeSectionId !== 'games') renderGames();
                if (activeSectionId !== 'digital') renderDigital();
            };

            if (typeof requestIdleCallback === 'function') {
                requestIdleCallback(renderRemainingSections, { timeout: 250 });
            } else {
                setTimeout(renderRemainingSections, 0);
            }
        }

        // Toggle custom validity input
        window.toggleCustomValidity = function() {
            const validitySelect = document.getElementById('d-validity');
            const customGroup = document.getElementById('custom-validity-group');

            if (validitySelect.value === 'custom') {
                customGroup.style.display = 'block';
            } else {
                customGroup.style.display = 'none';
            }
        };

        // Digital purchases form handler
        document.getElementById('digital-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const purchaseDate = document.getElementById('d-date').value;
            const validityPeriod = document.getElementById('d-validity').value;

            // Calculate expiry date and duration based on validity period
            let expiryDate = null;
            let duration = null;

            if (validityPeriod) {
                const startDate = new Date(purchaseDate);
                let months = 0;

                if (validityPeriod === 'custom') {
                    months = parseInt(document.getElementById('d-custom-months').value) || 0;
                } else {
                    months = parseInt(validityPeriod);
                }

                if (months > 0) {
                    // Calculate expiry date by adding months
                    const endDate = new Date(startDate);
                    endDate.setMonth(endDate.getMonth() + months);
                    expiryDate = endDate.toISOString().split('T')[0];

                    // Format duration text
                    if (months >= 12) {
                        const years = Math.floor(months / 12);
                        const remainingMonths = months % 12;
                        if (remainingMonths === 0) {
                            duration = `${years} year${years > 1 ? 's' : ''}`;
                        } else {
                            duration = `${years} year${years > 1 ? 's' : ''} ${remainingMonths} month${remainingMonths > 1 ? 's' : ''}`;
                        }
                    } else {
                        duration = `${months} month${months > 1 ? 's' : ''}`;
                    }
                }
            }

            const digital = {
                name: document.getElementById('d-name').value,
                type: document.getElementById('d-type').value,
                amount: parseFloat(document.getElementById('d-amount').value),
                date: purchaseDate,
                duration: duration,
                expiryDate: expiryDate,
                imageUrl: document.getElementById('d-final-image-url').value || '',
                notes: document.getElementById('d-notes').value,
                timestamp: Date.now()
            };

            try {
               if (window.editingDigitalId) {

                const editingDigitalId = window.editingDigitalId;
                await saveCloudflareCollectionItem('digitalPurchases', digital, editingDigitalId);

                window.editingDigitalId = null;
                document.querySelector('#digital-form .btn').textContent = 'Add Purchase';

                } else {

                await saveCloudflareCollectionItem('digitalPurchases', digital);
            }
            e.target.reset();
            document.getElementById('d-date').valueAsDate = new Date();
            document.getElementById('custom-validity-group').style.display = 'none';
            // Reset image preview
            document.getElementById('d-final-image-url').value = '';
            document.getElementById('d-image-preview-container').innerHTML = `
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:#10b981;flex-shrink:0;"><rect x="2.5" y="4" width="19" height="16" rx="2.5"/><path d="M2.5 8.5h19"/><circle cx="6.1" cy="6.2" r="0.7" fill="currentColor" stroke="none"/><circle cx="9.1" cy="6.2" r="0.7" fill="currentColor" stroke="none"/><path d="m8.4 15.2 2.5 2.5 4.8-5"/></svg>
                <div style="font-size: 13px; color: var(--text-muted);">Click to add icon</div>
            `;

            // Close the add form
            const digitalWrapper = document.getElementById('digital-add-wrapper');
            const digitalBtn = document.querySelector('[data-toggle="digital-add-wrapper"]');
            if (digitalWrapper) { digitalWrapper.classList.remove('open'); }
            if (digitalBtn) { digitalBtn.classList.remove('open'); }

            } catch (error) {
                alert('Error adding purchase. Please try again.');
            }
        });

        // Digital filter
        window.filterDigital = function(event, filter) {
            currentDigitalFilter = filter;
            document.querySelectorAll('#digital .filter-chip').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            renderDigital();
        };

        // Render digital purchases
        function renderDigital() {
            const container = document.getElementById('digital-list');
            let filtered = digitalPurchases;

            const today = new Date();
            today.setHours(0, 0, 0, 0);

            if (currentDigitalFilter === 'active') {
                filtered = digitalPurchases.filter(d => {
                    if (!d.expiryDate) return true;
                    return new Date(d.expiryDate) >= today;
                });
            }
            if (currentDigitalFilter === 'soon') {
                filtered = digitalPurchases.filter(d => {
                    if (!d.expiryDate) return false;
                    const expiry = new Date(d.expiryDate);
                    const diffTime = expiry - today;
                    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
                    return diffDays > 0 && diffDays <= 7;
                });
            }
            if (currentDigitalFilter === 'expired') {
                filtered = digitalPurchases.filter(d => {
                    if (!d.expiryDate) return false;
                    return new Date(d.expiryDate) < today;
                });
            }

            if (filtered.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">${getDigitalPlaceholderSvg({ size: 48, strokeWidth: 1.5, style: 'opacity:0.4;' })}</div>
                        <p>No digital purchases in this category yet!</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = filtered.map((d, index) => {
                const isExpired = d.expiryDate && new Date(d.expiryDate) < today;
                const cardId = `digital-card-${index}`;

                // Calculate remaining days and status for active subscriptions
                let remainingDays = null;
                let remainingText = '';
                let statusClass = 'status-owned';
                let statusText = 'ACTIVE';
                let statusIcon = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';

                if (d.expiryDate) {
                    if (isExpired) {
                        statusClass = 'status-sold';
                        statusText = 'EXPIRED';
                        statusIcon = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>';
                    } else {
                        const expiry = new Date(d.expiryDate);
                        const diffTime = expiry - today;
                        remainingDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

                        // Check if expiring soon (within 7 days)
                        if (remainingDays <= 7) {
                            statusClass = 'status-badge';
                            statusText = 'SOON TO EXPIRE';
                            statusIcon = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
                        }

                        // Format remaining time text
                        if (remainingDays === 0) {
                            remainingText = 'Expires today';
                        } else if (remainingDays === 1) {
                            remainingText = '1 day left';
                        } else if (remainingDays <= 30) {
                            remainingText = `${remainingDays} days left`;
                        } else {
                            const months = Math.floor(remainingDays / 30);
                            remainingText = `${months} month${months > 1 ? 's' : ''} left`;
                        }
                    }
                } else {
                    statusText = 'LIFETIME';
                }

                return `
                <div class="item-card" id="${cardId}" onclick="toggleCard('${cardId}')">
                    <!-- Main Card Content (Always Visible) -->
                    <div class="card-main">
                        <div style="width: 100%;">
                            <!-- Title Above Everything -->
                            <div class="item-title" style="margin-bottom: 12px;">${sanitizeText(d.name)}</div>

                            <!-- Content Row: Image + Info -->
                            <div style="display: flex; gap: 16px; align-items: flex-start;">
                                ${getCardImageMarkup(d.imageUrl, d.name, getDigitalPlaceholderSvg({ size: 30, strokeWidth: 1.8 }))}

                                <!-- Info -->
                                <div style="flex: 1; min-width: 0;">
                                    <div class="item-meta" style="margin-bottom: 8px;">
                                        <span class="item-category">${sanitizeText(normalizeLabel(d.type || ""))}</span>
                                    </div>

                                    <!-- Badges Row -->
                                    <div class="badge-row">
                                        <span class="status-badge ${statusClass}${statusText === 'SOON TO EXPIRE' ? '' : ''}" style="${statusText === 'SOON TO EXPIRE' ? 'background: rgba(251, 191, 36, 0.15); color: #fbbf24; border-color: rgba(251, 191, 36, 0.3);' : ''}">
                                            ${statusIcon} ${statusText}
                                        </span>
                                        ${remainingText ? `<span class="status-badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border-color: rgba(16, 185, 129, 0.3);"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:3px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>${remainingText}</span>` : ''}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Expandable Details Section -->
                    <div class="card-details">
                        <div class="item-info">
                            <div class="info-row">
                                <span class="info-label">Amount</span>
                                <span class="info-value">₹${d.amount.toFixed(2)}</span>
                            </div>
                            <div class="info-row">
                                <span class="info-label">Purchase Date</span>
                                <span class="info-value">${new Date(d.date).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</span>
                            </div>
                            ${d.duration ? `
                            <div class="info-row">
                                <span class="info-label">Duration</span>
                                <span class="info-value">${sanitizeText(d.duration)}</span>
                            </div>
                            ` : ''}
                            ${d.expiryDate ? `
                            <div class="info-row">
                                <span class="info-label">Expiry Date</span>
                                <span class="info-value ${isExpired ? 'profit-negative' : remainingDays <= 7 ? '' : ''}" style="${remainingDays <= 7 && !isExpired ? 'color: #fbbf24;' : ''}">${new Date(d.expiryDate).toLocaleDateString('en-IN', {day: 'numeric', month: 'short', year: 'numeric'})}</span>
                            </div>
                            ` : ''}
                            ${d.notes ? `
                            <div class="info-row">
                                <span class="info-label">Notes</span>
                                <span class="info-value">${sanitizeHTML(d.notes)}</span>
                            </div>
                            ` : ''}
                        </div>

                        <!-- Action Buttons -->
                        <div style="display: flex; gap: 12px; margin-top: 16px;" onclick="event.stopPropagation();">
                            <button class="btn-edit" onclick="editDigital('${d.firestoreId}')" style="flex: 1;">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>Edit
                            </button>
                            <button class="btn-delete" onclick="deleteDigital('${d.firestoreId}', '${sanitizeText(d.name).replace(/'/g, "\\'")}')" style="flex: 1;">
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px;"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>Delete
                            </button>
                        </div>
                    </div>
                </div>
            `;
            }).join('');
        }

        // Delete digital purchase
        window.deleteDigital = function(firestoreId, name) {
            document.getElementById('deleteMessage').textContent =
                `Are you sure you want to delete "${name}"? This action cannot be undone.`;
            const modal = document.getElementById('deleteModal');
            modal.classList.add('active');
            modal.style.display = 'flex';

            deleteCallback = async () => {
                try {
                    await deleteCloudflareCollectionItem('digitalPurchases', firestoreId);
                } catch (error) {
                    alert('Error deleting purchase. Please try again.');
                }
            };
        };

        // Edit digital purchase
        // Toggle custom validity input for edit modal
        window.toggleEditCustomValidity = function() {
            const validitySelect = document.getElementById('edit-d-validity');
            const customGroup = document.getElementById('edit-custom-validity-group');

            if (validitySelect.value === 'custom') {
                customGroup.style.display = 'block';
            } else {
                customGroup.style.display = 'none';
            }
        };

        window.editDigital = function(firestoreId) {
            const digital = digitalPurchases.find(d => d.firestoreId === firestoreId);
            if (!digital) return;

            // Populate modal form
            document.getElementById('edit-d-name').value = digital.name;
            document.getElementById('edit-d-type').value = digital.type;
            document.getElementById('edit-d-price').value = digital.amount;
            document.getElementById('edit-d-date').value = digital.date;
            document.getElementById('edit-d-notes').value = digital.notes || '';

            // Populate image preview
            const imageUrl = digital.imageUrl || '';
            document.getElementById('edit-d-final-image-url').value = imageUrl;
            const imagePreviewContainer = document.getElementById('edit-d-image-preview-container');

            if (imageUrl) {
                imagePreviewContainer.innerHTML = `
                    <img src="${imageUrl}" style="width: 40px; height: 40px; border-radius: 6px; object-fit: cover;">
                    <div style="font-size: 13px; color: var(--text-primary); flex: 1;">Icon added</div>
                `;
            } else {
                imagePreviewContainer.innerHTML = `
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:#10b981;flex-shrink:0;"><rect x="2.5" y="4" width="19" height="16" rx="2.5"/><path d="M2.5 8.5h19"/><circle cx="6.1" cy="6.2" r="0.7" fill="currentColor" stroke="none"/><circle cx="9.1" cy="6.2" r="0.7" fill="currentColor" stroke="none"/><path d="m8.4 15.2 2.5 2.5 4.8-5"/></svg>
                    <div style="font-size: 13px; color: var(--text-muted);">Click to add/change icon</div>
                `;
            }

            // Calculate validity period from purchase date and expiry date
            if (digital.expiryDate && digital.date) {
                const start = new Date(digital.date);
                const end = new Date(digital.expiryDate);
                const diffTime = Math.abs(end - start);
                const diffMonths = Math.round(diffTime / (1000 * 60 * 60 * 24 * 30.44)); // Average days per month

                // Select the appropriate validity option
                const validitySelect = document.getElementById('edit-d-validity');
                const customGroup = document.getElementById('edit-custom-validity-group');

                if (diffMonths === 1) {
                    validitySelect.value = '1';
                    customGroup.style.display = 'none';
                } else if (diffMonths === 3) {
                    validitySelect.value = '3';
                    customGroup.style.display = 'none';
                } else if (diffMonths === 6) {
                    validitySelect.value = '6';
                    customGroup.style.display = 'none';
                } else if (diffMonths === 12) {
                    validitySelect.value = '12';
                    customGroup.style.display = 'none';
                } else if (diffMonths > 0) {
                    validitySelect.value = 'custom';
                    document.getElementById('edit-d-custom-months').value = diffMonths;
                    customGroup.style.display = 'block';
                } else {
                    validitySelect.value = '';
                    customGroup.style.display = 'none';
                }
            } else {
                document.getElementById('edit-d-validity').value = '';
                document.getElementById('edit-custom-validity-group').style.display = 'none';
            }

            // Store editing ID
            window.editingDigitalId = firestoreId;

            // Show modal
            const modal = document.getElementById('digitalEditModal');
            modal.style.display = 'flex';
            setTimeout(() => modal.classList.add('active'), 10);
        };

        window.closeDigitalEditModal = function() {
            const modal = document.getElementById('digitalEditModal');
            modal.classList.remove('active');
            setTimeout(() => modal.style.display = 'none', 200);
            window.editingDigitalId = null;
        };

        window.updateDigitalFromModal = async function(e) {
            e.preventDefault();

            const purchaseDate = document.getElementById('edit-d-date').value;
            const validityPeriod = document.getElementById('edit-d-validity').value;

            // Calculate expiry date and duration based on validity period
            let expiryDate = null;
            let duration = null;

            if (validityPeriod) {
                const startDate = new Date(purchaseDate);
                let months = 0;

                if (validityPeriod === 'custom') {
                    months = parseInt(document.getElementById('edit-d-custom-months').value) || 0;
                } else {
                    months = parseInt(validityPeriod);
                }

                if (months > 0) {
                    // Calculate expiry date by adding months
                    const endDate = new Date(startDate);
                    endDate.setMonth(endDate.getMonth() + months);
                    expiryDate = endDate.toISOString().split('T')[0];

                    // Format duration text
                    if (months >= 12) {
                        const years = Math.floor(months / 12);
                        const remainingMonths = months % 12;
                        if (remainingMonths === 0) {
                            duration = `${years} year${years > 1 ? 's' : ''}`;
                        } else {
                            duration = `${years} year${years > 1 ? 's' : ''} ${remainingMonths} month${remainingMonths > 1 ? 's' : ''}`;
                        }
                    } else {
                        duration = `${months} month${months > 1 ? 's' : ''}`;
                    }
                }
            }

            const digital = {
                name: sanitizeText(document.getElementById('edit-d-name').value),
                type: sanitizeText(document.getElementById('edit-d-type').value),
                amount: sanitizeNumber(parseFloat(document.getElementById('edit-d-price').value)),
                date: purchaseDate,
                duration: duration,
                expiryDate: expiryDate,
                imageUrl: document.getElementById('edit-d-final-image-url').value || '',
                notes: sanitizeHTML(document.getElementById('edit-d-notes').value),
                timestamp: Date.now()
            };

            try {
                const digitalIdToUpdate = window.editingDigitalId;
                await saveCloudflareCollectionItem('digitalPurchases', digital, digitalIdToUpdate);
                closeDigitalEditModal();
            } catch (error) {
                alert('Error updating digital purchase. Please try again.');
            }
        };

        const IMPORT_PREVIEW_LIMIT = 25;

        function normalizeImportText(rawText) {
            if (typeof rawText !== 'string') return '';
            let text = rawText;
            if (text.charCodeAt(0) === 0xFEFF) {
                text = text.slice(1);
            }
            return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
        }

        function detectImportDelimiter(lines) {
            const sample = lines.find(line => line && line.trim().length > 0) || '';
            return sample.includes('\t') ? '\t' : ',';
        }

        function parseDelimitedRow(line, delimiter) {
            const values = [];
            let current = '';
            let inQuotes = false;

            for (let i = 0; i < line.length; i++) {
                const ch = line[i];
                if (ch === '"') {
                    if (inQuotes && line[i + 1] === '"') {
                        current += '"';
                        i += 1;
                    } else {
                        inQuotes = !inQuotes;
                    }
                } else if (ch === delimiter && !inQuotes) {
                    values.push(current.trim());
                    current = '';
                } else {
                    current += ch;
                }
            }

            values.push(current.trim());
            return values;
        }

        function parseImportDataRows(text) {
            const normalized = normalizeImportText(text);
            const lines = normalized
                .split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);

            if (lines.length <= 1) {
                return [];
            }

            const delimiter = detectImportDelimiter(lines);
            return lines.slice(1).map(line => parseDelimitedRow(line, delimiter));
        }

        function parseImportNumber(value) {
            const parsed = parseFloat(String(value || '').replace(/[^\d.-]/g, ''));
            return Number.isFinite(parsed) ? parsed : NaN;
        }

        function parseImportDate(value) {
            const raw = String(value || '').trim();
            if (!raw) return '';

            if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
                return raw;
            }

            const slashMatch = raw.match(/^(\d{1,2})\/(\d{1,2})\/(\d{2}|\d{4})$/);
            if (slashMatch) {
                const day = parseInt(slashMatch[1], 10);
                const month = parseInt(slashMatch[2], 10);
                let year = parseInt(slashMatch[3], 10);
                if (year < 100) year += 2000;
                const parsed = new Date(year, month - 1, day);
                if (!Number.isNaN(parsed.getTime())) {
                    return parsed.toISOString().split('T')[0];
                }
            }

            const parsed = new Date(raw);
            if (Number.isNaN(parsed.getTime())) {
                return '';
            }

            return parsed.toISOString().split('T')[0];
        }

        function buildGadgetImportPayload(fileName, text) {
            const rows = parseImportDataRows(text);
            const today = new Date().toISOString().split('T')[0];
            const items = [];
            let skipped = 0;

            rows.forEach(values => {
                const name = (values[0] || '').trim();
                const category = normalizeLabel((values[1] || 'Other').trim()) || 'Other';
                const price = parseImportNumber(values[2]);
                if (!name || !Number.isFinite(price)) {
                    skipped += 1;
                    return;
                }

                const sellPriceRaw = parseImportNumber(values[4]);
                const sellPrice = Number.isFinite(sellPriceRaw) ? sellPriceRaw : null;
                const sellDate = parseImportDate(values[5]) || null;
                const statusRaw = String(values[6] || '').trim().toLowerCase();
                const status = (statusRaw === 'sold' || statusRaw === 'owned')
                    ? statusRaw
                    : ((sellPrice !== null && sellDate) ? 'sold' : 'owned');

                items.push({
                    name,
                    category,
                    price,
                    date: parseImportDate(values[3]) || today,
                    sellPrice,
                    sellDate,
                    status,
                    notes: (values[7] || '').trim(),
                    timestamp: Date.now() + items.length
                });
            });

            return {
                type: 'gadgets',
                label: 'Gadgets',
                collectionName: 'gadgets',
                fileName,
                items,
                skipped,
                columns: ['Name', 'Category', 'Price', 'Purchase Date', 'Sell Price', 'Sell Date', 'Status', 'Notes'],
                previewRows: items.slice(0, IMPORT_PREVIEW_LIMIT).map(item => [
                    item.name,
                    item.category,
                    item.price,
                    item.date,
                    item.sellPrice == null ? '' : item.sellPrice,
                    item.sellDate || '',
                    item.status,
                    item.notes || ''
                ])
            };
        }

        function buildGameImportPayload(fileName, text) {
            const rows = parseImportDataRows(text);
            const today = new Date().toISOString().split('T')[0];
            const items = [];
            let skipped = 0;

            rows.forEach(values => {
                const title = (values[0] || '').trim();
                const buyPrice = parseImportNumber(values[3]);
                if (!title || !Number.isFinite(buyPrice) || buyPrice <= 0) {
                    skipped += 1;
                    return;
                }

                const sellPriceRaw = parseImportNumber(values[6]);
                const sellPrice = Number.isFinite(sellPriceRaw) ? sellPriceRaw : null;
                const sellDate = parseImportDate(values[7]) || null;
                const statusRaw = String(values[8] || '').trim().toLowerCase();
                const status = (statusRaw === 'sold' || statusRaw === 'owned')
                    ? statusRaw
                    : ((sellPrice !== null && sellDate) ? 'sold' : 'owned');

                let notes = (values[9] || '').trim();
                if (!notes && values[8] && statusRaw !== 'sold' && statusRaw !== 'owned') {
                    notes = String(values[8]).trim();
                }

                const importedGame = applyCatalogFallbackToGameRecord({
                    title,
                    platform: normalizeLabel((values[1] || 'PlayStation 5').trim()) || 'PlayStation 5',
                    genre: normalizeLabel((values[2] || 'Action').trim()) || 'Action',
                    buyPrice,
                    buyDate: parseImportDate(values[4]) || today,
                    condition: normalizeLabel((values[5] || 'New/Sealed').trim()) || 'New/Sealed',
                    sellPrice,
                    sellDate,
                    status,
                    notes,
                    metacriticScore: normalizeMetacriticScore(values[10] || ''),
                    metacriticUrl: sanitizeURL(values[11] || ''),
                    imageUrl: sanitizeURL(values[12] || ''),
                    timestamp: Date.now() + items.length
                });
                items.push(importedGame);
            });

            return {
                type: 'games',
                label: 'Games',
                collectionName: 'games',
                fileName,
                items,
                skipped,
                columns: ['Title', 'Platform', 'Genre', 'Buy Price', 'Buy Date', 'Condition', 'Sell Price', 'Sell Date', 'Status', 'Notes', 'Metacritic Score', 'Metacritic URL', 'Cover Image URL'],
                previewRows: items.slice(0, IMPORT_PREVIEW_LIMIT).map(item => [
                    item.title,
                    item.platform,
                    item.genre,
                    item.buyPrice,
                    item.buyDate,
                    item.condition,
                    item.sellPrice == null ? '' : item.sellPrice,
                    item.sellDate || '',
                    item.status,
                    item.notes || '',
                    item.metacriticScore || '',
                    item.metacriticUrl || '',
                    item.imageUrl || ''
                ])
            };
        }

        function buildGameMetadataCatalogImportPayload(fileName, text) {
            const rows = parseImportDataRows(text);
            const items = [];
            let skipped = 0;

            rows.forEach(values => {
                const candidate = normalizeGameMetadataEntry({
                    title: values[0] || '',
                    platform: values[1] || 'Other',
                    genre: values[2] || '',
                    metacriticScore: values[3] || '',
                    metacriticUrl: values[4] || '',
                    imageUrl: values[5] || ''
                });

                if (!candidate) {
                    skipped += 1;
                    return;
                }

                items.push(candidate);
            });

            const normalizedItems = normalizeGameMetadataCatalog(items);
            return {
                type: 'gameMetadataCatalog',
                label: 'Game Metadata Catalog',
                fileName,
                items: normalizedItems,
                skipped: skipped + Math.max(0, items.length - normalizedItems.length),
                columns: ['Title', 'Platform', 'Genre', 'Metacritic Score', 'Metacritic URL', 'Cover Image URL'],
                previewRows: normalizedItems.slice(0, IMPORT_PREVIEW_LIMIT).map(item => [
                    item.title,
                    item.platform,
                    item.genre || '',
                    item.metacriticScore || '',
                    item.metacriticUrl || '',
                    item.imageUrl || ''
                ])
            };
        }

        function buildDigitalImportPayload(fileName, text) {
            const rows = parseImportDataRows(text);
            const today = new Date().toISOString().split('T')[0];
            const items = [];
            let skipped = 0;

            rows.forEach(values => {
                const name = (values[0] || '').trim();
                const amount = parseImportNumber(values[2]);
                if (!name || !Number.isFinite(amount)) {
                    skipped += 1;
                    return;
                }

                items.push({
                    name,
                    type: normalizeLabel((values[1] || 'Other').trim()) || 'Other',
                    amount,
                    date: parseImportDate(values[3]) || today,
                    duration: (values[4] || '').trim(),
                    expiryDate: parseImportDate(values[5]) || null,
                    notes: (values[6] || '').trim(),
                    timestamp: Date.now() + items.length
                });
            });

            return {
                type: 'digital',
                label: 'Digital Purchases',
                collectionName: 'digitalPurchases',
                fileName,
                items,
                skipped,
                columns: ['Name', 'Type', 'Amount', 'Purchase Date', 'Duration', 'Expiry Date', 'Notes'],
                previewRows: items.slice(0, IMPORT_PREVIEW_LIMIT).map(item => [
                    item.name,
                    item.type,
                    item.amount,
                    item.date,
                    item.duration || '',
                    item.expiryDate || '',
                    item.notes || ''
                ])
            };
        }

        function escapeImportPreviewCell(value) {
            const safe = document.createElement('div');
            safe.textContent = String(value == null ? '' : value);
            return safe.innerHTML;
        }

        function openImportPreviewModal(payload) {
            if (!payload || !Array.isArray(payload.items)) return;
            if (payload.items.length === 0) {
                alert('No valid rows found to import. Please check your file format.');
                return;
            }

            pendingCsvImport = payload;

            const modal = document.getElementById('importPreviewModal');
            const titleEl = document.getElementById('import-preview-title');
            const summaryEl = document.getElementById('import-preview-summary');
            const headEl = document.getElementById('import-preview-head');
            const bodyEl = document.getElementById('import-preview-body');
            const footnoteEl = document.getElementById('import-preview-footnote');
            const confirmBtn = document.getElementById('import-preview-confirm-btn');

            if (!modal || !titleEl || !summaryEl || !headEl || !bodyEl || !footnoteEl || !confirmBtn) {
                alert('Import preview is not available right now. Please refresh and try again.');
                pendingCsvImport = null;
                return;
            }

            titleEl.textContent = `${payload.label} Import Preview`;
            const skippedText = payload.skipped > 0
                ? ` ${payload.skipped} invalid row${payload.skipped === 1 ? '' : 's'} will be skipped.`
                : '';
            const actionLabel = payload.type === 'gameMetadataCatalog' ? 'ready to merge' : 'ready';
            summaryEl.textContent = `${payload.items.length} row${payload.items.length === 1 ? '' : 's'} ${actionLabel} from ${payload.fileName}.${skippedText}`;

            headEl.innerHTML = `<tr>${payload.columns.map(col => `<th>${escapeImportPreviewCell(col)}</th>`).join('')}</tr>`;
            bodyEl.innerHTML = payload.previewRows
                .map(row => `<tr>${row.map(cell => `<td>${escapeImportPreviewCell(cell)}</td>`).join('')}</tr>`)
                .join('');

            if (payload.type === 'gameMetadataCatalog') {
                footnoteEl.textContent = payload.items.length > IMPORT_PREVIEW_LIMIT
                    ? `Showing first ${IMPORT_PREVIEW_LIMIT} rows for preview. All ${payload.items.length} rows will be merged into the existing catalog after confirmation.`
                    : 'Rows will be merged into the existing catalog after confirmation.';
            } else {
                footnoteEl.textContent = payload.items.length > IMPORT_PREVIEW_LIMIT
                    ? `Showing first ${IMPORT_PREVIEW_LIMIT} rows for preview. All ${payload.items.length} rows will be imported after confirmation.`
                    : 'This preview shows exactly what will be imported.';
            }

            confirmBtn.disabled = false;
            confirmBtn.textContent = `Import ${payload.items.length} row${payload.items.length === 1 ? '' : 's'}`;

            modal.style.display = 'flex';
            requestAnimationFrame(() => modal.classList.add('active'));
        }

        window.closeImportPreview = function() {
            const modal = document.getElementById('importPreviewModal');
            if (!modal) return;
            modal.classList.remove('active');
            setTimeout(() => {
                modal.style.display = 'none';
            }, 180);
            pendingCsvImport = null;
        };

        async function persistImportItems(collectionName, items) {
            const imported = [];

            const prefixMap = {
                gadgets: 'g',
                games: 'gm',
                digitalPurchases: 'd'
            };
            const prefix = prefixMap[collectionName] || 'item';
            for (const item of items) {
                imported.push({
                    firestoreId: generateLocalItemId(prefix),
                    ...item
                });
            }

            return imported;
        }

        function applyImportedItemsToLocalState(type, importedItems) {
            if (!Array.isArray(importedItems) || importedItems.length === 0) return;
            if (type === 'gadgets') {
                gadgets = sortByTimestampDesc(gadgets.concat(importedItems));
            } else if (type === 'games') {
                games = sortByTimestampDesc(games.concat(importedItems.map(item => applyCatalogFallbackToGameRecord(item))));
            } else if (type === 'digital') {
                digitalPurchases = sortByTimestampDesc(digitalPurchases.concat(importedItems));
            }
        }

        window.confirmImportFromPreview = async function() {
            if (!pendingCsvImport || !currentUserUID) {
                alert('No pending import found. Please choose a file again.');
                return;
            }

            const payload = pendingCsvImport;
            const confirmBtn = document.getElementById('import-preview-confirm-btn');
            const summaryEl = document.getElementById('import-preview-summary');
            const originalBtnText = confirmBtn ? confirmBtn.textContent : '';
            const originalSummary = summaryEl ? summaryEl.textContent : '';

            if (confirmBtn) {
                confirmBtn.disabled = true;
                confirmBtn.textContent = 'Importing...';
            }
            if (summaryEl) {
                summaryEl.textContent = `Importing ${payload.items.length} row${payload.items.length === 1 ? '' : 's'} from ${payload.fileName}...`;
            }

            try {
                let importedCount = 0;
                let importMessage = '';

                if (payload.type === 'gameMetadataCatalog') {
                    if (!requireAdminAccess('import game metadata catalog')) {
                        window.closeImportPreview();
                        return;
                    }

                    const existingCatalog = Array.isArray(gameMetadataCatalog) ? gameMetadataCatalog : [];
                    const incomingCatalog = normalizeGameMetadataCatalog(payload.items || []);
                    const catalogMap = new Map(
                        existingCatalog.map(entry => [buildGameMetadataKey(entry.title, entry.platform), entry])
                    );

                    let addedCount = 0;
                    let updatedCount = 0;
                    incomingCatalog.forEach(entry => {
                        const key = buildGameMetadataKey(entry.title, entry.platform);
                        if (catalogMap.has(key)) {
                            updatedCount += 1;
                        } else {
                            addedCount += 1;
                        }
                        catalogMap.set(key, entry);
                    });

                    gameMetadataCatalog = normalizeGameMetadataCatalog(Array.from(catalogMap.values()));
                    await saveSettings({ includeGameMetadataCatalog: true });
                    refreshGameMetadataCatalogUI();
                    importedCount = incomingCatalog.length;
                    importMessage = `Catalog merged. Added ${addedCount} new and updated ${updatedCount} existing entries. Total catalog size: ${gameMetadataCatalog.length}.`;
                } else {
                    const importedItems = await persistImportItems(payload.collectionName, payload.items);
                    applyImportedItemsToLocalState(payload.type, importedItems);
                    if (importedItems.length > 0) {
                        await saveCloudflareCollectionItemsBatch(payload.collectionName, importedItems, { waitForSync: true });
                    }
                    updateAll();
                    importedCount = importedItems.length;
                    importMessage = `Imported ${importedCount} ${payload.label.toLowerCase()} successfully.`;
                }

                const skippedText = payload.skipped > 0
                    ? ` ${payload.skipped} invalid row${payload.skipped === 1 ? '' : 's'} were skipped.`
                    : '';
                alert(`${importMessage}${skippedText}`);

                window.closeImportPreview();
            } catch (error) {
                if (summaryEl) {
                    summaryEl.textContent = originalSummary;
                }
                if (confirmBtn) {
                    confirmBtn.disabled = false;
                    confirmBtn.textContent = originalBtnText;
                }
                alert('Import failed. Please try again.');
            }
        };

        window.triggerSettingsImport = function(inputId) {
            const input = document.getElementById(inputId);
            if (!input) return;
            input.value = '';
            input.click();
        };

        function buildCloudflareMigrationSnapshot(source = 'cloudflare-web', options = {}) {
            const includeGlobalSettings = options && options.includeGlobalSettings === true;
            return {
                version: 1,
                source,
                exportedAt: new Date().toISOString(),
                user: {
                    uid: currentUserUID || '',
                    email: (currentUser && currentUser.email) ? currentUser.email : ''
                },
                data: {
                    gadgets: Array.isArray(gadgets) ? gadgets : [],
                    games: Array.isArray(games) ? games : [],
                    digitalPurchases: Array.isArray(digitalPurchases) ? digitalPurchases : []
                },
                settings: {
                    currency: currentCurrency || '₹',
                    gadgetCategories: includeGlobalSettings && Array.isArray(gadgetCategories) ? gadgetCategories : [],
                    gamePlatforms: includeGlobalSettings && Array.isArray(gamePlatforms) ? gamePlatforms : [],
                    gameGenres: includeGlobalSettings && Array.isArray(gameGenres) ? gameGenres : [],
                    digitalTypes: includeGlobalSettings && Array.isArray(digitalTypes) ? digitalTypes : [],
                    customIcons: includeGlobalSettings && Array.isArray(customIcons) ? customIcons : [],
                    gameMetadataCatalog: includeGlobalSettings && Array.isArray(gameMetadataCatalog) ? gameMetadataCatalog : []
                }
            };
        }

        window.downloadCloudflareMigrationBackup = function() {
            if (!requireAdminAccess('export Cloudflare migration backup')) return;
            if (!currentUserUID) {
                alert('User not logged in');
                return;
            }

            const snapshot = buildCloudflareMigrationSnapshot('cloudflare-web-backup', { includeGlobalSettings: true });
            const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `gearnest_cloudflare_backup_${new Date().toISOString().split('T')[0]}.json`;
            a.click();
            URL.revokeObjectURL(url);
        };

async function uploadSnapshotToCloudflare(snapshotPayload, options = {}) {
    const includeAppConfig = options.includeAppConfig === true;
    const response = await fetchWithTimeout('/api/v1/snapshot', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            source: snapshotPayload && snapshotPayload.source ? snapshotPayload.source : 'cloudflare-web',
            includeAppConfig,
            snapshot: snapshotPayload
        })
    }, CLOUDFLARE_API_TIMEOUTS.snapshotWrite);

            let payload = null;
            try {
                payload = await response.json();
            } catch {
                payload = null;
            }

            if (!response.ok) {
                const message = payload && payload.message
                    ? payload.message
                    : 'Upload failed. Ensure /api/* is protected by Cloudflare Access and D1 binding is configured.';
                throw new Error(message);
            }

            return payload;
        }

        window.uploadCurrentDataToCloudflare = async function() {
            if (!requireAdminAccess('upload data to Cloudflare')) return;
            if (!currentUserUID) {
                alert('User not logged in');
                return;
            }

            const snapshot = buildCloudflareMigrationSnapshot('cloudflare-web-live', { includeGlobalSettings: true });
            const counts = {
                gadgets: snapshot.data.gadgets.length,
                games: snapshot.data.games.length,
                digitalPurchases: snapshot.data.digitalPurchases.length
            };

            if (!confirm(`Upload current data to Cloudflare D1 now?\n\nGadgets: ${counts.gadgets}\nGames: ${counts.games}\nDigital: ${counts.digitalPurchases}`)) {
                return;
            }

            try {
                const result = await uploadSnapshotToCloudflare(snapshot, { includeAppConfig: true });
                const savedCounts = result && result.counts ? result.counts : counts;
                alert(`Cloudflare upload complete.\n\nGadgets: ${savedCounts.gadgets || 0}\nGames: ${savedCounts.games || 0}\nDigital: ${savedCounts.digitalPurchases || 0}`);
            } catch (error) {
                alert(`Cloudflare upload failed: ${error.message}`);
            }
        };

        window.uploadCloudflareBackupFile = function(event) {
            if (!requireAdminAccess('upload backup JSON to Cloudflare')) {
                if (event && event.target) event.target.value = '';
                return;
            }

            const file = event && event.target ? event.target.files[0] : null;
            if (!file) return;

            const reader = new FileReader();
            reader.onload = async function(loadEvent) {
                try {
                    const raw = String(loadEvent && loadEvent.target ? (loadEvent.target.result || '') : '');
                    const parsed = JSON.parse(raw);
                    const snapshot = buildCloudflareMigrationSnapshot('cloudflare-web-file', { includeGlobalSettings: true });
                    const sourceSnapshot = parsed && typeof parsed === 'object' ? parsed : {};

                    // Keep strict expected shape but preserve imported data where valid.
                    snapshot.data = {
                        gadgets: Array.isArray(sourceSnapshot?.data?.gadgets) ? sourceSnapshot.data.gadgets : [],
                        games: Array.isArray(sourceSnapshot?.data?.games) ? sourceSnapshot.data.games : [],
                        digitalPurchases: Array.isArray(sourceSnapshot?.data?.digitalPurchases) ? sourceSnapshot.data.digitalPurchases : []
                    };
                    snapshot.settings = {
                        ...snapshot.settings,
                        currency: sourceSnapshot?.settings?.currency || snapshot.settings.currency,
                        gadgetCategories: Array.isArray(sourceSnapshot?.settings?.gadgetCategories) ? sourceSnapshot.settings.gadgetCategories : snapshot.settings.gadgetCategories,
                        gamePlatforms: Array.isArray(sourceSnapshot?.settings?.gamePlatforms) ? sourceSnapshot.settings.gamePlatforms : snapshot.settings.gamePlatforms,
                        gameGenres: Array.isArray(sourceSnapshot?.settings?.gameGenres) ? sourceSnapshot.settings.gameGenres : snapshot.settings.gameGenres,
                        digitalTypes: Array.isArray(sourceSnapshot?.settings?.digitalTypes) ? sourceSnapshot.settings.digitalTypes : snapshot.settings.digitalTypes,
                        customIcons: Array.isArray(sourceSnapshot?.settings?.customIcons) ? sourceSnapshot.settings.customIcons : snapshot.settings.customIcons,
                        gameMetadataCatalog: Array.isArray(sourceSnapshot?.settings?.gameMetadataCatalog) ? sourceSnapshot.settings.gameMetadataCatalog : snapshot.settings.gameMetadataCatalog
                    };

                    const totalItems = snapshot.data.gadgets.length + snapshot.data.games.length + snapshot.data.digitalPurchases.length;
                    if (!confirm(`Upload backup file to Cloudflare now?\n\nTotal items: ${totalItems}`)) {
                        event.target.value = '';
                        return;
                    }

                    await uploadSnapshotToCloudflare(snapshot, { includeAppConfig: true });
                    alert('Backup uploaded to Cloudflare successfully.');
                } catch (error) {
                    alert(`Could not upload backup: ${error.message}`);
                } finally {
                    event.target.value = '';
                }
            };
            reader.readAsText(file, 'UTF-8');
        };

        // TSV/CSV Export for Gadgets
        window.exportGadgetsCSV = function() {
            if (gadgets.length === 0) {
                alert('No gadgets to export!');
                return;
            }

            const headers = ['Name', 'Category', 'Price', 'Purchase Date', 'Sell Price', 'Sell Date', 'Status', 'Notes'];
            const rows = gadgets.map(g => [
                g.name,
                g.category,
                g.price,
                g.date,
                g.sellPrice || '',
                g.sellDate || '',
                g.status || 'owned',
                g.notes || ''
            ]);

            // Use CSV format with proper escaping for Mac Excel compatibility
            const escapeCsvValue = (val) => {
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            const csv = [headers, ...rows]
                .map(row => row.map(escapeCsvValue).join(','))
                .join('\n');

            // UTF-8 with BOM for broad character support in both Excel and Google Sheets
            const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `gadgets_export_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        };

        // Download Gadget Template
        window.downloadGadgetTemplate = function() {
            const headers = ['Name', 'Category', 'Price', 'Purchase Date', 'Sell Price', 'Sell Date', 'Status', 'Notes'];
            const exampleRow = ['iPhone 15 Pro', 'Phone', '119900', '2024-01-15', '95000', '2025-02-01', 'sold', 'Upgraded to 16'];

            const escapeCsvValue = (val) => {
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            const csv = [headers, exampleRow].map(row => row.map(escapeCsvValue).join(',')).join('\n');

            const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'gadgets_template.csv';
            a.click();
            URL.revokeObjectURL(url);

            alert('Template downloaded! Open it in Excel or Google Sheets, fill in your data (one item per row), and import it back.');
        };

       window.importGadgetsCSV = function(event) {
    if (!currentUserUID) {
        alert('User not logged in');
        return;
    }

    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const payload = buildGadgetImportPayload(file.name, e.target.result || '');
            openImportPreviewModal(payload);
        } catch (error) {
            alert('Could not parse this file. Please check the template and try again.');
        }
        event.target.value = '';
    };

    reader.readAsText(file, 'UTF-8');
};


        // TSV/CSV Export for Games
        window.exportGamesCSV = function() {
            if (games.length === 0) {
                alert('No games to export!');
                return;
            }

            const headers = ['Title', 'Platform', 'Genre', 'Buy Price', 'Buy Date', 'Condition', 'Sell Price', 'Sell Date', 'Status', 'Notes', 'Metacritic Score', 'Metacritic URL', 'Cover Image URL'];
            const rows = games.map(g => [
                g.title,
                g.platform,
                g.genre || '',
                g.buyPrice,
                g.buyDate,
                g.condition,
                g.sellPrice || '',
                g.sellDate || '',
                g.status || 'owned',
                g.notes || '',
                normalizeMetacriticScore(g.metacriticScore || ''),
                sanitizeURL(g.metacriticUrl || ''),
                sanitizeURL(g.imageUrl || '')
            ]);

            // Use CSV format with proper escaping for Mac Excel compatibility
            const escapeCsvValue = (val) => {
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            const csv = [headers, ...rows]
                .map(row => row.map(escapeCsvValue).join(','))
                .join('\n');

            // UTF-8 with BOM for broad character support in both Excel and Google Sheets
            const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `games_export_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        };

        // Download Game Template
        window.downloadGameTemplate = function() {
            const headers = ['Title', 'Platform', 'Genre', 'Buy Price', 'Buy Date', 'Condition', 'Sell Price', 'Sell Date', 'Status', 'Notes', 'Metacritic Score', 'Metacritic URL', 'Cover Image URL'];
            const exampleRow = ['Spider-Man 2', 'PlayStation 5', 'Action', '3999', '2024-06-01', 'Mint', '2500', '2025-01-15', 'sold', 'Completed', '90', 'https://www.metacritic.com/game/marvels-spider-man-2/', 'https://example.com/spiderman2-cover.jpg'];

            const escapeCsvValue = (val) => {
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            const csv = [headers, exampleRow].map(row => row.map(escapeCsvValue).join(',')).join('\n');

            const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'games_template.csv';
            a.click();
            URL.revokeObjectURL(url);

            alert('Template downloaded! Open it in Excel or Google Sheets, fill in your data (one game per row), and import it back.');
        };

        // TSV Import for Games (Multi-User Safe)
window.importGamesCSV = function(event) {
    if (!currentUserUID) {
        alert('User not logged in');
        return;
    }

    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const payload = buildGameImportPayload(file.name, e.target.result || '');
            openImportPreviewModal(payload);
        } catch (error) {
            alert('Could not parse this file. Please check the template and try again.');
        }
        event.target.value = '';
    };

    reader.readAsText(file, 'UTF-8');
};


        // TSV/CSV Export for Digital Purchases
        window.exportDigitalCSV = function() {
            if (digitalPurchases.length === 0) {
                alert('No digital purchases to export!');
                return;
            }

            const headers = ['Name', 'Type', 'Amount', 'Purchase Date', 'Duration', 'Expiry Date', 'Notes'];
            const rows = digitalPurchases.map(d => [
                d.name,
                d.type,
                d.amount,
                d.date,
                d.duration || '',
                d.expiryDate || '',
                d.notes || ''
            ]);

            // Use CSV format with proper escaping for Mac Excel compatibility
            const escapeCsvValue = (val) => {
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            const csv = [headers, ...rows]
                .map(row => row.map(escapeCsvValue).join(','))
                .join('\n');

            // UTF-8 with BOM for broad character support in both Excel and Google Sheets
            const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `digital_purchases_export_${new Date().toISOString().split('T')[0]}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        };

        // Download Digital Template
        window.downloadDigitalTemplate = function() {
            const headers = ['Name', 'Type', 'Amount', 'Purchase Date', 'Duration', 'Expiry Date', 'Notes'];
            const exampleRow = ['PS+ Premium', 'Game Subscription', '1299', '2024-01-15', '1 Month', '2024-02-15', 'Auto-renewal enabled'];

            const escapeCsvValue = (val) => {
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            const csv = [headers, exampleRow].map(row => row.map(escapeCsvValue).join(',')).join('\n');

            const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'digital_purchases_template.csv';
            a.click();
            URL.revokeObjectURL(url);

            alert('Template downloaded! Open it in Excel or Google Sheets, fill in your data (one purchase per row), and import it back.');
        };
window.downloadGameMetadataTemplate = function() {
    if (!requireAdminAccess('download game metadata templates')) return;
    const headers = ['Title', 'Platform', 'Genre', 'Metacritic Score', 'Metacritic URL', 'Cover Image URL'];
    const exampleRow = ['Elden Ring', 'PlayStation 5', 'RPG', '96', 'https://www.metacritic.com/game/elden-ring/', 'https://example.com/elden-ring-cover.jpg'];

    const escapeCsvValue = (val) => {
        const str = String(val == null ? '' : val);
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    };

    const csv = [headers, exampleRow].map(row => row.map(escapeCsvValue).join(',')).join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'game_metadata_catalog_template.csv';
    a.click();
    URL.revokeObjectURL(url);

    alert('Template downloaded. Fill one game per row and import from Admin.');
};

window.exportGameMetadataCatalogCSV = function() {
    if (!requireAdminAccess('export game metadata catalog')) return;
    if (!Array.isArray(gameMetadataCatalog) || gameMetadataCatalog.length === 0) {
        alert('No game metadata catalog entries to export!');
        return;
    }

    const headers = ['Title', 'Platform', 'Genre', 'Metacritic Score', 'Metacritic URL', 'Cover Image URL'];
    const rows = gameMetadataCatalog.map(entry => [
        entry.title,
        entry.platform,
        entry.genre || '',
        entry.metacriticScore || '',
        entry.metacriticUrl || '',
        entry.imageUrl || ''
    ]);

    const escapeCsvValue = (val) => {
        const str = String(val == null ? '' : val);
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    };

    const csv = [headers, ...rows]
        .map(row => row.map(escapeCsvValue).join(','))
        .join('\n');

    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `game_metadata_catalog_export_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
};

window.importGameMetadataCatalogCSV = function(event) {
    if (!requireAdminAccess('import game metadata catalog')) {
        if (event && event.target) event.target.value = '';
        return;
    }
    if (!currentUserUID) {
        alert('User not logged in');
        return;
    }

    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const payload = buildGameMetadataCatalogImportPayload(file.name, e.target.result || '');
            openImportPreviewModal(payload);
        } catch (error) {
            alert('Could not parse this file. Please check the metadata template and try again.');
        }
        event.target.value = '';
    };

    reader.readAsText(file, 'UTF-8');
};

// TSV/CSV Import for Digital Purchases (GLOBAL SAFE)
window.importDigitalCSV = function(event) {
    if (!currentUserUID) {
        alert('User not logged in');
        return;
    }

    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const payload = buildDigitalImportPayload(file.name, e.target.result || '');
            openImportPreviewModal(payload);
        } catch (error) {
            alert('Could not parse this file. Please check the template and try again.');
        }
        event.target.value = '';
    };

    reader.readAsText(file, 'UTF-8');
};


        // ========== ENCRYPTION UI FUNCTIONS ==========

        window.setupEncryption = async function() {

            const passwordInput = document.getElementById('masterPassword');
            const confirmPasswordInput = document.getElementById('masterPasswordConfirm');


            const password = passwordInput ? passwordInput.value : '';
            const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : '';


            if (!password || password.length < 8) {
                alert('Password must be at least 8 characters long');
                return;
            }

            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }

            try {

                if (!currentUserUID) {
                    throw new Error('User not authenticated. Please sign in again.');
                }

                await encryptionManager.setupNewUser(password);

                // Close modal properly
                const modal = document.getElementById('encryptionSetupModal');
                modal.classList.remove('active');
                setTimeout(() => {
                    modal.style.display = 'none';
                }, 200); // Wait for fade out animation

                document.body.classList.add('encrypted');

                // Clear password fields
                if (passwordInput) passwordInput.value = '';
                if (confirmPasswordInput) confirmPasswordInput.value = '';

                alert('Encryption enabled. Your data is now protected. You will need to enter your password on next login.');

                // Update encryption status in settings (with error handling)
                try {
                    if (typeof updateEncryptionStatus === 'function') {
                        updateEncryptionStatus();
                    }
                } catch (statusError) {
                    // Don't throw - encryption is already enabled successfully
                }

            } catch (error) {
                alert('Failed to setup encryption: ' + error.message);
            }
        };

        window.skipEncryptionSetup = async function() {
            // Just close the modal
            const modal = document.getElementById('encryptionSetupModal');
            modal.classList.remove('active');
            setTimeout(() => {
                modal.style.display = 'none';
            }, 200); // Wait for fade out animation

            // If data hasn't loaded yet, load it now
            if (gadgets.length === 0 && games.length === 0 && digitalPurchases.length === 0) {
                await loadData();
            }
        };

        // ========== ENCRYPTION SETTINGS FUNCTIONS (FROM SETTINGS PANEL) ==========

        window.updateEncryptionStatus = function() {
            const isEnabled = encryptionManager.isEncryptionEnabled();

            // Get all the elements
            const statusIcon = document.getElementById('encryption-status-icon');
            const statusText = document.getElementById('encryption-status-text');
            const statusSubtitle = document.getElementById('encryption-status-subtitle');
            const statusContainer = document.getElementById('encryption-status');
            const disabledBtn = document.getElementById('encryption-disabled-controls');
            const enabledBtn = document.getElementById('encryption-enabled-controls');

            // If essential elements don't exist, skip update silently
            if (!statusIcon || !statusText || !statusSubtitle || !statusContainer) {
                return;
            }

            if (isEnabled) {
                statusIcon.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
                statusText.textContent = 'Encryption On';
                statusSubtitle.textContent = 'Protected';
                statusContainer.style.background = 'rgba(16, 185, 129, 0.15)';
                statusContainer.style.borderColor = 'rgba(16, 185, 129, 0.3)';

                // Show enabled button, hide disabled button
                if (disabledBtn) disabledBtn.style.display = 'none';
                if (enabledBtn) enabledBtn.style.display = 'block';
            } else {
                statusIcon.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg>';
                statusText.textContent = 'Encryption Off';
                statusSubtitle.textContent = 'Not encrypted';
                statusContainer.style.background = 'rgba(148, 163, 184, 0.1)';
                statusContainer.style.borderColor = 'rgba(148, 163, 184, 0.2)';

                // Show disabled button, hide enabled button
                if (disabledBtn) disabledBtn.style.display = 'block';
                if (enabledBtn) enabledBtn.style.display = 'none';
            }

            // Sync profile menu encryption item
            const pmIcon = document.getElementById('profileMenuEncryptionIcon');
            const pmLabel = document.getElementById('profileMenuEncryptionLabel');
            const pmItem = document.getElementById('profileMenuEncryption');
            if (pmLabel) {
                if (isEnabled) {
                    pmLabel.textContent = 'Disable Encryption';
                    if (pmItem) pmItem.style.color = '#ef4444';
                    if (pmIcon) {
                        pmIcon.innerHTML = '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>';
                        pmIcon.style.stroke = '#ef4444';
                    }
                } else {
                    pmLabel.textContent = 'Enable Encryption';
                    if (pmItem) pmItem.style.color = '#10b981';
                    if (pmIcon) {
                        pmIcon.innerHTML = '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>';
                        pmIcon.style.stroke = '#10b981';
                    }
                }
            }
        };

        // Profile menu encryption toggle handler
        window.profileMenuEncryptionToggle = function() {
            const isEnabled = encryptionManager.isEncryptionEnabled();
            if (isEnabled) {
                if (confirm('Are you sure you want to disable encryption?\n\nYour data will no longer be encrypted.')) {
                    disableEncryption();
                }
            } else {
                showEnableEncryptionForm();
            }
        };

        window.showEnableEncryptionForm = function() {
            // This function is no longer needed since we use the modal
            const modal = document.getElementById('encryptionSetupModal');
            if (modal) {
                modal.style.display = 'flex';
                modal.classList.add('active');
            }
        };

        window.cancelEnableEncryption = function() {
            // This function is no longer needed since we use the modal
        };

        window.enableEncryptionFromSettings = async function() {
            const passwordField = document.getElementById('settings-master-password');
            const confirmPasswordField = document.getElementById('settings-master-password-confirm');

            // If password fields don't exist, open the modal instead
            if (!passwordField || !confirmPasswordField) {
                const modal = document.getElementById('encryptionSetupModal');
                if (modal) {
                    modal.style.display = 'flex';
                    modal.classList.add('active');
                }
                return;
            }

            const password = passwordField.value;
            const confirmPassword = confirmPasswordField.value;

            if (!password || password.length < 8) {
                alert('Password must be at least 8 characters long');
                return;
            }

            if (password !== confirmPassword) {
                alert('Passwords do not match');
                return;
            }

            if (!confirm('Are you sure you want to enable encryption?\n\nImportant: If you lose your password, your data cannot be recovered.')) {
                return;
            }

            try {
                // Setup encryption
                await encryptionManager.setupNewUser(password);

                // Re-encrypt all existing data
                const encryptedSnapshot = buildCloudflareMigrationSnapshot('cloudflare-web-encrypted', {
                    includeGlobalSettings: isAdmin(currentUser)
                });
                encryptedSnapshot.data.gadgets = await Promise.all(gadgets.map(async (gadget) => ({
                    firestoreId: gadget.firestoreId || generateLocalItemId('g'),
                    ...(await encryptData(gadget))
                })));
                encryptedSnapshot.data.games = await Promise.all(games.map(async (game) => ({
                    firestoreId: game.firestoreId || generateLocalItemId('gm'),
                    ...(await encryptData(game))
                })));
                encryptedSnapshot.data.digitalPurchases = await Promise.all(digitalPurchases.map(async (digital) => ({
                    firestoreId: digital.firestoreId || generateLocalItemId('d'),
                    ...(await encryptData(digital))
                })));

                await uploadSnapshotToCloudflare(encryptedSnapshot, {
                    includeAppConfig: isAdmin(currentUser)
                });
                cloudflareSnapshotCache = encryptedSnapshot;

                document.body.classList.add('encrypted');

                try {
                    updateEncryptionStatus();
                } catch (statusError) {
                }

                alert('Encryption enabled successfully.\n\nAll your data has been encrypted with your master password.');

                // Clear password fields if they exist
                const masterPasswordField = document.getElementById('settings-master-password');
                const confirmPasswordField = document.getElementById('settings-master-password-confirm');
                if (masterPasswordField) masterPasswordField.value = '';
                if (confirmPasswordField) confirmPasswordField.value = '';

            } catch (error) {
                alert('Failed to setup encryption: ' + error.message);
            }
        };

        window.disableEncryption = async function() {
            try {

                // Remove encryption settings from localStorage
                localStorage.removeItem('encryptionEnabled_' + currentUserUID);
                localStorage.removeItem('encryptionSalt_' + currentUserUID);

                // Reset encryption manager
                encryptionManager.encryptionKey = null;
                encryptionManager.isUnlocked = false;

                document.body.classList.remove('encrypted');

                try {
                    updateEncryptionStatus();
                } catch (statusError) {
                }

                alert('Encryption disabled.\n\nYour app will reload to apply changes.');

                // Reload the page to clear everything
                window.location.reload();

            } catch (error) {
                alert('Failed to disable encryption: ' + error.message);
            }
        };
        window.unlockData = async function() {
            const password = document.getElementById('unlockPassword').value;
            const errorDiv = document.getElementById('unlockError');

            if (!password) {
                errorDiv.textContent = 'Please enter your password';
                errorDiv.style.display = 'block';
                return;
            }

            try {
                await encryptionManager.unlockExistingUser(password);
                const modal = document.getElementById('unlockModal');
                modal.classList.remove('active');
                setTimeout(() => {
                    modal.style.display = 'none';
                }, 200);
                document.body.classList.add('encrypted');
                errorDiv.style.display = 'none';

                await loadData();

            } catch (error) {
                errorDiv.textContent = 'Incorrect password or decryption error';
                errorDiv.style.display = 'block';
            }
        };

    // Initialize
    document.getElementById('g-date').valueAsDate = new Date();
    document.getElementById('gm-buy-date').valueAsDate = new Date();
    document.getElementById('d-date').valueAsDate = new Date();

    // Initialize icon upload handlers
    setTimeout(() => {
        const fileInput = document.getElementById('icon-upload');
        const urlInput = document.getElementById('icon-url');

        if (fileInput) {
            fileInput.addEventListener('change', handleIconUpload);
        }

        if (urlInput) {
            urlInput.addEventListener('input', handleIconURL);
        }
    }, 1000);

    // Data loads automatically after Cloudflare session bootstrap
