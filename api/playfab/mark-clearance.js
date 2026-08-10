// api/playfab/mark-clearance.js
//
// Called by CloudScript (via http.request) the instant your anti-cheat
// chain (AntiUnity, CustomIDChecker, HandleAntiCheat, etc.) finishes
// clearing a player. Writes a short-lived "cleared" flag into Redis.
//
// api/photon/authenticate.js then reads that flag synchronously - no
// PlayFab propagation lag, because CloudScript's http.request call
// completes before CloudScript returns a result to the client, so the
// flag is already in Redis by the time the client turns around and hits
// Photon.
//
// SECURITY: this endpoint sets a flag that gates Photon access, so it
// MUST verify the shared secret before writing anything. Anyone who
// could hit this endpoint without the secret could clear themselves
// without ever passing anti-cheat.

const { Redis } = require("@upstash/redis");

// ---------------------------------------------------------------------------
// Config / env
// ---------------------------------------------------------------------------
const CLEARANCE_SECRET = process.env.CLOUDSCRIPT_CLEARANCE_SECRET;

// How long the "cleared" flag lives in Redis before it expires. This only
// needs to cover the gap between CloudScript clearing the player and that
// same client hitting /api/photon/authenticate - a few seconds of margin
// is plenty. Keeping it short limits how long a flag could be replayed if
// it ever leaked.
const CLEARANCE_TTL_SEC = 90;

const PLAYFABID_RE = /^[0-9A-F]{16}$/i;

const redis = new Redis({
    url: process.env.KV_REST_API_URL,
    token: process.env.KV_REST_API_TOKEN,
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function reject(res, status, message) {
    return res.status(status).json({ ok: false, message });
}

function timingSafeEqual(a, b) {
    // Avoid short-circuit string comparison for secret checking. Both
    // inputs are coerced to strings of matching length before comparing
    // so this doesn't leak timing info about where a mismatch occurs.
    if (typeof a !== "string" || typeof b !== "string") return false;
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return diff === 0;
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------
async function handler(req, res) {
    if (!CLEARANCE_SECRET) {
        console.error("Missing CLOUDSCRIPT_CLEARANCE_SECRET env var.");
        return reject(res, 500, "Server misconfigured.");
    }

    if (req.method !== "POST") {
        return reject(res, 405, "Method not allowed.");
    }

    // ---- Auth: only your own CloudScript should ever be able to call this ----
    const providedSecret = req.headers["x-clearance-secret"];
    if (!providedSecret || !timingSafeEqual(providedSecret, CLEARANCE_SECRET)) {
        console.error("[mark-clearance] rejected: bad or missing secret");
        return reject(res, 401, "Unauthorized.");
    }

    // ---- Validate body ----
    const playFabId = req.body && req.body.playFabId;
    if (!playFabId || !PLAYFABID_RE.test(playFabId)) {
        return reject(res, 400, "Missing or malformed playFabId.");
    }

    // ---- Write the flag ----
    try {
        await redis.set(`cleared:${playFabId}`, "1", { ex: CLEARANCE_TTL_SEC });
    } catch (e) {
        console.error("[mark-clearance] redis write failed:", e.message);
        return reject(res, 502, "Failed to record clearance.");
    }

    return res.status(200).json({ ok: true, playFabId, ttlSec: CLEARANCE_TTL_SEC });
}

// Outer safety net - never let an unhandled exception escape as a raw 500
// with no body, since CloudScript's http.request call is just checking
// this fired, not parsing a rich response.
module.exports = async function safeHandler(req, res) {
    try {
        return await handler(req, res);
    } catch (e) {
        console.error("[mark-clearance] unhandled exception:", e.message, e.stack);
        return reject(res, 500, "Internal error.");
    }
};

module.exports.config = { maxDuration: 5 };
