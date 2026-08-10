// api/photon/authenticate.js
//
// v3 - AntiUnity check removed.
//
// ============================================================================
// WHAT CHANGED FROM v2
// ============================================================================
// v2 replaced the old "reject on any AntiUnity ambiguity" logic with an
// optimistic-admit + background-verify pattern. That fixed the false
// rejections, but it was still built around a fundamentally slow check:
// reading PlayFab's GetUserInternalData, which has multi-second eventual
// consistency lag.
//
// v3 removes that check entirely and replaces it with something that
// can't have a propagation race by construction: your CloudScript
// anti-cheat chain (AntiUnity, CustomIDChecker, HandleAntiCheat, etc.)
// now PUSHES a "cleared" flag directly into Redis via http.request the
// moment it finishes - see api/playfab/mark-clearance.js. Redis writes
// are near-instant, and CloudScript's http.request call completes
// synchronously before CloudScript returns a result to the client, so by
// the time the client turns around and hits Photon, the flag is already
// there. No retries, no waitUntil, no provisional admit, no kick step.
//
// Security property is the same as before, just enforced differently: a
// modified client that skips your CloudScript anti-cheat call entirely
// will never have the Redis flag set, and gets rejected immediately and
// deterministically - not "maybe rejected depending on timing," which is
// what made the old check both leaky AND annoying.
//
// You still need to add the http.request call to your existing CloudScript
// anti-cheat chain - see the snippet at the bottom of
// api/playfab/mark-clearance.js.
// ============================================================================

const axios = require("axios");
const { Redis } = require("@upstash/redis");

// ---------------------------------------------------------------------------
// Config / env
// ---------------------------------------------------------------------------
const TITLE_ID = process.env.PLAYFAB_TITLE_ID;
const SECRET_KEY = process.env.PLAYFAB_SECRET_KEY;
const PLAYFAB_BASE = `https://${TITLE_ID}.playfabapi.com`;
const ABUSE_ALERT_WEBHOOK_URL = process.env.ABUSE_ALERT_WEBHOOK_URL;
const AUTH_STATUS_WEBHOOK_URL = process.env.AUTH_STATUS_WEBHOOK_URL;
const STATUS_LOG_ENABLED = !!AUTH_STATUS_WEBHOOK_URL;

const redis = new Redis({
    url: process.env.KV_REST_API_URL,
    token: process.env.KV_REST_API_TOKEN,
});

// ---- Rate limiting tunables ----
// Kept at the values you already fought hard to get right - Photon Cloud's
// custom auth webhook is called SERVER-SIDE by Photon's own infrastructure.
// The x-forwarded-for IP is very likely a shared Photon relay/egress IP,
// not a per-player signal, and a single real player can legitimately
// trigger this webhook 5-6 times in a few seconds. Don't tighten these
// back down without re-confirming that lesson still holds.
const IP_LIMIT = { windowSec: 60, max: 300 };
const ID_LIMIT = { windowSec: 30, max: 20 };

// Title-wide circuit breaker for distributed CCU farming (many IDs, many
// IPs, deliberately spread to dodge per-key limits). Tune GLOBAL_LIMIT.max
// to your real peak CCU before relying on this.
const GLOBAL_LIMIT = { windowSec: 60, max: 1500 };
const CIRCUIT_TIGHTEN_DIVISOR = 4;

const PLAYFABID_RE = /^[0-9A-F]{16}$/i;
const ABUSE_BAN_THRESHOLD = 15;
const ABUSE_WINDOW_SEC = 120;
const ABUSE_BAN_HOURS = 24;

// If the clearance flag isn't found on the first read, one quick retry
// covers the (rare, if the client is well-behaved) case where CloudScript's
// http.request call is still landing. This is NOT the old multi-second
// retry loop - it's a single short check, because Redis writes don't have
// PlayFab's propagation lag.
const CLEARANCE_RETRY_DELAY_MS = 400;

// ---------------------------------------------------------------------------
// Redis helpers (never throw uncaught)
// ---------------------------------------------------------------------------
async function safeGet(key) {
    try {
        return await redis.get(key);
    } catch (e) {
        console.error("[redis] get failed:", key, e.message);
        return null;
    }
}

async function safeDel(key) {
    try {
        await redis.del(key);
    } catch (e) {
        console.error("[redis] del failed:", key, e.message);
    }
}

async function bumpCounter(key, windowSec) {
    try {
        const count = await redis.incr(key);
        if (count === 1) await redis.expire(key, windowSec);
        return count;
    } catch (e) {
        console.error("[redis] bumpCounter failed:", key, e.message);
        return null; // null = "couldn't check," distinct from "over limit"
    }
}

// Checks the "cleared" flag written by mark-clearance.js. One quick retry
// on a miss, no PlayFab call involved at all.
async function hasCloudScriptClearance(playFabId) {
    const key = `cleared:${playFabId}`;
    const first = await safeGet(key);
    if (first) return true;

    await new Promise((r) => setTimeout(r, CLEARANCE_RETRY_DELAY_MS));
    const second = await safeGet(key);
    return !!second;
}

// ---------------------------------------------------------------------------
// PlayFab helpers (only the token check remains - nothing else touches
// PlayFab in the hot path anymore)
// ---------------------------------------------------------------------------
async function playfabServerPost(path, body, timeoutMs = 3000) {
    const resp = await axios.post(`${PLAYFAB_BASE}/Server/${path}`, body, {
        headers: { "Content-Type": "application/json", "X-SecretKey": SECRET_KEY },
        timeout: timeoutMs,
    });
    return resp.data;
}

async function photonTokenAuthenticate(playFabId, photonToken, timeoutMs = 4000) {
    const resp = await axios.get(`${PLAYFAB_BASE}/photon/authenticate`, {
        params: { username: playFabId, token: photonToken },
        timeout: timeoutMs,
    });
    return resp.data;
}

async function autoBan(playFabId, ip, reason, durationHours) {
    return playfabServerPost("BanUsers", {
        Bans: [{ PlayFabId: playFabId, IPAddress: ip, DurationInHours: durationHours, Reason: reason }],
    });
}

// ---------------------------------------------------------------------------
// Discord alert helpers
// ---------------------------------------------------------------------------
async function postToWebhook(url, embed) {
    if (!url) return;
    try {
        await axios.post(url, { embeds: [embed] }, { timeout: 4000 });
    } catch (e) {
        console.error("[webhook] post failed:", e.message);
    }
}

async function sendAbuseAlert(title, fields, color = 15158332) {
    await postToWebhook(ABUSE_ALERT_WEBHOOK_URL, { title, color, fields, timestamp: new Date().toISOString() });
}

async function sendAuthStatus({ outcome, success, playFabId, ip, detail }) {
    if (!STATUS_LOG_ENABLED) return;
    await postToWebhook(AUTH_STATUS_WEBHOOK_URL, {
        title: success ? "Photon auth success" : "Photon auth failed",
        color: success ? 3066993 : 15105570,
        fields: [
            { name: "PlayFabId", value: playFabId || "unknown", inline: true },
            { name: "Outcome", value: outcome, inline: true },
            ...(detail ? [{ name: "Detail", value: String(detail).slice(0, 500), inline: false }] : []),
        ],
        timestamp: new Date().toISOString(),
    });
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------
function reject(res, message, resultCode = 2) {
    return res.status(200).json({ ResultCode: resultCode, Message: message });
}

function getClientIp(req) {
    const fwd = req.headers["x-forwarded-for"];
    if (fwd) return fwd.split(",")[0].trim();
    return req.socket?.remoteAddress || "unknown";
}

async function recordFailureAndMaybeBan(playFabId, ip) {
    const count = await bumpCounter(`authfail:${playFabId}`, ABUSE_WINDOW_SEC);
    if (count === ABUSE_BAN_THRESHOLD) {
        try {
            await autoBan(
                playFabId,
                ip,
                `${count} failed Photon auth attempts in ${ABUSE_WINDOW_SEC}s - suspected CCU/endpoint spam`,
                ABUSE_BAN_HOURS
            );
            await sendAbuseAlert("Photon auth abuse - auto-banned", [
                { name: "PlayFabId", value: playFabId, inline: true },
                { name: "IP", value: ip, inline: true },
            ]);
        } catch (e) {
            console.error("[autoBan] failed:", e.message);
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------
async function handler(req, res) {
    if (!TITLE_ID || !SECRET_KEY) {
        console.error("Missing PLAYFAB_TITLE_ID or PLAYFAB_SECRET_KEY env vars.");
        return reject(res, "Server misconfigured.", 2);
    }

    const ip = getClientIp(req);
    const playFabId = req.query.username;
    const photonToken = req.query.token;

    // ---- Cheap shape validation before any network/Redis cost ----
    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.", 3);
    }
    if (!PLAYFABID_RE.test(playFabId)) {
        return reject(res, "Malformed identity.", 3);
    }
    if (typeof photonToken !== "string" || photonToken.length < 8 || photonToken.length > 512) {
        return reject(res, "Malformed token.", 3);
    }

    // ---- Rate limiting, with a title-wide circuit breaker ----
    const globalCount = await bumpCounter(`rl:global`, GLOBAL_LIMIT.windowSec);
    const circuitOpen = globalCount !== null && globalCount > GLOBAL_LIMIT.max;
    if (circuitOpen && globalCount === GLOBAL_LIMIT.max + 1) {
        await sendAbuseAlert("Photon auth CIRCUIT BREAKER OPEN - title-wide spike", [
            { name: "Global count (60s)", value: String(globalCount), inline: true },
        ]);
    }
    const ipMax = circuitOpen ? Math.max(10, Math.floor(IP_LIMIT.max / CIRCUIT_TIGHTEN_DIVISOR)) : IP_LIMIT.max;
    const idMax = circuitOpen ? Math.max(3, Math.floor(ID_LIMIT.max / CIRCUIT_TIGHTEN_DIVISOR)) : ID_LIMIT.max;

    const ipCount = await bumpCounter(`rl:ip:${ip}`, IP_LIMIT.windowSec);
    if (ipCount !== null && ipCount > ipMax) {
        if (ipCount === ipMax + 1) {
            await sendAbuseAlert("Photon auth rate limit hit (IP)", [
                { name: "Count", value: String(ipCount), inline: true },
                { name: "Circuit open", value: String(circuitOpen), inline: true },
            ]);
        }
        return reject(res, "Too many requests.", 2);
    }

    const idCount = await bumpCounter(`rl:id:${playFabId}`, ID_LIMIT.windowSec);
    if (idCount !== null && idCount > idMax) {
        if (idCount === idMax + 1) {
            await sendAbuseAlert("Photon auth rate limit hit (PlayFabId)", [
                { name: "PlayFabId", value: playFabId, inline: true },
                { name: "IP", value: ip, inline: true },
                { name: "Count", value: String(idCount), inline: true },
            ]);
        }
        return reject(res, "Too many requests for this account.", 2);
    }
    // If bumpCounter returned null (Redis down), we deliberately don't
    // block - fail-open on infra hiccups, same as before.

    // ---- Confirm the Photon token is legit via PlayFab's real endpoint ----
    let playfabResult;
    try {
        playfabResult = await photonTokenAuthenticate(playFabId, photonToken, 4000);
    } catch (e) {
        const detail = e.response ? `upstream ${e.response.status}` : e.message;
        console.error("[gateway] PlayFab upstream call failed:", detail);
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({ outcome: "upstream_error", success: false, playFabId, ip, detail });
        return reject(res, "Upstream auth service unavailable.", 2);
    }

    if (!playfabResult || playfabResult.resultCode !== 1) {
        console.error("[gateway] PlayFab rejected auth:", JSON.stringify(playfabResult));
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({ outcome: "playfab_rejected", success: false, playFabId, ip });
        return reject(res, "PlayFab auth failed.", 2);
    }

    // ---- Ban check: Redis only, populated by your OnPlayerBanned
    // PlayStream rule hitting api/playfab/on-ban.js. No PlayFab call here. ----
    const banned = await safeGet(`ban:${playFabId}`);
    if (banned) {
        await sendAuthStatus({ outcome: "banned", success: false, playFabId, ip });
        return reject(res, "Player is banned.", 2);
    }

    // ---- CloudScript clearance check: replaces the old AntiUnity read.
    // Fast Redis flag, pushed by your CloudScript chain via
    // api/playfab/mark-clearance.js the moment anti-cheat passes. ----
    const cleared = await hasCloudScriptClearance(playFabId);
    if (!cleared) {
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({ outcome: "no_clearance", success: false, playFabId, ip });
        return reject(res, "No CloudScript clearance - anti-cheat check must run before Photon.", 2);
    }

    // Success - clear this identity's failure counter.
    await safeDel(`authfail:${playFabId}`);

    const minimalResponse = { ResultCode: 1, UserId: playfabResult.userId || playFabId };
    if (playfabResult.nickname) minimalResponse.Nickname = playfabResult.nickname;

    await sendAuthStatus({ outcome: "ok", success: true, playFabId, ip });
    return res.status(200).json(minimalResponse);
}

// Outer safety net: whatever goes wrong inside handler(), Photon's custom
// auth webservice contract still needs a clean 200 + ResultCode JSON body,
// never a raw 500 - that's what produces ReturnCode 32755 client-side.
module.exports = async function safeHandler(req, res) {
    try {
        return await handler(req, res);
    } catch (e) {
        console.error("[authenticate] unhandled exception:", e.message, e.stack);
        try {
            await sendAuthStatus({
                outcome: "unhandled_exception",
                success: false,
                playFabId: req.query?.username,
                ip: getClientIp(req),
                detail: e.message,
            });
        } catch (_) {
            // don't let the error-reporting path also crash us
        }
        return reject(res, "Internal error.", 2);
    }
};

// Needs headroom for: PlayFab token call (~4s worst case) + the clearance
// retry (400ms) + a little margin. 10s is comfortable and fits within
// Vercel Hobby's 10s cap too, unlike the v2 design which needed 20s.
module.exports.config = { maxDuration: 10 };
