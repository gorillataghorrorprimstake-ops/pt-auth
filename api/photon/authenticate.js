// api/photon/authenticate.js

const axios = require("axios");
const { Redis } = require("@upstash/redis");

const TITLE_ID = process.env.PLAYFAB_TITLE_ID;
const SECRET_KEY = process.env.PLAYFAB_SECRET_KEY;
const PLAYFAB_BASE = `https://${TITLE_ID}.playfabapi.com`;
const ABUSE_ALERT_WEBHOOK_URL = process.env.ABUSE_ALERT_WEBHOOK_URL;
const AUTH_STATUS_WEBHOOK_URL = process.env.AUTH_STATUS_WEBHOOK_URL;

const redis = new Redis({
    url: process.env.KV_REST_API_URL,
    token: process.env.KV_REST_API_TOKEN,
});

const IP_LIMIT = { windowSec: 60, max: 20 };        // 20 auth attempts/min per IP
const ID_LIMIT = { windowSec: 30, max: 5 };          // 5 auth attempts/30s per PlayFabId
const ABUSE_BAN_THRESHOLD = 15;                      // failed attempts in ABUSE_WINDOW -> autoban
const ABUSE_WINDOW_SEC = 120;
const ABUSE_BAN_HOURS = 24;
const PASS_CACHE_TTL_SEC = 20;                       // cache a passing AntiUnity check briefly
const PLAYFABID_RE = /^[0-9A-F]{16}$/i;               // PlayFab IDs are 16 hex chars

// Status-log tunables — keep this from becoming a spam cannon into Discord
// under a CCU flood. Only fire status pings while under the per-IP limit;
// once someone's rate-limited we already emit a separate one-time alert.
const STATUS_LOG_ENABLED = !!AUTH_STATUS_WEBHOOK_URL;

async function playfabServerPost(path, body) {
    const resp = await axios.post(`${PLAYFAB_BASE}/Server/${path}`, body, {
        headers: { "Content-Type": "application/json", "X-SecretKey": SECRET_KEY },
        timeout: 5000,
    });
    return resp.data;
}

function reject(res, message, resultCode = 2) {
    return res.status(200).json({ ResultCode: resultCode, Message: message });
}

function getClientIp(req) {
    const fwd = req.headers["x-forwarded-for"];
    if (fwd) return fwd.split(",")[0].trim();
    return req.socket?.remoteAddress || "unknown";
}

async function bumpCounter(key, windowSec) {
    const count = await redis.incr(key);
    if (count === 1) {
        await redis.expire(key, windowSec);
    }
    return count;
}

async function postToWebhook(url, embed) {
    if (!url) return;
    try {
        await axios.post(url, { embeds: [embed] }, { timeout: 4000 });
    } catch (e) {
        console.error("[webhook] post failed:", e.message);
    }
}

async function sendAbuseAlert(title, fields) {
    await postToWebhook(ABUSE_ALERT_WEBHOOK_URL, {
        title,
        color: 15158332, // red
        fields,
        timestamp: new Date().toISOString(),
    });
}

async function sendAuthStatus({ outcome, success, playFabId, ip, detail }) {
    if (!STATUS_LOG_ENABLED) return;
    await postToWebhook(AUTH_STATUS_WEBHOOK_URL, {
        title: success ? "Photon auth success" : "Photon auth failed",
        color: success ? 3066993 : 15105570, // green / orange
        fields: [
            { name: "PlayFabId", value: playFabId || "unknown", inline: true },
            { name: "Outcome", value: outcome, inline: true },
            ...(detail ? [{ name: "Detail", value: String(detail).slice(0, 500), inline: false }] : []),
        ],
        timestamp: new Date().toISOString(),
    });
}

async function autoBan(playFabId, ip, reason) {
    try {
        await playfabServerPost("BanUsers", {
            Bans: [{ PlayFabId: playFabId, IPAddress: ip, DurationInHours: ABUSE_BAN_HOURS, Reason: reason }],
        });
        await sendAbuseAlert("Photon auth abuse - auto-banned", [
            { name: "PlayFabId", value: playFabId, inline: true },
            { name: "IP", value: ip, inline: true },
            { name: "Reason", value: reason, inline: false },
        ]);
    } catch (e) {
        console.error("[autoBan] failed:", e.message);
    }
}

async function isBanned(playFabId) {
    try {
        const data = await playfabServerPost("GetUserAccountInfo", { PlayFabId: playFabId });
        const banned = data?.data?.UserInfo?.PrivateInfo?.BannedUntil;
        return !!banned;
    } catch (e) {
        console.error("[isBanned] lookup failed:", e.message);
        return true; // fail closed
    }
}

async function hasValidAntiUnityPass(playFabId) {
    const cacheKey = `auc:${playFabId}`;
    try {
        const cached = await redis.get(cacheKey);
        if (cached === "1") return true;
        if (cached === "0") return false;
    } catch (e) {
        console.error("[hasValidAntiUnityPass] cache read failed, continuing to PlayFab:", e.message);
    }

    try {
        const data = await playfabServerPost("GetUserInternalData", {
            PlayFabId: playFabId,
            Keys: ["AntiUnityAuthPass"],
        });
        const raw = data?.data?.Data?.AntiUnityAuthPass?.Value;
        if (!raw) {
            await safeRedisSet(cacheKey, "0", PASS_CACHE_TTL_SEC);
            return false;
        }
        const record = JSON.parse(raw);
        const MAX_AGE_MS = 12 * 60 * 60 * 1000;
        const valid = record.passed === true && (Date.now() - record.timestamp) < MAX_AGE_MS;
        await safeRedisSet(cacheKey, valid ? "1" : "0", PASS_CACHE_TTL_SEC);
        return valid;
    } catch (e) {
        console.error("[hasValidAntiUnityPass] lookup failed:", e.message);
        return false; // fail closed
    }
}

// Redis is a nice-to-have cache here, never a reason to blow up the request.
async function safeRedisSet(key, value, ttlSec) {
    try {
        await redis.set(key, value, { ex: ttlSec });
    } catch (e) {
        console.error("[redis] set failed (non-fatal):", key, e.message);
    }
}

// Was previously called with no try/catch anywhere it's used. A Redis
// hiccup here used to throw uncaught -> Vercel 500 -> Photon client sees
// ReturnCode 32755 "Internal Server Error" instead of a clean auth reject.
// Failure tracking is best-effort; never let it take the request down.
async function recordFailureAndMaybeBan(playFabId, ip) {
    try {
        const key = `authfail:${playFabId}`;
        const count = await bumpCounter(key, ABUSE_WINDOW_SEC);
        if (count === ABUSE_BAN_THRESHOLD) {
            await autoBan(
                playFabId,
                ip,
                `${count} failed Photon auth attempts in ${ABUSE_WINDOW_SEC}s - suspected CCU/endpoint spam`
            );
        }
        return count;
    } catch (e) {
        console.error("[recordFailureAndMaybeBan] failed (non-fatal):", e.message);
        return null;
    }
}

async function handler(req, res) {
    if (!TITLE_ID || !SECRET_KEY) {
        console.error("Missing PLAYFAB_TITLE_ID or PLAYFAB_SECRET_KEY env vars.");
        return reject(res, "Server misconfigured.", 2);
    }

    const ip = getClientIp(req);
    const playFabId = req.query.username;
    const photonToken = req.query.token;

    // ---- Cheap shape validation BEFORE any network/Redis cost ----
    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.", 3);
    }
    if (!PLAYFABID_RE.test(playFabId)) {
        // Not even shaped like a real PlayFabId - don't waste a rate-limit
        // slot, an upstream call, or a webhook post on it, just bounce it.
        return reject(res, "Malformed identity.", 3);
    }
    if (typeof photonToken !== "string" || photonToken.length < 8 || photonToken.length > 512) {
        return reject(res, "Malformed token.", 3);
    }

    // ---- Rate limiting, before any expensive calls ----
    try {
        const ipCount = await bumpCounter(`rl:ip:${ip}`, IP_LIMIT.windowSec);
        if (ipCount > IP_LIMIT.max) {
            if (ipCount === IP_LIMIT.max + 1) {
                await sendAbuseAlert("Photon auth rate limit hit (IP)", [
                    { name: "IP", value: ip, inline: true },
                    { name: "Count", value: String(ipCount), inline: true },
                ]);
            }
            return reject(res, "Too many requests.", 2);
        }

        const idCount = await bumpCounter(`rl:id:${playFabId}`, ID_LIMIT.windowSec);
        if (idCount > ID_LIMIT.max) {
            if (idCount === ID_LIMIT.max + 1) {
                await sendAbuseAlert("Photon auth rate limit hit (PlayFabId)", [
                    { name: "PlayFabId", value: playFabId, inline: true },
                    { name: "IP", value: ip, inline: true },
                    { name: "Count", value: String(idCount), inline: true },
                ]);
            }
            return reject(res, "Too many requests for this account.", 2);
        }
    } catch (e) {
        // If Redis itself is down, don't fail the whole auth pipeline open -
        // just skip rate limiting for this request and log it.
        console.error("[ratelimit] redis error, skipping limiter:", e.message);
    }

    // ---- Step 1: confirm the Photon token is legit via PlayFab's real endpoint ----
    let playfabResult;
    try {
        const upstream = await axios.get(`${PLAYFAB_BASE}/photon/authenticate`, {
            params: { username: playFabId, token: photonToken },
            timeout: 5000,
        });
        playfabResult = upstream.data;
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

    // ---- Step 2: our own extra gate ----
    const [banned, hasPass] = await Promise.all([
        isBanned(playFabId),
        hasValidAntiUnityPass(playFabId),
    ]);

    if (banned) {
        await sendAuthStatus({ outcome: "banned", success: false, playFabId, ip });
        return reject(res, "Player is banned.", 2);
    }

    if (!hasPass) {
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({ outcome: "no_antiunity_pass", success: false, playFabId, ip });
        return reject(res, "No valid AntiUnity ticket - device check must pass before Photon.", 2);
    }

    // Success - clear this identity's failure counter so a bad streak
    // doesn't linger against someone who just fixed their state.
    try {
        await redis.del(`authfail:${playFabId}`);
    } catch (e) {
        // non-fatal
    }

    const minimalResponse = { ResultCode: 1, UserId: playfabResult.userId || playFabId };
    if (playfabResult.nickname) {
        minimalResponse.Nickname = playfabResult.nickname;
    }

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
