// api/photon/authenticate.js
//
// v9 - PlayFab token verification REMOVED. This is intentional and
// TEMPORARY, at the user's explicit request, to get players playing while
// the auth chain gets rebuilt properly. Read this before touching anything
// else in this file.
//
// WHAT THIS MEANS: photonTokenAuthenticate() (the call to PlayFab's real
// /photon/authenticate endpoint that used to confirm the token actually
// belongs to that playFabId) is gone. This handler now only checks:
//   1. Request shape (16-char hex ID, token is a non-trivial string)
//   2. Rate limits / circuit breaker
//   3. Local ban list
// It does NOT verify the token is real. Anyone who can produce a
// well-formed playFabId + any string 8-512 chars long as "token" gets a
// ResultCode: 1 back. This is genuinely weak auth - fine as a stopgap,
// not fine as a permanent state. When you're ready to tighten this back
// up, reintroduce a real credential check here (this used to be the
// PlayFab token call; it doesn't have to be that specific mechanism again,
// but it has to be SOMETHING that actually verifies the caller owns the
// identity, not just that the identity is well-formed).
//
// The PlayFab Server API (TITLE_ID/SECRET_KEY) is still used for BanUsers
// - actual anti-spam/anti-abuse enforcement is unaffected, only identity
// verification is off.
//
// Everything else (CloudScript clearance polling, device check) was
// already removed in prior versions - see git history / prior versions of
// this file for that context if you need it later.

const axios = require("axios");
const { kvGet, kvIncr, kvDel } = require("../../lib/store");

// ---------------------------------------------------------------------------
// Config / env
// ---------------------------------------------------------------------------
const TITLE_ID = process.env.PLAYFAB_TITLE_ID;
const SECRET_KEY = process.env.PLAYFAB_SECRET_KEY;
const PLAYFAB_BASE = `https://${TITLE_ID}.playfabapi.com`;
const ABUSE_ALERT_WEBHOOK_URL = process.env.ABUSE_ALERT_WEBHOOK_URL;
const AUTH_STATUS_WEBHOOK_URL = process.env.AUTH_STATUS_WEBHOOK_URL;
const STATUS_LOG_ENABLED = !!AUTH_STATUS_WEBHOOK_URL;

// ---- Rate limiting tunables ----
// Photon Cloud's custom auth webhook is called SERVER-SIDE by Photon's own
// infrastructure. The x-forwarded-for IP is very likely a shared Photon
// relay/egress IP, not a per-player signal, and a single real player can
// legitimately trigger this webhook 5-6 times in a few seconds. Don't
// tighten these back down without re-confirming that lesson still holds.
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

// ---------------------------------------------------------------------------
// Store helpers (never throw uncaught)
// ---------------------------------------------------------------------------
async function safeGet(key) {
    try {
        return await kvGet(key);
    } catch (e) {
        console.error("[store] get failed:", key, e.message);
        return null;
    }
}

async function safeDel(key) {
    try {
        await kvDel(key);
    } catch (e) {
        console.error("[store] del failed:", key, e.message);
    }
}

async function bumpCounter(key, windowSec) {
    try {
        return await kvIncr(key, windowSec);
    } catch (e) {
        console.error("[store] bumpCounter failed:", key, e.message);
        return null; // null = "couldn't check," distinct from "over limit"
    }
}

// ---------------------------------------------------------------------------
// PlayFab helpers (BanUsers only now - identity verification removed)
// ---------------------------------------------------------------------------
async function playfabServerPost(path, body, timeoutMs = 3000) {
    const resp = await axios.post(`${PLAYFAB_BASE}/Server/${path}`, body, {
        headers: { "Content-Type": "application/json", "X-SecretKey": SECRET_KEY },
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
// reject() ALWAYS console.errors when meta is passed, independent of the
// Discord webhook. Vercel's own Function Logs are the reliable source of
// truth regardless of webhook config.
function reject(res, message, resultCode = 2, meta = null) {
    if (meta) {
        console.error("[gateway] reject:", message, JSON.stringify(meta));
    }
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

    // ---- Cheap shape validation - this is now the ONLY identity check ----
    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.", 3, { ip });
    }
    if (!PLAYFABID_RE.test(playFabId)) {
        return reject(res, "Malformed identity.", 3, { ip, playFabId });
    }
    if (typeof photonToken !== "string" || photonToken.length < 8 || photonToken.length > 512) {
        return reject(res, "Malformed token.", 3, { ip, playFabId });
    }

    // ---- Rate limiting, with a title-wide circuit breaker ----
    const globalCount = await bumpCounter(`rl:global`, GLOBAL_LIMIT.windowSec);
    const circuitOpen = globalCount !== null && globalCount > GLOBAL_LIMIT.max;
    if (circuitOpen && globalCount === GLOBAL_LIMIT.max + 1) {
        console.error("[gateway] CIRCUIT BREAKER OPEN - global count:", globalCount);
        await sendAbuseAlert("Photon auth CIRCUIT BREAKER OPEN - title-wide spike", [
            { name: "Global count (60s)", value: String(globalCount), inline: true },
        ]);
    }
    const ipMax = circuitOpen ? Math.max(10, Math.floor(IP_LIMIT.max / CIRCUIT_TIGHTEN_DIVISOR)) : IP_LIMIT.max;
    const idMax = circuitOpen ? Math.max(3, Math.floor(ID_LIMIT.max / CIRCUIT_TIGHTEN_DIVISOR)) : ID_LIMIT.max;

    const ipCount = await bumpCounter(`rl:ip:${ip}`, IP_LIMIT.windowSec);
    if (ipCount !== null && ipCount > ipMax) {
        console.error("[gateway] IP rate limited:", ip, `${ipCount}/${ipMax}`, "circuitOpen:", circuitOpen, "playFabId:", playFabId);
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
        console.error("[gateway] ID rate limited:", playFabId, `${idCount}/${idMax}`, "circuitOpen:", circuitOpen, "ip:", ip);
        if (idCount === idMax + 1) {
            await sendAbuseAlert("Photon auth rate limit hit (PlayFabId)", [
                { name: "PlayFabId", value: playFabId, inline: true },
                { name: "IP", value: ip, inline: true },
                { name: "Count", value: String(idCount), inline: true },
            ]);
        }
        return reject(res, "Too many requests for this account.", 2);
    }
    // If bumpCounter returned null (store down), we deliberately don't
    // block - fail-open on infra hiccups, same as before.

    // ---- Ban check: store only, populated by your OnPlayerBanned
    // PlayStream rule hitting api/playfab/on-ban.js. No PlayFab call here. ----
    const banned = await safeGet(`ban:${playFabId}`);
    if (banned) {
        console.error("[gateway] banned player attempted auth:", playFabId, "ip:", ip);
        await sendAuthStatus({ outcome: "banned", success: false, playFabId, ip });
        return reject(res, "Player is banned.", 2);
    }

    // ---- No PlayFab identity check anymore - see header note. ----
    // Success - clear this identity's failure counter.
    await safeDel(`authfail:${playFabId}`);

    const minimalResponse = { ResultCode: 1, UserId: playFabId };

    await sendAuthStatus({ outcome: "ok (weak auth - no token verification)", success: true, playFabId, ip });
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

// No external calls left in the hot path except the occasional BanUsers
// call and Discord webhooks, both fire-and-forget-ish. This can run short.
module.exports.config = { maxDuration: 8 };
