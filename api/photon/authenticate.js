// api/photon/authenticate.js
//
// v7 - CloudScript clearance removed entirely.
//
// The old flow was: client logs in -> PlayFab fires CustomIDChecker via
// CloudScript -> CloudScript POSTs to mark-clearance.js -> this file polls
// the "cleared" flag for up to ~23s before giving up. That chain had two
// independent failure points we confirmed in Vercel logs: (1) mark-clearance
// returning 400 (clearance never got written), and (2) a suspicion that
// PlayFab CloudScript itself was getting rate-limited under load, so
// CustomIDChecker sometimes never fired or finished in time. Either one
// silently ate real players with no_clearance after a long poll.
//
// New flow: the client sends its device model as an extra query param on
// the same Photon custom-auth request it already makes (alongside
// username/token). This file checks it against an allowlist SYNCHRONOUSLY,
// in the same request, with no async round trip to anything. No CloudScript,
// no webhook push, no polling, no race condition, no mark-clearance.js.
//
// TRADEOFF: this is a plain client-supplied string, not a cryptographic
// attestation - Meta doesn't expose a public API for proving genuine
// hardware server-side, and CloudScript's AntiUnity check was working from
// the same kind of signal anyway. This isn't materially weaker than what
// you had; it's just synchronous and reliable instead of async and flaky.
//
// ============================================================================
// ROLLOUT: DEVICE_CHECK_ENFORCE
// ============================================================================
// Set DEVICE_CHECK_ENFORCE=false (or leave unset) to start: every request
// still gets authenticated normally, but any device model NOT in
// ALLOWED_DEVICE_MODELS just gets logged as "[device-check] would reject"
// instead of actually rejected. Watch Vercel logs for a while, see what
// real strings your players' clients are actually sending, and add any
// missing legitimate ones to ALLOWED_DEVICE_MODELS. Once logs are clean
// (no more unexpected "would reject" entries from real players), set
// DEVICE_CHECK_ENFORCE=true to start actually rejecting.
// ============================================================================

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

// ---- Device check ----
// Fill this in from real log output (see rollout note above). These are
// common Quest-family strings as a starting point ONLY - don't trust them
// blind, confirm against what your own client actually sends.
const ALLOWED_DEVICE_MODELS = new Set([
    "Quest",
    "Quest 2",
    "Quest 3",
    "Quest 3S",
    "Quest Pro",
    "Oculus Quest",
    "Oculus Quest2",
]);
const DEVICE_CHECK_ENFORCE = process.env.DEVICE_CHECK_ENFORCE === "true";

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
// PlayFab helpers
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
// reject() ALWAYS console.errors when meta is passed, independent of the
// Discord webhook and independent of any threshold-crossing logic. Vercel's
// own Function Logs are the reliable source of truth regardless of webhook
// config.
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

// Checks the device model against the allowlist. In log-only mode
// (DEVICE_CHECK_ENFORCE=false), a bad model is logged but NOT rejected -
// use this phase to build ALLOWED_DEVICE_MODELS from real traffic before
// flipping enforcement on.
function checkDeviceModel(deviceModel, playFabId, ip) {
    const ok = typeof deviceModel === "string" && ALLOWED_DEVICE_MODELS.has(deviceModel);
    if (!ok) {
        console.error(
            DEVICE_CHECK_ENFORCE ? "[device-check] rejecting:" : "[device-check] would reject (log-only):",
            JSON.stringify({ deviceModel: deviceModel || null, playFabId, ip })
        );
    }
    return ok || !DEVICE_CHECK_ENFORCE;
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
    // New: client includes this alongside username/token on the same
    // Photon custom-auth request. Configure this as an extra entry in
    // Photon's AuthValues.AuthGetParameters on the client side.
    const deviceModel = req.query.deviceModel;

    // ---- Cheap shape validation before any network/store cost ----
    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.", 3, { ip });
    }
    if (!PLAYFABID_RE.test(playFabId)) {
        return reject(res, "Malformed identity.", 3, { ip, playFabId });
    }
    if (typeof photonToken !== "string" || photonToken.length < 8 || photonToken.length > 512) {
        return reject(res, "Malformed token.", 3, { ip, playFabId });
    }

    // ---- Device check (replaces CloudScript AntiUnity + clearance chain) ----
    if (!checkDeviceModel(deviceModel, playFabId, ip)) {
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({
            outcome: "device_check_failed",
            success: false,
            playFabId,
            ip,
            detail: deviceModel || "(missing)",
        });
        return reject(res, "Device check failed.", 2, { ip, playFabId, deviceModel });
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

    // ---- Confirm the Photon token is legit via PlayFab's real endpoint ----
    let playfabResult;
    try {
        playfabResult = await photonTokenAuthenticate(playFabId, photonToken, 4000);
    } catch (e) {
        const detail = e.response ? `upstream ${e.response.status}` : e.message;
        console.error("[gateway] PlayFab upstream call failed:", detail, "playFabId:", playFabId);
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({ outcome: "upstream_error", success: false, playFabId, ip, detail });
        return reject(res, "Upstream auth service unavailable.", 2);
    }

    if (!playfabResult || playfabResult.resultCode !== 1) {
        console.error("[gateway] PlayFab rejected auth:", JSON.stringify(playfabResult), "playFabId:", playFabId);
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({ outcome: "playfab_rejected", success: false, playFabId, ip });
        return reject(res, "PlayFab auth failed.", 2);
    }

    // ---- Ban check: store only, populated by your OnPlayerBanned
    // PlayStream rule hitting api/playfab/on-ban.js. No PlayFab call here. ----
    const banned = await safeGet(`ban:${playFabId}`);
    if (banned) {
        console.error("[gateway] banned player attempted auth:", playFabId, "ip:", ip);
        await sendAuthStatus({ outcome: "banned", success: false, playFabId, ip });
        return reject(res, "Player is banned.", 2);
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

// No more polling, so this can be much shorter than the old 25s budget.
// PlayFab token check (4s) + a couple of store round trips is normally
// well under 2s total; 8s leaves comfortable headroom.
module.exports.config = { maxDuration: 8 };
