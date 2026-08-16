// api/photon/authenticate.js
//
// v6 - Logging fix. Every rejection now logs unconditionally via
// console.error (visible in Vercel Function Logs) regardless of whether
// the Discord webhook is configured or whether a rate-limit threshold was
// just crossed. Previously, rate-limit rejects never logged at all, and
// the "alert on first crossing" logic silently broke whenever the circuit
// breaker tightened ipMax/idMax mid-stream (a request already past the
// new, lower limit but not exactly at old_limit+1 would be rejected with
// zero trace anywhere). If you were seeing "some players never get
// authed, no logs, no errors" - this was almost certainly why, alongside
// any Vercel Firewall custom rules that deny before the function even
// runs (those won't show up here either - check your Firewall dashboard
// activity log separately).
//
// v5 - Redis (Upstash) swapped for a Postgres-backed store (see
// lib/store.js) after the Redis free tier's request cap got maxed out
// by this endpoint's own traffic (3 rate-limit counters + a ban check +
// a poll loop, per auth request).
//
// Behavior is otherwise unchanged from v4 - same rate limiting, same
// circuit breaker, same poll-until-deadline clearance check. Only the
// storage backend changed. See lib/store.js for setup (DATABASE_URL env
// var, replacing KV_REST_API_URL / KV_REST_API_TOKEN).
//
// ============================================================================
// v4 -> v5 CHANGE: fewer round trips where it was easy to combine them
// ============================================================================
// Postgres round trips cost more than Redis round trips latency-wise, so
// this version collapses the two most obviously combinable Redis calls -
// the ban check and the first clearance check - is NOT done here, since
// they're logically independent and combining them would make the code
// harder to follow for a marginal saving. If you find the added Postgres
// latency is eating into your poll budget too much, the biggest win would
// be raising CLEARANCE_POLL_INTERVAL_MS or moving the ban check to only
// run when a request looks suspicious, not on every single auth call.
// ============================================================================
//
// ============================================================================
// (retained from v4) WHAT CHANGED FROM v3
// ============================================================================
// v3 checked for the "cleared" flag once, waited 400ms, checked once more,
// and gave up. That's fine if CustomIDChecker runs via a direct
// ExecuteCloudScript call the client is waiting on - but if it's actually
// wired up as a PlayStream rule (fired off a login event), there's no
// client-side callback to wait on and no bound on how fast the rule
// executes. A single 400ms retry isn't "we checked and it's not there" in
// that setup, it's "we barely looked."
//
// v4 replaced the fixed retry with a poll loop against a real deadline:
// it keeps checking on a short interval until either the flag shows up,
// or the function is genuinely out of time to keep waiting (bounded by
// maxDuration, minus a safety margin for the response itself). Only THEN
// does it report no_clearance.
//
// IMPORTANT: this budget is shared with the PlayFab token call earlier in
// the handler, which can itself take up to ~4s worst case. maxDuration
// below is set assuming a paid Vercel plan (Pro/Enterprise) that allows
// raising it past 10s. If you're on Vercel Hobby, maxDuration is hard-
// capped at 10s and CANNOT be raised - in that case the clearance poll
// only gets whatever's left after the PlayFab call. Check your plan
// before assuming this fully closes the race; if you're stuck on Hobby,
// the real fix is still getting CustomIDChecker to finish (and push
// clearance) before the client's first Photon connect attempt, not just
// waiting longer here.
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

// ---- Clearance polling ----
// How often to re-check while waiting for CloudScript to push the
// clearance flag. Left at 400ms from v4 - if Postgres latency makes this
// feel slow in practice, raising it to 600-800ms is the first knob to try.
const CLEARANCE_POLL_INTERVAL_MS = 400;

// Overall function time budget. Must be set to match module.exports.config
// below - keep these two in sync if you change one.
const FUNCTION_BUDGET_MS = 25000;

// Reserved so the function always has time to build and send its response
// even if the poll loop runs right up to the edge - never spend the whole
// budget polling.
const RESPONSE_SAFETY_MARGIN_MS = 1500;

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

// Polls the "cleared" flag written by mark-clearance.js until it shows up
// or the deadline passes. deadlineMs is an absolute Date.now()-style
// timestamp, not a duration - the caller computes it from the function's
// remaining budget so this never runs past the response safety margin.
async function hasCloudScriptClearance(playFabId, deadlineMs) {
    const key = `cleared:${playFabId}`;

    const first = await safeGet(key);
    if (first) return true;

    while (Date.now() < deadlineMs) {
        const remaining = deadlineMs - Date.now();
        const wait = Math.min(CLEARANCE_POLL_INTERVAL_MS, remaining);
        if (wait <= 0) break;
        await new Promise((r) => setTimeout(r, wait));

        const check = await safeGet(key);
        if (check) return true;
    }

    // Genuinely out of time - this is a real no_clearance, not a premature one.
    return false;
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
// v6: reject() now ALWAYS console.errors when meta is passed, independent
// of the Discord webhook and independent of any threshold-crossing logic.
// This is the fix for "some players fail with no logs anywhere" - previously
// rate-limit rejections never logged at all, and every other outcome only
// logged if AUTH_STATUS_WEBHOOK_URL happened to be set AND the webhook post
// succeeded. Vercel's own Function Logs are now the reliable source of
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
    const requestStartedAt = Date.now();
    const hardDeadline = requestStartedAt + FUNCTION_BUDGET_MS - RESPONSE_SAFETY_MARGIN_MS;

    if (!TITLE_ID || !SECRET_KEY) {
        console.error("Missing PLAYFAB_TITLE_ID or PLAYFAB_SECRET_KEY env vars.");
        return reject(res, "Server misconfigured.", 2);
    }

    const ip = getClientIp(req);
    const playFabId = req.query.username;
    const photonToken = req.query.token;

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
        // v6: log every single IP rate-limit rejection, not just the one
        // where ipCount happens to equal ipMax + 1. That equality check
        // only ever holds true under a STABLE limit - the instant the
        // circuit breaker tightens ipMax mid-stream, ipCount can jump
        // straight past the new ceiling without ever landing on exactly
        // ipMax + 1, which used to mean total silence on every rejection
        // that followed.
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

    // ---- CloudScript clearance check: polls until the flag shows up or
    // the function's genuinely out of time to keep waiting. See the v4
    // header comment for why this isn't a single quick retry anymore. ----
    const cleared = await hasCloudScriptClearance(playFabId, hardDeadline);
    if (!cleared) {
        const waitedMs = Date.now() - requestStartedAt;
        console.error(`[gateway] no_clearance for ${playFabId} after ${waitedMs}ms of polling, ip:`, ip);
        await recordFailureAndMaybeBan(playFabId, ip);
        await sendAuthStatus({
            outcome: "no_clearance",
            success: false,
            playFabId,
            ip,
            detail: `waited ${waitedMs}ms`,
        });
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

// Must match FUNCTION_BUDGET_MS above (in seconds). 25s assumes a Vercel
// plan that allows raising maxDuration past the Hobby tier's hard 10s cap
// - check Project Settings -> Functions on your plan. If you're stuck on
// Hobby, set this back to 10 and FUNCTION_BUDGET_MS to 10000; the poll
// loop will just have less room to work with.
module.exports.config = { maxDuration: 25 };
