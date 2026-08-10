// api/photon/authenticate.js
//
// v2 - full rewrite, single-file.
//
// ============================================================================
// WHY THIS EXISTS
// ============================================================================
// v1 was a "strict gate": every check (PlayFab token, ban, AntiUnity pass)
// had to succeed synchronously before Photon would let a player in. That
// meant any transient slowness anywhere in that chain - most commonly
// PlayFab's internal-data write for AntiUnityAuthPass not having propagated
// yet - hard-rejected a real player who'd done nothing wrong.
//
// v2 splits checks into two tiers:
//   HARD checks  (fail fast, reject immediately): malformed request, rate
//                limit, PlayFab token itself invalid, CONFIRMED ban,
//                EXPLICITLY failed AntiUnity check.
//   SOFT checks  (ambiguous / not yet resolvable): AntiUnity pass record
//                doesn't exist yet, or the PlayFab read timed out/errored.
//                These no longer reject. The player is admitted, and
//                verification continues in the background via waitUntil()
//                for a few seconds after the response is already sent to
//                Photon. If it resolves to an explicit failure, we kick
//                them.
//
// This is a deliberate security/availability tradeoff: a bot gets a few
// extra seconds of connection time in the worst case; a real player never
// gets falsely rejected by a propagation-delay race again.
//
// Ban checking also moved OFF the PlayFab hot path entirely - bans are
// pushed into Redis by a separate small webhook the moment PlayFab's
// OnPlayerBanned PlayStream rule fires, so this webhook never calls
// PlayFab's GetUserAccountInfo at all. See the "Ban check" comment below
// for what that side needs to look like.
//
// NOTE ON GOING SOLO-FILE: everything (Redis helpers, PlayFab helpers,
// Discord alert helpers, provisional-admit queue, kick stub) lives in this
// one file now instead of being split across lib/. If you later want a
// cron backstop sweep for anything the inline waitUntil check misses,
// that'd be a second file reusing the same Redis key shapes
// (`provisional_admits`, `provisional_ip:{id}`) defined below.
// ============================================================================

const axios = require("axios");
const { Redis } = require("@upstash/redis");
const { waitUntil } = require("@vercel/functions");

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
// IP/ID limits kept at the values you already fought hard to get right -
// Photon Cloud's custom auth webhook is called SERVER-SIDE by Photon's own
// infrastructure. The x-forwarded-for IP is very likely a shared Photon
// relay/egress IP, not a per-player signal, and a single real player can
// legitimately trigger this webhook 5-6 times in a few seconds (name
// server, master server, game server, region pings, reconnects). Don't
// tighten these back down without re-confirming that lesson still holds.
const IP_LIMIT = { windowSec: 60, max: 300 };
const ID_LIMIT = { windowSec: 30, max: 20 };

// Title-wide circuit breaker - NEW in v2. IP/ID limits catch a single
// abuser; this catches distributed CCU farming (many IDs, many IPs,
// deliberately spread out to dodge the per-key limits). If total new-auth
// volume across the whole title spikes far past a normal baseline, we
// tighten everyone's effective limits for a bit and alert. Tune the max
// to your real peak CCU pattern before relying on this.
const GLOBAL_LIMIT = { windowSec: 60, max: 1500 };
const CIRCUIT_TIGHTEN_DIVISOR = 4; // while circuit is open, effective IP/ID max is /4

const PLAYFABID_RE = /^[0-9A-F]{16}$/i;
const ABUSE_BAN_THRESHOLD = 15;
const ABUSE_WINDOW_SEC = 120;
const ABUSE_BAN_HOURS = 24;

// Inline verification schedule (ms after the response has already been
// sent to Photon). Two checks: a quick one to catch the common "landed a
// second later" case, a slower one as a second chance.
const INLINE_VERIFY_DELAYS_MS = [3000, 7000];

const PROVISIONAL_SET_KEY = "provisional_admits";

// ---------------------------------------------------------------------------
// Redis helpers (never throw uncaught - Redis flaking is "degrade
// gracefully", not "crash the auth pipeline")
// ---------------------------------------------------------------------------
async function safeGet(key) {
    try {
        return await redis.get(key);
    } catch (e) {
        console.error("[redis] get failed:", key, e.message);
        return null;
    }
}

async function safeSet(key, value, ttlSec) {
    try {
        if (ttlSec) await redis.set(key, value, { ex: ttlSec });
        else await redis.set(key, value);
    } catch (e) {
        console.error("[redis] set failed:", key, e.message);
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
    // Returns null on Redis failure so callers can distinguish "genuinely
    // over limit" from "couldn't check" - those are NOT treated the same.
    try {
        const count = await redis.incr(key);
        if (count === 1) await redis.expire(key, windowSec);
        return count;
    } catch (e) {
        console.error("[redis] bumpCounter failed:", key, e.message);
        return null;
    }
}

async function addProvisional(playFabId, ip) {
    try {
        await redis.zadd(PROVISIONAL_SET_KEY, { score: Date.now(), member: playFabId });
        await safeSet(`provisional_ip:${playFabId}`, ip, 300);
    } catch (e) {
        console.error("[redis] addProvisional failed:", e.message);
    }
}

async function removeProvisional(playFabId) {
    try {
        await redis.zrem(PROVISIONAL_SET_KEY, playFabId);
    } catch (e) {
        console.error("[redis] removeProvisional failed:", e.message);
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

// Single, un-retried read of the AntiUnityAuthPass record. Returns one of:
//   { status: "valid" }
//   { status: "no_record" }      - not written yet (race) or never ran
//   { status: "failed" }         - explicitly failed the check
//   { status: "expired" }        - passed once, too long ago
//   { status: "error", detail }  - PlayFab call itself broke (network/timeout)
async function readAntiUnityPass(playFabId, timeoutMs = 1500) {
    try {
        const data = await playfabServerPost(
            "GetUserInternalData",
            { PlayFabId: playFabId, Keys: ["AntiUnityAuthPass"] },
            timeoutMs
        );
        const raw = data?.data?.Data?.AntiUnityAuthPass?.Value;
        if (!raw) return { status: "no_record" };

        const record = JSON.parse(raw);
        const MAX_AGE_MS = 12 * 60 * 60 * 1000;
        if (record.passed !== true) return { status: "failed" };
        if (Date.now() - record.timestamp >= MAX_AGE_MS) return { status: "expired" };
        return { status: "valid" };
    } catch (e) {
        return { status: "error", detail: e.message };
    }
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
// Kick function - *** NEEDS YOUR ACTUAL PHOTON KICK CALL WIRED IN ***
// ---------------------------------------------------------------------------
// This is the one piece I'm not fabricating a fake endpoint for. Paste me
// whatever mechanism you already have set up to forcibly disconnect a
// specific actor/session in Photon (Server Plugin webhook call, self-hosted
// Photon Server admin call, a "banned list" clients poll and self-kick
// against, etc.) and I'll wire it in below. Until then, this stub logs
// loudly + alerts Discord so a missed kick is obvious instead of silent.
async function kickPlayer(playFabId, reason) {
    console.warn(`[photonKick] STUB CALLED - would kick ${playFabId}. Reason: ${reason}`);

    // TODO: replace with your real kick call, e.g.:
    //
    //   await axios.post(`https://<your-photon-endpoint>/kick`, {
    //       appId: process.env.PHOTON_APP_ID,
    //       userId: playFabId,
    //   }, {
    //       headers: { Authorization: `Bearer ${process.env.PHOTON_AUTH_TOKEN}` },
    //   });

    await sendAbuseAlert(
        "Photon kick STUB fired (not wired up yet)",
        [
            { name: "PlayFabId", value: playFabId, inline: true },
            { name: "Reason", value: reason, inline: false },
        ],
        16776960 // yellow - "you need to fix this," not a real ban alert
    );
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

// Background verification, scheduled via waitUntil() so it runs AFTER the
// response has already gone back to Photon. Never blocks the player.
async function verifyProvisionalInBackground(playFabId, ip) {
    for (const delay of INLINE_VERIFY_DELAYS_MS) {
        await new Promise((r) => setTimeout(r, delay));

        const result = await readAntiUnityPass(playFabId);

        if (result.status === "valid") {
            await removeProvisional(playFabId);
            return; // confirmed clean, done
        }

        if (result.status === "failed" || result.status === "expired") {
            await removeProvisional(playFabId);
            await kickPlayer(playFabId, `AntiUnity check resolved to "${result.status}" after provisional admit`);
            await sendAuthStatus({
                outcome: "provisional_kicked",
                success: false,
                playFabId,
                ip,
                detail: result.status,
            });
            return;
        }

        // still no_record / error - loop to the next delay, or fall through
        // and give up (leave it in the provisional set - if you add a cron
        // sweep later, it can pick these stragglers up).
    }

    console.warn(`[authenticate] ${playFabId} still unresolved after inline verification window`);
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
    // Note: if bumpCounter returned null (Redis down), we deliberately don't
    // block - same fail-open-on-infra-hiccup philosophy as v1.

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

    // ---- Ban check: Redis only, no PlayFab call. This key needs to be
    // populated by something else (e.g. your OnPlayerBanned PlayStream
    // rule hitting a small separate webhook that does
    // safeSet(`ban:${playFabId}`, "1", ttlSec)) - if that push isn't wired
    // up, this will always read "not banned" here even though the ban
    // still exists in PlayFab itself; it just won't be enforced at the
    // Photon gate until the push is live. Say the word if you want that
    // second endpoint written out too.
    const banned = await safeGet(`ban:${playFabId}`);
    if (banned) {
        await sendAuthStatus({ outcome: "banned", success: false, playFabId, ip });
        return reject(res, "Player is banned.", 2);
    }

    // ---- AntiUnity check: single attempt, no retry loop. ----
    const passResult = await readAntiUnityPass(playFabId, 1500);

    if (passResult.status === "failed" || passResult.status === "expired") {
        // Explicit signal, not a timing issue - hard reject, this one is real.
        await sendAuthStatus({ outcome: `antiunity_${passResult.status}`, success: false, playFabId, ip });
        return reject(res, "No valid AntiUnity ticket - device check must pass before Photon.", 2);
    }

    const buildSuccessResponse = () => {
        const resp = { ResultCode: 1, UserId: playfabResult.userId || playFabId };
        if (playfabResult.nickname) resp.Nickname = playfabResult.nickname;
        return resp;
    };

    if (passResult.status === "valid") {
        await safeDel(`authfail:${playFabId}`);
        await sendAuthStatus({ outcome: "ok", success: true, playFabId, ip });
        return res.status(200).json(buildSuccessResponse());
    }

    // ---- status is "no_record" or "error" - ambiguous, admit provisionally ----
    // This is the case that used to hard-reject real players mid-race.
    // Now: let them in, verify in the background, kick if it turns out bad.
    await addProvisional(playFabId, ip);
    await sendAuthStatus({
        outcome: "ok_provisional",
        success: true,
        playFabId,
        ip,
        detail: passResult.status,
    });

    // Schedule background verification AFTER we respond - waitUntil keeps
    // the function alive past the response without blocking Photon's
    // callback on it. Requires `@vercel/functions` and a maxDuration
    // comfortably longer than INLINE_VERIFY_DELAYS_MS's total.
    waitUntil(verifyProvisionalInBackground(playFabId, ip));

    return res.status(200).json(buildSuccessResponse());
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

// Needs headroom for: PlayFab token call (~4s worst case) + the inline
// verification window (3s + 7s = 10s) that waitUntil keeps this alive
// for. 20s gives comfortable margin. Hobby plan caps function duration at
// 10s regardless of this setting - if you're on Hobby, the inline
// verification will get cut short sometimes (nothing breaks, you just
// lose the fast-path kick until you add something else that sweeps the
// "provisional_admits" Redis set).
module.exports.config = { maxDuration: 20 };
