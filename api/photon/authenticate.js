// api/photon/authenticate.js
//
// Direct PlayFab token verification with Discord webhook notifications.

const axios = require("axios");

const TITLE_ID = process.env.PLAYFAB_TITLE_ID;
const SECRET_KEY = process.env.PLAYFAB_SECRET_KEY;
const PLAYFAB_BASE = `https://${TITLE_ID}.playfabapi.com`;
const AUTH_STATUS_WEBHOOK_URL = process.env.AUTH_STATUS_WEBHOOK_URL;
const STATUS_LOG_ENABLED = !!AUTH_STATUS_WEBHOOK_URL;

const PLAYFABID_RE = /^[0-9A-F]{16}$/i;

// ---------------------------------------------------------------------------
// Discord webhook helpers
// ---------------------------------------------------------------------------
async function postToWebhook(url, embed) {
    if (!url) return;
    try {
        await axios.post(url, { embeds: [embed] }, { timeout: 4000 });
    } catch (e) {
        console.error("[webhook] post failed:", e.message);
    }
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

    if (!playFabId || !photonToken) {
        return reject(res, "Missing username/token parameters.", 3, { ip });
    }
    if (!PLAYFABID_RE.test(playFabId)) {
        return reject(res, "Malformed identity.", 3, { ip, playFabId });
    }
    if (typeof photonToken !== "string" || photonToken.length < 8 || photonToken.length > 512) {
        return reject(res, "Malformed token.", 3, { ip, playFabId });
    }

    try {
        // Direct call to PlayFab Server API to authenticate the session ticket / token
        const pfResponse = await axios.post(
            `${PLAYFAB_BASE}/Server/AuthenticateSessionTicket`,
            { SessionTicket: photonToken },
            {
                headers: {
                    "Content-Type": "application/json",
                    "X-SecretKey": SECRET_KEY,
                },
                timeout: 4000,
            }
        );

        const data = pfResponse.data;
        if (!data || !data.data || !data.data.UserInfo || data.data.UserInfo.PlayFabId !== playFabId) {
            await sendAuthStatus({ outcome: "token verification failed or mismatch", success: false, playFabId, ip });
            return reject(res, "Token verification failed.", 2);
        }

        // Success - Auth directly into PlayFab confirmed
        await sendAuthStatus({ outcome: "ok", success: true, playFabId, ip });
        return res.status(200).json({ ResultCode: 1, UserId: playFabId });

    } catch (e) {
        const errorDetail = e.response?.data || e.message;
        console.error("[authenticate] PlayFab validation error:", errorDetail);
        await sendAuthStatus({ outcome: "playfab_api_error", success: false, playFabId, ip, detail: JSON.stringify(errorDetail) });
        return reject(res, "Authentication service error.", 2);
    }
}

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
        } catch (_) {}
        return reject(res, "Internal error.", 2);
    }
};

module.exports.config = { maxDuration: 8 };
