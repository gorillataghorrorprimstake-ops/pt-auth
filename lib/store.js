// lib/store.js
//
// Drop-in replacement for the Upstash Redis client used by
// api/playfab/mark-clearance.js and api/photon/authenticate.js.
//
// WHY THIS EXISTS
// ----------------
// Upstash's free tier caps you at a fixed number of commands/month, and
// every single Photon auth request was firing 4-6 Redis round trips
// (3 rate-limit counters, a ban check, and a poll loop on the clearance
// flag that can itself hit Redis several times). That adds up fast and
// you maxed it out.
//
// This module gives you the same four primitives (get / set-with-ttl /
// atomic-incr-with-ttl / del) backed by a single Postgres table instead.
// Neon's free tier has no request-count ceiling like Upstash's — it's
// bounded by storage/compute, which this workload won't come close to.
//
// SETUP
// -----
// 1. Create a free Neon project: https://neon.tech (no credit card).
// 2. Copy the connection string it gives you (starts with postgres://).
// 3. Set it as the DATABASE_URL env var in Vercel (Project Settings ->
//    Environment Variables). Remove KV_REST_API_URL / KV_REST_API_TOKEN,
//    they're no longer used.
// 4. npm install @neondatabase/serverless (remove @upstash/redis).
//
// The table is created automatically on first use — no migration step.
//
// SEMANTICS
// ---------
// - kvGet(key): returns the value, or null if missing/expired.
// - kvSet(key, value, ttlSec): upsert with a fresh expiry.
// - kvIncr(key, ttlSec): atomic increment. If the key doesn't exist OR
//   its TTL has already lapsed, it resets to 1 with a fresh expiry —
//   this matches the redis.incr() + expire-on-first-hit pattern the
//   original code relied on for rolling rate-limit windows.
// - kvDel(key): removes the key.
//
// All four run as a single round trip (one SQL statement), so swapping
// this in doesn't multiply latency the way a naive per-operation
// SELECT-then-UPDATE would.

const { neon } = require("@neondatabase/serverless");

if (!process.env.DATABASE_URL) {
    console.error("[store] Missing DATABASE_URL env var.");
}

const sql = neon(process.env.DATABASE_URL);

// Table creation is memoized per warm serverless instance so it only
// actually runs once (on that instance's cold start), not on every call.
let tableReady = null;
function ensureTable() {
    if (!tableReady) {
        tableReady = sql(`
            CREATE TABLE IF NOT EXISTS kv_store (
                key         TEXT PRIMARY KEY,
                value       TEXT,
                count       BIGINT NOT NULL DEFAULT 0,
                expires_at  TIMESTAMPTZ
            )
        `);
    }
    return tableReady;
}

async function kvGet(key) {
    await ensureTable();
    const rows = await sql(
        `SELECT value FROM kv_store
         WHERE key = $1 AND (expires_at IS NULL OR expires_at > now())`,
        [key]
    );
    return rows.length ? rows[0].value : null;
}

async function kvSet(key, value, ttlSec) {
    await ensureTable();
    await sql(
        `INSERT INTO kv_store (key, value, expires_at)
         VALUES ($1, $2, now() + ($3 || ' seconds')::interval)
         ON CONFLICT (key) DO UPDATE
           SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
        [key, value, String(ttlSec)]
    );
}

async function kvIncr(key, ttlSec) {
    await ensureTable();
    const rows = await sql(
        `INSERT INTO kv_store (key, count, expires_at)
         VALUES ($1, 1, now() + ($2 || ' seconds')::interval)
         ON CONFLICT (key) DO UPDATE
           SET count = CASE
                 WHEN kv_store.expires_at IS NOT NULL AND kv_store.expires_at <= now()
                 THEN 1
                 ELSE kv_store.count + 1
               END,
               expires_at = CASE
                 WHEN kv_store.expires_at IS NOT NULL AND kv_store.expires_at <= now()
                 THEN now() + ($2 || ' seconds')::interval
                 ELSE kv_store.expires_at
               END
         RETURNING count`,
        [key, String(ttlSec)]
    );
    return rows.length ? Number(rows[0].count) : null;
}

async function kvDel(key) {
    await ensureTable();
    await sql(`DELETE FROM kv_store WHERE key = $1`, [key]);
}

module.exports = { kvGet, kvSet, kvIncr, kvDel };
