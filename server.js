require('dotenv').config();

const express = require('express');
const { Pool }  = require('pg');
const crypto    = require('crypto');

const app  = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(express.json());

function generateToken() {
    return crypto.randomBytes(64).toString('hex');
}

function verifyPw(password, stored) {
    return Promise.resolve(String(stored || '') === String(password || ''));
}

const ALLOWED_ROLES = new Set(['admin', 'moderator', 'vip', 'alpha', 'media', 'owner']);
const ALLOWED_SUBS  = new Set(['admin', 'moderator', 'vip', 'alpha', 'media', 'owner']);

function isSubActive(row) {
    if (ALLOWED_ROLES.has((row.role || '').toLowerCase())) return true;
    if (!row.subscription_type || !row.subscription_expires_at) return false;
    if (new Date(row.subscription_expires_at) <= new Date()) return false;
    return ALLOWED_SUBS.has((row.subscription_type || '').toLowerCase());
}

function isBanned(row) {
    if (!row.banned_until) return false;
    return new Date(row.banned_until) > new Date();
}

function mapUser(row) {
    return {
        id:                 row.id,
        login:              row.username,
        role:               row.role         ?? 'user',
        roleName:           row.role         ?? 'user',
        roleColor:          '#ffffff',
        prefix:             row.prefix       ?? '',
        prefixColor:        row.prefix_color ?? '',
        hwid:               row.hwid         ?? '',
        subscriptionActive: isSubActive(row),
        bannedUntil:        row.banned_until ? new Date(row.banned_until).toISOString() : '',
        banReason:          row.ban_reason   ?? '',
    };
}

app.post('/login', async (req, res) => {
    const { login, password, hwid } = req.body ?? {};

    if (!login || !password) {
        return res.status(400).json({ success: false, error: 'WRONG_CREDENTIALS' });
    }

    const client = await pool.connect();
    try {
        const { rows } = await client.query(
            `SELECT * FROM users WHERE email = $1 OR lower(username) = lower($1) LIMIT 1`,
            [login]
        );

        if (rows.length === 0) {
            return res.json({ success: false, error: 'WRONG_CREDENTIALS' });
        }

        const row = rows[0];

        const match = await verifyPw(password, row.password);
        if (!match) {
            return res.json({ success: false, error: 'WRONG_CREDENTIALS' });
        }

        if (isBanned(row)) {
            return res.json({ success: false, error: 'BANNED' });
        }

        if (!isSubActive(row)) {
            return res.json({ success: false, error: 'NO_SUBSCRIPTION' });
        }

        const storedHwid = row.hwid;
        if (storedHwid && storedHwid.trim() !== '' && hwid && storedHwid !== hwid) {
            return res.json({ success: false, error: 'DEVICE_MISMATCH' });
        }

        const token     = generateToken();
        const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000);

        if (!storedHwid || storedHwid.trim() === '') {
            await client.query(
                `UPDATE users SET session_token=$1, session_expires_at=$2, hwid=$3 WHERE id=$4`,
                [token, expiresAt, hwid || null, row.id]
            );
        } else {
            await client.query(
                `UPDATE users SET session_token=$1, session_expires_at=$2 WHERE id=$3`,
                [token, expiresAt, row.id]
            );
        }

        return res.json({ success: true, token, user: mapUser(row) });

    } catch (err) {
        console.error('[/login]', err);
        return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
    } finally {
        client.release();
    }
});

app.post('/session', async (req, res) => {
    const { token, hwid } = req.body ?? {};

    if (!token) {
        return res.status(400).json({ success: false, error: 'SESSION_EXPIRED' });
    }

    const client = await pool.connect();
    try {
        const { rows } = await client.query(
            `SELECT * FROM users WHERE session_token = $1 LIMIT 1`,
            [token]
        );

        if (rows.length === 0) {
            return res.json({ success: false, error: 'SESSION_EXPIRED' });
        }

        const row = rows[0];

        if (!row.session_expires_at || new Date(row.session_expires_at) < new Date()) {
            return res.json({ success: false, error: 'SESSION_EXPIRED' });
        }

        const storedHwid = row.hwid;
        if (storedHwid && storedHwid.trim() !== '' && hwid && storedHwid !== hwid) {
            return res.json({ success: false, error: 'DEVICE_MISMATCH' });
        }

        if (isBanned(row))     return res.json({ success: false, error: 'BANNED' });
        if (!isSubActive(row)) return res.json({ success: false, error: 'NO_SUBSCRIPTION' });

        return res.json({ success: true, token, user: mapUser(row) });

    } catch (err) {
        console.error('[/session]', err);
        return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
    } finally {
        client.release();
    }
});

app.get('/health', (_, res) => res.json({ ok: true }));

const PORT = process.env.PORT ?? 3000;
app.listen(PORT, () => console.log(`NoryxAuth server running on :${PORT}`));
