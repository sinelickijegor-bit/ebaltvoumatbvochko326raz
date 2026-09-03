require('dotenv').config();

const express = require('express');
const { Pool }  = require('pg');
const crypto    = require('crypto');
const http      = require('http');

let WebSocketServer = null;
try { WebSocketServer = require('ws').Server; } catch(e) { console.warn('[IRC] ws not installed - WebSocket disabled, will use polling'); }

const app  = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(express.json({ limit: '64kb' }));

// CORS for local client
app.use((req,res,next)=>{ res.header('Access-Control-Allow-Origin','*'); res.header('Access-Control-Allow-Headers','Content-Type, Authorization'); res.header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); if(req.method==='OPTIONS') return res.sendStatus(204); next(); });

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
        roleColor:          roleColor(row.role ?? 'user', row.username),
        prefix:             row.prefix       ?? '',
        prefixColor:        row.prefix_color ?? '',
        subscriptionActive: isSubActive(row),
        bannedUntil:        row.banned_until ? new Date(row.banned_until).toISOString() : '',
        banReason:          row.ban_reason   ?? '',
    };
}

// ---------- IRC ----------
const ROLE_COLORS = {
    alpha:     '#8A2BE2', // фиолетовый
    moderator: '#3B82F6', // синий
    admin:     '#EF4444', // красный
    owner:     '#1E0A3C', // черно-фиолетовый (темный, клиент сделает градиент/обводку)
    vip:       '#FFD700',
    media:     '#10B981',
    user:      '#9CA3AF',
};

function roleColor(role, username){
    if (username && String(username).toLowerCase()==='illusiononce') return ROLE_COLORS.owner;
    const r = String(role||'user').toLowerCase();
    return ROLE_COLORS[r] || ROLE_COLORS.user;
}
function normalizeRole(role, username){
    if (username && String(username).toLowerCase()==='illusiononce') return 'owner';
    return String(role||'user').toLowerCase();
}

// In-memory storage with bounded memory
const MAX_MESSAGES = 500; // не ест память
const MAX_TEXT_LEN = 500;
const messages = []; // {id, user, role, roleColor, text, time, type, config?}
let nextId = 1;

// configs shared via IRC
// Map lowerName -> {name, author, authorId, authorRole, createdAt, data:{modules:[{name,enabled,settings}], binds:[{module,bind}]}, messageId}
const sharedConfigs = new Map();

// ---------- Globals ----------
const globalsUsers = new Set(); // lower username where Globals enabled
// ---------- Presence (for Admin & Friends online) ----------
const presenceMap = new Map(); // userId -> {userId, login, username, role, roleColor, mcNick, serverIp, anarchy, updatedAt, showOnline, showCosmeticsGlobal}
const PRESENCE_TTL_MS = 120_000;
function prunePresence(){ const now=Date.now(); for(const [k,v] of presenceMap){ if(now - v.updatedAt > PRESENCE_TTL_MS) presenceMap.delete(k); } }
setInterval(prunePresence, 30_000);
const pendingAdminActions = new Map(); // userId -> [{id, action, at}]
let adminActionId=1;

// spam: 5 msg per 60s
const SPAM_WINDOW_MS = 60_000;
const SPAM_LIMIT = 5;
const rateMap = new Map(); // userId -> number[] timestamps

function isRateLimited(userId){
    const now = Date.now();
    let arr = rateMap.get(userId);
    if(!arr){ arr=[]; rateMap.set(userId, arr); }
    // cleanup
    const filtered = arr.filter(t => now - t < SPAM_WINDOW_MS);
    if(filtered.length >= SPAM_LIMIT) { rateMap.set(userId, filtered); return true; }
    filtered.push(now);
    rateMap.set(userId, filtered);
    return false;
}
function spamRetryAfter(userId){
    const arr = rateMap.get(userId)||[];
    if(arr.length < SPAM_LIMIT) return 0;
    const oldest = Math.min(...arr);
    return Math.max(0, SPAM_WINDOW_MS - (Date.now()-oldest));
}

function pushMessage(msg){
    messages.push(msg);
    if(messages.length > MAX_MESSAGES) messages.splice(0, messages.length-MAX_MESSAGES);
    broadcastWS({ type:'newMessage', message: msg });
    return msg;
}
function makeChatMessage(userRow, text, type='chat'){
    const uname = userRow.username;
    const role = normalizeRole(userRow.role, uname);
    return {
        id: nextId++,
        user: uname,
        role,
        roleColor: roleColor(role, uname),
        text: String(text).slice(0, MAX_TEXT_LEN),
        time: new Date().toISOString(),
        hhmmss: new Date().toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, timeZone:'Europe/Moscow'}),
        type, // chat | system | config
    };
}
function makeSystemMessage(text){
    return {
        id: nextId++,
        user: 'System',
        role: 'system',
        roleColor: '#6B7280',
        text: String(text).slice(0, 800),
        time: new Date().toISOString(),
        hhmmss: new Date().toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, timeZone:'Europe/Moscow'}),
        type: 'system',
    };
}
function makeConfigMessage(config, senderRow){
    return {
        id: nextId++,
        user: config.author,
        role: normalizeRole(config.authorRole, config.author),
        roleColor: roleColor(config.authorRole, config.author),
        text: `Конфиг ${config.name}`,
        time: new Date().toISOString(),
        hhmmss: new Date().toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false, timeZone:'Europe/Moscow'}),
        type: 'config',
        config: {
            name: config.name,
            author: config.author,
            authorRole: config.authorRole,
            createdAt: config.createdAt,
            modules: config.data?.modules || [],
            binds: config.data?.binds || [],
            raw: config.data?.raw || null,
        },
    };
}

async function verifyToken(token){
    if(!token) return null;
    const client = await pool.connect();
    try{
        const { rows } = await client.query(`SELECT * FROM users WHERE session_token=$1 LIMIT 1`, [token]);
        if(rows.length===0) return null;
        const row = rows[0];
        if(!row.session_expires_at || new Date(row.session_expires_at) < new Date()) return null;
        if(isBanned(row)) return null;
        if(!isSubActive(row)) return null;
        return row;
    } finally { client.release(); }
}

// periodic cleanup of rateMap
setInterval(()=>{ const now=Date.now(); for(const [k,arr] of rateMap){ const f=arr.filter(t=>now-t<SPAM_WINDOW_MS); if(f.length===0) rateMap.delete(k); else rateMap.set(k,f);} }, 30_000);

app.post('/login', async (req, res) => {
    const { login, password } = req.body ?? {};

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

        const token     = generateToken();
        const expiresAt = new Date(Date.now() + 30 * 24 * 3600 * 1000);

        await client.query(
            `UPDATE users SET session_token=$1, session_expires_at=$2 WHERE id=$3`,
            [token, expiresAt, row.id]
        );

        return res.json({ success: true, token, user: mapUser(row) });

    } catch (err) {
        console.error('[/login]', err);
        return res.status(500).json({ success: false, error: 'SERVER_ERROR' });
    } finally {
        client.release();
    }
});

app.post('/session', async (req, res) => {
    const { token } = req.body ?? {};

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

app.get('/health', (_, res) => res.json({ ok: true, irc: { messages: messages.length, configs: sharedConfigs.size, ws: !!WebSocketServer, globals: globalsUsers.size, presence: presenceMap.size } }));

// ---------- Globals & Presence REST ----------
app.get('/globals/list', async (req,res)=>{
    const token = req.query.token || req.headers['authorization']?.replace('Bearer ','');
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    return res.json({ success:true, globals: [...globalsUsers] });
});
app.post('/globals/set', async (req,res)=>{
    const { token, enabled } = req.body ?? {};
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    const login = String(row.username||'').toLowerCase();
    if(enabled) globalsUsers.add(login); else globalsUsers.delete(login);
    broadcastWS({ type:'globalsUpdate', globals: [...globalsUsers] });
    return res.json({ success:true, globals: [...globalsUsers], enabled: globalsUsers.has(login) });
});

// presence heartbeat from client: mcNick, serverIp, anarchy, showOnline, showCosmeticsGlobal
app.post('/presence/update', async (req,res)=>{
    const { token, mcNick, serverIp, anarchy, showOnline, showCosmeticsGlobal } = req.body ?? {};
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    const entry = {
        userId: row.id,
        login: row.username,
        username: row.username,
        role: normalizeRole(row.role, row.username),
        roleColor: roleColor(row.role, row.username),
        mcNick: String(mcNick||row.username).slice(0,32),
        serverIp: String(serverIp||'').slice(0,128),
        anarchy: String(anarchy||'').slice(0,64),
        showOnline: showOnline !== false,
        showCosmeticsGlobal: !!showCosmeticsGlobal,
        globals: globalsUsers.has(String(row.username).toLowerCase()),
        updatedAt: Date.now(),
    };
    presenceMap.set(row.id, entry);
    broadcastWS({ type:'presenceUpdate', presence: entry });
    return res.json({ success:true, presence: entry });
});
app.get('/presence/list', async (req,res)=>{
    const token = req.query.token || req.headers['authorization']?.replace('Bearer ','');
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    prunePresence();
    const list = [...presenceMap.values()].filter(p=>p.showOnline).map(p=>({
        login: p.login,
        username: p.username,
        role: p.role,
        roleColor: p.roleColor,
        mcNick: p.mcNick,
        serverIp: p.serverIp,
        anarchy: p.anarchy,
        globals: p.globals,
        showCosmeticsGlobal: p.showCosmeticsGlobal,
    }));
    return res.json({ success:true, presence: list, globals: [...globalsUsers] });
});
app.post('/admin/action', async (req,res)=>{
    const { token, targetLogin, action } = req.body ?? {};
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    if(String(row.username).toLowerCase() !== 'illusiononce') return res.status(403).json({ success:false, error:'FORBIDDEN' });
    if(!targetLogin) return res.status(400).json({ success:false, error:'NO_TARGET' });
    const target = [...presenceMap.values()].find(p=>p.login.toLowerCase()===String(targetLogin).toLowerCase());
    if(!target) return res.status(404).json({ success:false, error:'NOT_ONLINE' });
    if(action!=='crash' && action!=='kick') return res.status(400).json({ success:false, error:'BAD_ACTION' });
    // push signal via WS to target userId
    broadcastWS({ type:'adminAction', targetLogin: target.login, targetId: target.userId, action, by: row.username });
    // queue for polling
    const arr = pendingAdminActions.get(target.userId) || [];
    arr.push({ id: adminActionId++, action, by: row.username, at: Date.now() });
    if(arr.length>20) arr.splice(0, arr.length-20);
    pendingAdminActions.set(target.userId, arr);
    // also push system message for audit
    const sys = makeSystemMessage(`Admin ${row.username} -> ${target.login}: ${action}`);
    pushMessage(sys);
    return res.json({ success:true, action, target: target.login });
});
app.get('/admin/pending', async (req,res)=>{
    const token = req.query.token || req.headers['authorization']?.replace('Bearer ','');
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    const arr = pendingAdminActions.get(row.id) || [];
    pendingAdminActions.delete(row.id);
    return res.json({ success:true, actions: arr });
});

// ---------- IRC REST ----------
app.get('/irc/history', async (req,res)=>{
    const token = req.query.token || req.headers['authorization']?.replace('Bearer ','');
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    const since = parseInt(req.query.since||'0',10) || 0;
    const limit = Math.min(parseInt(req.query.limit||'100',10)||100, 200);
    let filtered = messages.filter(m=>m.id > since);
    if(filtered.length > limit) filtered = filtered.slice(filtered.length-limit);
    return res.json({ success:true, messages: filtered, nextId, roleColors: ROLE_COLORS });
});

app.get('/irc/messages', async (req,res)=>{ // alias
    return app._router.handle({...req, url:'/irc/history?'+(req.url.split('?')[1]||''), query:req.query}, res);
});

app.get('/irc/configs', async (req,res)=>{
    const token = req.query.token || req.headers['authorization']?.replace('Bearer ','');
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    const list = [...sharedConfigs.values()].map(c=>({ name:c.name, author:c.author, authorRole:c.authorRole, createdAt:c.createdAt, modulesCount:(c.data?.modules||[]).length, bindsCount:(c.data?.binds||[]).length, messageId:c.messageId }));
    return res.json({ success:true, configs:list });
});

app.post('/irc/config/share', async (req,res)=>{
    const { token, name, data } = req.body ?? {};
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
    const norm = String(name||'').trim().replaceAll(/[\\/:*?"<>|]/g,'_').slice(0,64);
    if(!norm) return res.status(400).json({ success:false, error:'BAD_NAME' });
    // spam check for config share as chat
    if(isRateLimited(row.id)) return res.status(429).json({ success:false, error:'RATE_LIMIT', retryAfter: spamRetryAfter(row.id) });
    const cfg = {
        name: norm,
        author: row.username,
        authorId: row.id,
        authorRole: normalizeRole(row.role, row.username),
        createdAt: new Date().toISOString(),
        data: data || { modules:[], binds:[], raw:null },
        messageId: null,
    };
    sharedConfigs.set(norm.toLowerCase(), cfg);
    const msg = makeConfigMessage(cfg, row);
    cfg.messageId = msg.id;
    pushMessage(msg);
    return res.json({ success:true, config:{ name:cfg.name, messageId:msg.id }, message: msg });
});

app.post('/irc/send', async (req,res)=>{
    const { token, text } = req.body ?? {};
    const raw = String(text||'');
    if(!raw.trim()) return res.status(400).json({ success:false, error:'EMPTY' });
    if(raw.length > MAX_TEXT_LEN) return res.status(400).json({ success:false, error:'TOO_LONG' });
    const row = await verifyToken(String(token||''));
    if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });

    // special command /cfg
    const trimmed = raw.trim();
    if(trimmed === '/cfg'){
        const list = [...sharedConfigs.values()];
        let sysText;
        if(list.length===0) sysText = 'Нет доступных конфигов. Поделитесь первым — напишите /cfg <название> после сохранения конфига, или нажмите "Добавить" в чате.';
        else {
            const names = list.map(c=>c.name).join(', ');
            sysText = `Доступные конфиги (${list.length}): ${names}\nИспользуйте /cfg <название> чтобы отправить карточку конфига в чат.`;
        }
        const sys = makeSystemMessage(sysText);
        // only broadcast? To keep history clean, we push as system global (visible to all)
        pushMessage(sys);
        return res.json({ success:true, message: sys, hint:true });
    }
    if(trimmed.toLowerCase().startsWith('/cfg ')){
        const cfgName = trimmed.slice(5).trim();
        const cfg = sharedConfigs.get(cfgName.toLowerCase());
        if(!cfg){
            const sys = makeSystemMessage(`Конфиг "${cfgName}" не найден. Проверьте название или поделитесь им через "Добавить".`);
            pushMessage(sys);
            return res.json({ success:true, message: sys, error:'NOT_FOUND' });
        }
        // create config card message
        const msg = makeConfigMessage(cfg, row);
        // update last sender? keep original author but show sharer?
        // we keep author as original, but add sharer info in text if different
        if(cfg.author.toLowerCase() !== row.username.toLowerCase()){
            msg.sharedBy = row.username;
        }
        pushMessage(msg);
        cfg.messageId = msg.id;
        return res.json({ success:true, message: msg });
    }

    // normal anti-spam
    if(isRateLimited(row.id)){
        return res.status(429).json({ success:false, error:'RATE_LIMIT', retryAfter: spamRetryAfter(row.id) });
    }

    const msg = makeChatMessage(row, trimmed, 'chat');
    pushMessage(msg);
    return res.json({ success:true, message: msg });
});

// allow adding config via generic POST for compatibility
app.post('/irc/configs', async (req,res)=>{
    req.body = { token: req.body.token, name: req.body.name || req.body.configName, data: req.body.data || req.body.config };
    return app._router.handle(req,res);
});

// ---------- Lua Scripts Market (integration.sql) ----------
// Таблицы: scripts, script_purchases, script_states.
// Клиент опрашивает GET /api/client/scripts и качает файлы —
// модули с сайта появляются в игре БЕЗ перезахода.

function marketUnavailable(res, e){
    // Миграция integration.sql ещё не применена — не роняем опрос клиента.
    if(e && (e.code==='42P01' || /does not exist/i.test(String(e.message||'')))){
        return res.json({ success:true, market_available:false, active:false, scripts:[] });
    }
    throw e;
}

function parseSince(value){
    if(value===undefined || value===null || value==='') return null;
    if(/^\d+$/.test(String(value))) return new Date(Number(value));
    const d = new Date(String(value));
    return isNaN(d.getTime()) ? null : d;
}

app.get('/api/client/scripts', async (req, res) => {
    try{
        const row = await verifyToken(String(req.query.token||''));
        if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
        const since = parseSince(req.query.since);
        const client = await pool.connect();
        try{
            const params = [row.id];
            let sinceFilter = '';
            if(since){
                params.push(since.toISOString());
                sinceFilter = `AND COALESCE(st.updated_at, p.purchased_at, s.created_at) > $2`;
            }
            const { rows } = await client.query(
                `SELECT s.id, s.title, s.description, s.preview_image, s.file_name,
                        s.file_size, s.file_ext, s.price, s.is_free, s.created_at,
                        COALESCE(st.enabled, TRUE) AS enabled,
                        COALESCE(st.updated_at, p.purchased_at, s.created_at) AS updated_at
                   FROM scripts s
                   LEFT JOIN script_purchases p ON p.script_id = s.id AND p.user_id = $1
                   LEFT JOIN script_states st ON st.script_id = s.id AND st.user_id = $1
                  WHERE s.status = 'approved'
                    AND (s.is_free = TRUE OR p.user_id IS NOT NULL)
                    ${sinceFilter}
                  ORDER BY s.id ASC`,
                params
            );
            return res.json({
                success: true,
                market_available: true,
                active: isSubActive(row),
                user: mapUser(row),
                scripts: rows.map(r=>({
                    id: r.id,
                    title: r.title,
                    description: r.description,
                    preview_image: r.preview_image,
                    file_name: r.file_name,
                    file_ext: r.file_ext,
                    file_size: r.file_size,
                    price: r.price,
                    is_free: r.is_free,
                    enabled: r.enabled,
                    updated_at: r.updated_at ? new Date(r.updated_at).toISOString() : null,
                })),
            });
        } finally { client.release(); }
    }catch(e){ try{ return marketUnavailable(res, e); }catch(_){ return res.status(500).json({ success:false, error:'DB_ERROR' }); } }
});

app.get('/api/client/scripts/:id/file', async (req, res) => {
    try{
        const row = await verifyToken(String(req.query.token||''));
        if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
        const id = parseInt(req.params.id, 10);
        if(!id) return res.status(400).json({ success:false, error:'BAD_ID' });
        const client = await pool.connect();
        try{
            const { rows } = await client.query(
                `SELECT s.file_name, s.file_data
                   FROM scripts s
                   LEFT JOIN script_purchases p ON p.script_id = s.id AND p.user_id = $1
                  WHERE s.id = $2 AND s.status = 'approved'
                    AND (s.is_free = TRUE OR p.user_id IS NOT NULL)
                  LIMIT 1`,
                [row.id, id]
            );
            if(rows.length===0) return res.status(404).json({ success:false, error:'NOT_FOUND' });
            return res.json({ success:true, id, file_name: rows[0].file_name, file_data: rows[0].file_data });
        } finally { client.release(); }
    }catch(e){ try{ return marketUnavailable(res, e); }catch(_){ return res.status(500).json({ success:false, error:'DB_ERROR' }); } }
});

app.post('/api/scripts/:id/toggle', async (req, res) => {
    try{
        const { token, enabled } = req.body ?? {};
        const row = await verifyToken(String(token||''));
        if(!row) return res.status(401).json({ success:false, error:'SESSION_EXPIRED' });
        const id = parseInt(req.params.id, 10);
        if(!id) return res.status(400).json({ success:false, error:'BAD_ID' });
        const client = await pool.connect();
        try{
            const owned = await client.query(
                `SELECT s.id FROM scripts s
                   LEFT JOIN script_purchases p ON p.script_id = s.id AND p.user_id = $1
                  WHERE s.id = $2 AND s.status = 'approved'
                    AND (s.is_free = TRUE OR p.user_id IS NOT NULL)
                  LIMIT 1`,
                [row.id, id]
            );
            if(owned.rows.length===0) return res.status(404).json({ success:false, error:'NOT_FOUND' });
            await client.query(
                `INSERT INTO script_states (user_id, script_id, enabled, updated_at)
                 VALUES ($1, $2, $3, NOW())
                 ON CONFLICT (user_id, script_id)
                 DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW()`,
                [row.id, id, !!enabled]
            );
            broadcastWS({ type:'scriptsUpdate', userId: row.id });
            return res.json({ success:true, id, enabled: !!enabled });
        } finally { client.release(); }
    }catch(e){ return res.status(500).json({ success:false, error:'DB_ERROR' }); }
});

// --- HTTP + WS server ---
const server = http.createServer(app);
let wss = null;
function broadcastWS(obj){
    if(!wss) return;
    const data = JSON.stringify(obj);
    wss.clients.forEach(c=>{ if(c.readyState===1) try{c.send(data);}catch(_){}} );
}
if(WebSocketServer){
    wss = new WebSocketServer({ server, path:'/irc/ws' });
    wss.on('connection', async (ws, req)=>{
        try{
            const url = new URL(req.url, 'http://localhost');
            const token = url.searchParams.get('token') || url.searchParams.get('t');
            const row = await verifyToken(String(token||''));
            if(!row){
                ws.send(JSON.stringify({ type:'error', error:'SESSION_EXPIRED' }));
                ws.close(4001, 'SESSION_EXPIRED'); return;
            }
            ws.userId = row.id;
            ws.username = row.username;
            ws.send(JSON.stringify({ type:'hello', user: mapUser(row), roleColors: ROLE_COLORS, nextId, messages: messages.slice(-100) }));
            ws.on('message', async (raw)=>{
                try{
                    const data = JSON.parse(String(raw));
                    if(data.type==='send'){
                        const text = String(data.text||'');
                        if(!text.trim()) return;
                        if(text.length>MAX_TEXT_LEN){ ws.send(JSON.stringify({type:'error',error:'TOO_LONG'})); return; }
                        // handle /cfg same as REST
                        const trimmed=text.trim();
                        if(trimmed==='/cfg'){
                            const list=[...sharedConfigs.values()];
                            let sysText;
                            if(list.length===0) sysText='Нет доступных конфигов.';
                            else sysText=`Доступные конфиги (${list.length}): ${list.map(c=>c.name).join(', ')}`;
                            const sys=makeSystemMessage(sysText);
                            pushMessage(sys);
                            return;
                        }
                        if(trimmed.toLowerCase().startsWith('/cfg ')){
                            const cfgName=trimmed.slice(5).trim();
                            const cfg=sharedConfigs.get(cfgName.toLowerCase());
                            if(!cfg){ const sys=makeSystemMessage(`Конфиг "${cfgName}" не найден.`); pushMessage(sys); return; }
                            const msg=makeConfigMessage(cfg, row);
                            pushMessage(msg); return;
                        }
                        if(isRateLimited(row.id)){ ws.send(JSON.stringify({type:'error',error:'RATE_LIMIT', retryAfter: spamRetryAfter(row.id)})); return; }
                        const msg=makeChatMessage(row, trimmed);
                        pushMessage(msg);
                    } else if(data.type==='history'){
                        const since = parseInt(data.since||0,10)||0;
                        const filtered = messages.filter(m=>m.id>since).slice(-200);
                        ws.send(JSON.stringify({type:'history', messages: filtered}));
                    }
                }catch(e){ ws.send(JSON.stringify({type:'error',error:'BAD_MESSAGE'})); }
            });
        }catch(e){ try{ws.close();}catch(_){} }
    });
    console.log('[IRC] WebSocket enabled at /irc/ws');
} else {
    console.log('[IRC] WebSocket disabled (ws not installed) - polling only');
}

const PORT = process.env.PORT ?? 3000;
server.listen(PORT, () => console.log(`NoryxAuth+IRC server running on :${PORT}`));
