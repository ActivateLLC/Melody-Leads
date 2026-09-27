'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const PASSWORD = process.env.APP_PASSWORD || '';
const HOOK_KEY = process.env.HOOK_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false }
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* ---------------------------------------------------------------- schema */

const SCHEMA = `
CREATE TABLE IF NOT EXISTS leads (
  id             SERIAL PRIMARY KEY,
  received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  form_name      TEXT,
  page_url       TEXT,
  name           TEXT,
  email          TEXT,
  phone          TEXT,
  organization   TEXT,
  message        TEXT,
  raw            JSONB,
  status         TEXT NOT NULL DEFAULT 'new',
  is_spam        BOOLEAN NOT NULL DEFAULT false,
  spam_reason    TEXT,
  notes          TEXT NOT NULL DEFAULT '',
  next_follow_up DATE,
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS leads_received_idx ON leads (received_at DESC);
CREATE INDEX IF NOT EXISTS leads_status_idx   ON leads (status);
CREATE INDEX IF NOT EXISTS leads_spam_idx     ON leads (is_spam);
CREATE INDEX IF NOT EXISTS leads_email_idx    ON leads (email);
`;

async function init() {
  await pool.query(SCHEMA);
  console.log('schema ready');
}

/* ----------------------------------------------------------------- auth */

function token() {
  return crypto.createHmac('sha256', SESSION_SECRET).update(PASSWORD).digest('hex');
}

function authed(req) {
  return PASSWORD !== '' && req.cookies && req.cookies.mv_session === token();
}

function requireAuth(req, res, next) {
  if (authed(req)) return next();
  return res.redirect('/login');
}

/* --------------------------------------------------------------- triage */

const SPAM_TERMS = [
  'seo service', 'backlink', 'crypto', 'casino', 'viagra', 'loan offer',
  'bitcoin', 'forex', 'porn', 'escort', 'rank your site', 'guest post',
  'web design services', 'increase traffic'
];

// Returns { spam: bool, reason: string|null }
function triage(fields, message) {
  const honeypot = (fields.Website || fields.website || '').toString().trim();
  if (honeypot) return { spam: true, reason: 'honeypot filled' };

  const body = (message || '').toString();
  const lower = body.toLowerCase();

  const urls = body.match(/https?:\/\/|www\./gi) || [];
  if (urls.length >= 2) return { spam: true, reason: urls.length + ' links in message' };

  for (const term of SPAM_TERMS) {
    if (lower.includes(term)) return { spam: true, reason: 'matched "' + term + '"' };
  }

  // Non-Latin scripts are a strong signal for this audience, not a universal rule.
  if (/[\u0400-\u04FF\u4E00-\u9FFF]/.test(body)) {
    return { spam: true, reason: 'non-Latin script' };
  }

  const email = (fields.Email || fields['Email Address'] || '').toString().toLowerCase();
  if (email && /@(mail\.ru|qq\.com|yandex\.)/.test(email)) {
    return { spam: true, reason: 'suspicious email domain' };
  }

  return { spam: false, reason: null };
}

function pick(fields, keys) {
  for (const k of keys) {
    for (const actual of Object.keys(fields)) {
      if (actual.toLowerCase() === k.toLowerCase() && fields[actual]) {
        return String(fields[actual]).trim();
      }
    }
  }
  return null;
}

/* -------------------------------------------------------------- ingest */

app.post('/hook', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) {
    return res.status(401).json({ ok: false, error: 'bad key' });
  }

  try {
    const payload = (req.body && req.body.payload) || req.body || {};
    const fields = payload.data || payload.fields || {};
    const formName = payload.name || payload.formName || 'unknown';
    const pageUrl = payload.pageUrl || payload.page_url || null;

    const name = pick(fields, ['name', 'full name', 'your name', 'first name']);
    const email = pick(fields, ['email', 'email address', 'e-mail']);
    const phone = pick(fields, ['phone', 'phone number', 'telephone']);
    const org = pick(fields, ['organization', 'organisation', 'company']);
    const message = pick(fields, [
      'message', 'write about your project', 'event details', 'comments', 'notes'
    ]);

    const t = triage(fields, message);

    const result = await pool.query(
      `INSERT INTO leads
         (form_name, page_url, name, email, phone, organization, message, raw,
          is_spam, spam_reason, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id`,
      [
        formName, pageUrl, name, email, phone, org, message,
        JSON.stringify(payload), t.spam, t.reason, t.spam ? 'spam' : 'new'
      ]
    );

    console.log('lead', result.rows[0].id, formName, t.spam ? 'SPAM:' + t.reason : 'ok');
    res.json({ ok: true, id: result.rows[0].id, spam: t.spam });
  } catch (err) {
    console.error('ingest failed', err);
    res.status(500).json({ ok: false });
  }
});

/* ------------------------------------------------------------------ ui */

const STATUSES = ['new', 'contacted', 'booked', 'cold', 'spam'];

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function layout(title, body) {
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<style>
  :root{ --purple:#7670B3; --deep:#5C5695; --lav:#C7C4E2; --wash:#F4F3F9;
         --ink:#1F1D26; --mid:#4A4751; --soft:#7A7684; --line:#E4E2EC; }
  *{box-sizing:border-box}
  body{margin:0;background:var(--wash);color:var(--ink);
       font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
  header{background:var(--purple);color:#fff;padding:18px 20px;
         display:flex;justify-content:space-between;align-items:center;gap:12px}
  header h1{margin:0;font-size:1.05rem;font-weight:600;letter-spacing:.01em}
  header a{color:#fff;opacity:.85;text-decoration:none;font-size:.82rem}
  .wrap{max-width:1000px;margin:0 auto;padding:18px 16px 60px}
  .tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
  .tab{padding:8px 14px;border-radius:999px;border:1px solid var(--line);
       background:#fff;color:var(--mid);text-decoration:none;font-size:.85rem}
  .tab.on{background:var(--deep);border-color:var(--deep);color:#fff;font-weight:600}
  .search{display:flex;gap:8px;margin-bottom:16px}
  .search input{flex:1;padding:11px 14px;border:1px solid var(--line);
                border-radius:10px;font-size:.92rem;background:#fff}
  .search button{padding:11px 18px;border:0;border-radius:10px;
                 background:var(--purple);color:#fff;font-weight:600;font-size:.85rem}
  .lead{background:#fff;border:1px solid var(--line);border-radius:12px;
        padding:16px;margin-bottom:12px}
  .lead.spam{opacity:.62}
  .meta{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;
        font-size:.76rem;color:var(--soft);margin-bottom:8px}
  .who{font-weight:600;font-size:1.02rem;margin:0 0 3px}
  .contact{font-size:.86rem;color:var(--mid);margin-bottom:8px;word-break:break-word}
  .contact a{color:var(--deep)}
  .msg{font-size:.9rem;color:var(--mid);background:var(--wash);
       border-radius:8px;padding:10px 12px;margin:8px 0;white-space:pre-wrap}
  .flag{display:inline-block;font-size:.68rem;letter-spacing:.08em;
        text-transform:uppercase;color:#9a3d3d;background:#fbeaea;
        padding:3px 8px;border-radius:999px}
  form.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
  select,input[type=date],textarea{border:1px solid var(--line);border-radius:8px;
        padding:9px 11px;font-size:.86rem;font-family:inherit;background:#fff}
  textarea{width:100%;min-height:54px;resize:vertical}
  button.save{padding:9px 16px;border:0;border-radius:8px;background:var(--deep);
              color:#fff;font-weight:600;font-size:.82rem}
  .empty{background:#fff;border:1px dashed var(--line);border-radius:12px;
         padding:34px 20px;text-align:center;color:var(--soft)}
  .count{font-size:.8rem;color:var(--soft);margin-bottom:10px}
  .login{max-width:340px;margin:12vh auto;background:#fff;padding:26px;
         border-radius:14px;border:1px solid var(--line)}
  .login h1{font-size:1.1rem;margin:0 0 16px}
  .login input{width:100%;padding:12px;border:1px solid var(--line);
               border-radius:10px;margin-bottom:12px;font-size:.95rem}
  .login button{width:100%;padding:12px;border:0;border-radius:10px;
                background:var(--purple);color:#fff;font-weight:600}
  .err{color:#9a3d3d;font-size:.85rem;margin-bottom:10px}
</style></head><body>${body}</body></html>`;
}

app.get('/login', (req, res) => {
  res.send(layout('Sign in', `
    <div class="login">
      <h1>Melody &mdash; lead inbox</h1>
      ${req.query.bad ? '<div class="err">That password did not work.</div>' : ''}
      <form method="post" action="/login">
        <input type="password" name="password" placeholder="Password" autofocus>
        <button type="submit">Sign in</button>
      </form>
    </div>`));
});

app.post('/login', (req, res) => {
  if (PASSWORD && req.body.password === PASSWORD) {
    res.cookie('mv_session', token(), {
      httpOnly: true, sameSite: 'lax', secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 30
    });
    return res.redirect('/');
  }
  res.redirect('/login?bad=1');
});

app.get('/logout', (req, res) => {
  res.clearCookie('mv_session');
  res.redirect('/login');
});

app.get('/', requireAuth, async (req, res) => {
  const status = (req.query.status || 'new').toLowerCase();
  const q = (req.query.q || '').trim();

  const where = [];
  const params = [];

  if (status === 'spam') {
    where.push('is_spam = true');
  } else if (status === 'all') {
    where.push('is_spam = false');
  } else {
    params.push(status);
    where.push('is_spam = false AND status = $' + params.length);
  }

  if (q) {
    params.push('%' + q.toLowerCase() + '%');
    const i = params.length;
    where.push(`(lower(coalesce(name,'')) LIKE $${i}
              OR lower(coalesce(email,'')) LIKE $${i}
              OR lower(coalesce(organization,'')) LIKE $${i}
              OR lower(coalesce(message,'')) LIKE $${i})`);
  }

  const sql = `SELECT * FROM leads WHERE ${where.join(' AND ')}
               ORDER BY received_at DESC LIMIT 200`;
  const { rows } = await pool.query(sql, params);

  const counts = await pool.query(`
    SELECT status, count(*)::int AS n, is_spam FROM leads GROUP BY status, is_spam`);
  const tally = {};
  let spamCount = 0;
  counts.rows.forEach(r => {
    if (r.is_spam) spamCount += r.n;
    else tally[r.status] = (tally[r.status] || 0) + r.n;
  });

  const tabs = ['new', 'contacted', 'booked', 'cold', 'all', 'spam'].map(s => {
    const n = s === 'spam' ? spamCount
            : s === 'all' ? Object.values(tally).reduce((a, b) => a + b, 0)
            : (tally[s] || 0);
    const label = s.charAt(0).toUpperCase() + s.slice(1);
    return `<a class="tab ${s === status ? 'on' : ''}"
              href="/?status=${s}${q ? '&q=' + encodeURIComponent(q) : ''}">${label} (${n})</a>`;
  }).join('');

  const cards = rows.length ? rows.map(l => {
    const when = new Date(l.received_at).toLocaleString('en-US', {
      month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'
    });
    const opts = STATUSES.map(s =>
      `<option value="${s}" ${s === l.status ? 'selected' : ''}>${s}</option>`).join('');
    return `
    <div class="lead ${l.is_spam ? 'spam' : ''}">
      <div class="meta">
        <span>${esc(when)} &middot; ${esc(l.form_name || 'form')}</span>
        ${l.is_spam ? `<span class="flag">spam &middot; ${esc(l.spam_reason || '')}</span>` : ''}
      </div>
      <p class="who">${esc(l.name || 'No name given')}</p>
      <div class="contact">
        ${l.email ? `<a href="mailto:${esc(l.email)}">${esc(l.email)}</a>` : ''}
        ${l.phone ? ` &middot; <a href="tel:${esc(l.phone)}">${esc(l.phone)}</a>` : ''}
        ${l.organization ? `<br>${esc(l.organization)}` : ''}
      </div>
      ${l.message ? `<div class="msg">${esc(l.message)}</div>` : ''}
      <form class="row" method="post" action="/leads/${l.id}">
        <select name="status">${opts}</select>
        <input type="date" name="next_follow_up"
               value="${l.next_follow_up ? new Date(l.next_follow_up).toISOString().slice(0, 10) : ''}">
        <textarea name="notes" placeholder="Notes">${esc(l.notes)}</textarea>
        <button class="save" type="submit">Save</button>
      </form>
    </div>`;
  }).join('') : `<div class="empty">Nothing here.</div>`;

  res.send(layout('Lead inbox', `
    <header>
      <h1>Melody &mdash; lead inbox</h1>
      <a href="/logout">Sign out</a>
    </header>
    <div class="wrap">
      <div class="tabs">${tabs}</div>
      <form class="search" method="get" action="/">
        <input type="hidden" name="status" value="${esc(status)}">
        <input name="q" value="${esc(q)}" placeholder="Search name, email, organisation, message">
        <button type="submit">Search</button>
      </form>
      <div class="count">${rows.length} shown</div>
      ${cards}
    </div>`));
});

app.post('/leads/:id', requireAuth, async (req, res) => {
  const { status, notes, next_follow_up } = req.body;
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');

  await pool.query(
    `UPDATE leads
        SET status = $1,
            notes = $2,
            next_follow_up = NULLIF($3,'')::date,
            is_spam = ($1 = 'spam'),
            updated_at = now()
      WHERE id = $4`,
    [STATUSES.includes(status) ? status : 'new', notes || '', next_follow_up || '', id]
  );

  res.redirect('back' in res ? req.get('Referrer') || '/' : '/');
});

app.get('/health', (req, res) => res.json({ ok: true }));

init()
  .then(() => app.listen(PORT, () => console.log('listening on ' + PORT)))
  .catch(err => { console.error('startup failed', err); process.exit(1); });
