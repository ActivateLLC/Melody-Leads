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
    ? false : { rejectUnauthorized: false }
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

/* --------------------------------------------------------------- schema */

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
ALTER TABLE leads ADD COLUMN IF NOT EXISTS tag TEXT NOT NULL DEFAULT 'general';
ALTER TABLE leads ADD COLUMN IF NOT EXISTS last_contacted TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS lead_events (
  id      SERIAL PRIMARY KEY,
  lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
  at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  kind    TEXT NOT NULL,
  body    TEXT
);

CREATE INDEX IF NOT EXISTS leads_received_idx ON leads (received_at DESC);
CREATE INDEX IF NOT EXISTS leads_status_idx   ON leads (status);
CREATE INDEX IF NOT EXISTS leads_spam_idx     ON leads (is_spam);
CREATE INDEX IF NOT EXISTS leads_follow_idx   ON leads (next_follow_up);
CREATE INDEX IF NOT EXISTS leads_email_idx    ON leads (email);
CREATE INDEX IF NOT EXISTS events_lead_idx    ON lead_events (lead_id, at DESC);
`;

async function init() { await pool.query(SCHEMA); console.log('schema ready'); }

/* ----------------------------------------------------------------- auth */

const token = () =>
  crypto.createHmac('sha256', SESSION_SECRET).update(PASSWORD).digest('hex');
const authed = req =>
  PASSWORD !== '' && req.cookies && req.cookies.mv_session === token();
const requireAuth = (req, res, next) =>
  authed(req) ? next() : res.redirect('/login');

/* --------------------------------------------------------------- triage */

const SPAM_TERMS = ['seo service','backlink','crypto','casino','viagra','loan offer',
  'bitcoin','forex','escort','rank your site','guest post','web design services',
  'increase traffic','digital marketing agency'];

function triage(fields, message) {
  const hp = (fields.Website || fields.website || '').toString().trim();
  if (hp) return { spam: true, reason: 'honeypot filled' };
  const body = (message || '').toString();
  const lower = body.toLowerCase();
  const urls = body.match(/https?:\/\/|www\./gi) || [];
  if (urls.length >= 2) return { spam: true, reason: urls.length + ' links' };
  for (const t of SPAM_TERMS)
    if (lower.includes(t)) return { spam: true, reason: 'matched "' + t + '"' };
  if (/[\u0400-\u04FF\u4E00-\u9FFF]/.test(body))
    return { spam: true, reason: 'non-Latin script' };
  const email = (fields.Email || fields['Email Address'] || '').toString().toLowerCase();
  if (email && /@(mail\.ru|qq\.com|yandex\.)/.test(email))
    return { spam: true, reason: 'suspicious domain' };
  return { spam: false, reason: null };
}

const TAGS = ['speaking', 'book', 'guide', 'general'];

function inferTag(formName, message) {
  const f = (formName || '').toLowerCase();
  const m = (message || '').toLowerCase();
  if (f.includes('guide') || f.includes('email')) return 'guide';
  if (/keynote|speak|conference|workshop|panel|event|booking/.test(m + ' ' + f))
    return 'speaking';
  if (/book|still, i rise|copies|signed/.test(m)) return 'book';
  return 'general';
}

function pick(fields, keys) {
  for (const k of keys)
    for (const a of Object.keys(fields))
      if (a.toLowerCase() === k.toLowerCase() && fields[a])
        return String(fields[a]).trim();
  return null;
}

/* --------------------------------------------------------------- ingest */

app.post('/hook', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY)
    return res.status(401).json({ ok: false, error: 'bad key' });
  try {
    const payload = (req.body && req.body.payload) || req.body || {};
    const fields = payload.data || payload.fields || {};
    const formName = payload.name || payload.formName || 'unknown';
    const message = pick(fields, ['message','write about your project','event details','comments','notes']);
    const t = triage(fields, message);
    const tag = inferTag(formName, message);

    const r = await pool.query(
      `INSERT INTO leads (form_name,page_url,name,email,phone,organization,message,raw,
                          is_spam,spam_reason,status,tag)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id`,
      [formName, payload.pageUrl || null,
       pick(fields, ['name','full name','your name','first name']),
       pick(fields, ['email','email address','e-mail']),
       pick(fields, ['phone','phone number','telephone']),
       pick(fields, ['organization','organisation','company']),
       message, JSON.stringify(payload), t.spam, t.reason,
       t.spam ? 'spam' : 'new', tag]
    );
    await pool.query(
      `INSERT INTO lead_events (lead_id, kind, body) VALUES ($1,'received',$2)`,
      [r.rows[0].id, 'via ' + formName]);
    res.json({ ok: true, id: r.rows[0].id, spam: t.spam, tag });
  } catch (e) {
    console.error('ingest failed', e);
    res.status(500).json({ ok: false });
  }
});

/* ------------------------------------------------------------------- ui */

const STATUSES = ['new', 'contacted', 'booked', 'cold', 'spam'];

const esc = s => String(s == null ? '' : s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

const CSS = `
:root{--purple:#7670B3;--deep:#5C5695;--lav:#C7C4E2;--wash:#F4F3F9;--ink:#1F1D26;
      --mid:#4A4751;--soft:#7A7684;--line:#E4E2EC;--warn:#B4553F;}
*{box-sizing:border-box}
body{margin:0;background:var(--wash);color:var(--ink);
     font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
a{color:var(--deep)}
header{background:var(--purple);color:#fff;padding:14px 18px;position:sticky;top:0;z-index:20;
       display:flex;justify-content:space-between;align-items:center;gap:10px}
header h1{margin:0;font-size:1rem;font-weight:600}
header a{color:#fff;opacity:.9;text-decoration:none;font-size:.8rem}
.wrap{max-width:900px;margin:0 auto;padding:16px 14px 80px}
.tabs{display:flex;gap:7px;overflow-x:auto;padding-bottom:4px;margin-bottom:14px}
.tab{white-space:nowrap;padding:8px 14px;border-radius:999px;border:1px solid var(--line);
     background:#fff;color:var(--mid);text-decoration:none;font-size:.84rem}
.tab.on{background:var(--deep);border-color:var(--deep);color:#fff;font-weight:600}
.tab.due{border-color:var(--warn);color:var(--warn)}
.tab.due.on{background:var(--warn);border-color:var(--warn);color:#fff}
.search{display:flex;gap:7px;margin-bottom:14px}
.search input{flex:1;padding:11px 13px;border:1px solid var(--line);border-radius:10px;
              font-size:.92rem;background:#fff}
.search button{padding:11px 16px;border:0;border-radius:10px;background:var(--purple);
               color:#fff;font-weight:600;font-size:.84rem}
.bulkbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:#fff;
         border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-bottom:12px}
.bulkbar select{flex:1;min-width:140px;padding:9px;border:1px solid var(--line);border-radius:8px}
.bulkbar button{padding:9px 14px;border:0;border-radius:8px;background:var(--deep);
                color:#fff;font-weight:600;font-size:.82rem}
.bulkbar label{font-size:.8rem;color:var(--soft)}
.lead{background:#fff;border:1px solid var(--line);border-radius:12px;padding:14px;margin-bottom:10px;
      display:flex;gap:11px;align-items:flex-start}
.lead.spam{opacity:.6}
.lead.overdue{border-left:3px solid var(--warn)}
.lead input[type=checkbox]{margin-top:4px;width:18px;height:18px;flex:none}
.body{flex:1;min-width:0}
.meta{font-size:.74rem;color:var(--soft);margin-bottom:5px;
      display:flex;gap:7px;flex-wrap:wrap;align-items:center}
.who{font-weight:600;font-size:1rem;margin:0 0 2px}
.who a{text-decoration:none;color:var(--ink)}
.snip{font-size:.87rem;color:var(--mid);margin-top:5px;overflow:hidden}
.pill{font-size:.66rem;letter-spacing:.06em;text-transform:uppercase;padding:3px 8px;
      border-radius:999px;background:var(--wash);color:var(--deep);border:1px solid var(--line)}
.pill.spam{color:#9a3d3d;background:#fbeaea;border-color:#f2d6d6}
.pill.due{color:var(--warn);background:#fbefeb;border-color:#f0dcd4}
.empty{background:#fff;border:1px dashed var(--line);border-radius:12px;padding:32px 18px;
       text-align:center;color:var(--soft)}
.count{font-size:.78rem;color:var(--soft);margin:0 0 9px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.card h2{margin:0 0 4px;font-size:1.2rem}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.btn{padding:10px 15px;border:0;border-radius:9px;background:var(--deep);color:#fff;
     font-weight:600;font-size:.83rem;text-decoration:none;display:inline-block}
.btn.ghost{background:#fff;color:var(--deep);border:1px solid var(--lav)}
select,input[type=date],textarea,input[type=text]{border:1px solid var(--line);border-radius:8px;
     padding:10px 11px;font-size:.88rem;font-family:inherit;background:#fff}
textarea{width:100%;min-height:70px;resize:vertical}
.msg{font-size:.92rem;color:var(--mid);background:var(--wash);border-radius:9px;
     padding:11px 12px;white-space:pre-wrap;margin:9px 0}
.timeline{list-style:none;margin:10px 0 0;padding:0}
.timeline li{border-left:2px solid var(--line);padding:0 0 12px 13px;position:relative}
.timeline li::before{content:"";position:absolute;left:-5px;top:5px;width:8px;height:8px;
     border-radius:50%;background:var(--lav)}
.timeline .when{font-size:.72rem;color:var(--soft)}
.timeline .what{font-size:.89rem;color:var(--mid);white-space:pre-wrap}
.login{max-width:330px;margin:12vh auto;background:#fff;padding:24px;border-radius:14px;
       border:1px solid var(--line)}
.login input{width:100%;padding:12px;border:1px solid var(--line);border-radius:10px;
             margin-bottom:11px}
.login button{width:100%;padding:12px;border:0;border-radius:10px;background:var(--purple);
              color:#fff;font-weight:600}
.err{color:#9a3d3d;font-size:.84rem;margin-bottom:9px}
`;

const layout = (title, body) => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${CSS}</style></head><body>${body}</body></html>`;

/* ---------------------------------------------------------------- login */

app.get('/login', (req, res) => res.send(layout('Sign in', `
  <div class="login"><h2 style="margin:0 0 14px;font-size:1.05rem">Melody &mdash; leads</h2>
  ${req.query.bad ? '<div class="err">That password did not work.</div>' : ''}
  <form method="post" action="/login">
    <input type="password" name="password" placeholder="Password" autofocus>
    <button type="submit">Sign in</button></form></div>`)));

app.post('/login', (req, res) => {
  if (PASSWORD && req.body.password === PASSWORD) {
    res.cookie('mv_session', token(), { httpOnly: true, sameSite: 'lax',
      secure: true, maxAge: 1000 * 60 * 60 * 24 * 30 });
    return res.redirect('/');
  }
  res.redirect('/login?bad=1');
});

app.get('/logout', (req, res) => { res.clearCookie('mv_session'); res.redirect('/login'); });

/* ----------------------------------------------------------------- list */

app.get('/', requireAuth, async (req, res) => {
  const view = (req.query.view || 'due').toLowerCase();
  const q = (req.query.q || '').trim();
  const where = [];
  const params = [];

  if (view === 'due') {
    where.push(`is_spam = false AND status NOT IN ('booked','cold')
                AND next_follow_up IS NOT NULL AND next_follow_up <= CURRENT_DATE`);
  } else if (view === 'spam') {
    where.push('is_spam = true');
  } else if (view === 'all') {
    where.push('is_spam = false');
  } else if (TAGS.includes(view)) {
    params.push(view);
    where.push('is_spam = false AND tag = $' + params.length);
  } else {
    params.push(view);
    where.push('is_spam = false AND status = $' + params.length);
  }

  if (q) {
    params.push('%' + q.toLowerCase() + '%');
    const i = params.length;
    where.push(`(lower(coalesce(name,'')) LIKE $${i} OR lower(coalesce(email,'')) LIKE $${i}
              OR lower(coalesce(organization,'')) LIKE $${i} OR lower(coalesce(message,'')) LIKE $${i})`);
  }

  const order = view === 'due' ? 'next_follow_up ASC' : 'received_at DESC';
  const { rows } = await pool.query(
    `SELECT * FROM leads WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT 300`, params);

  const c = await pool.query(`
    SELECT
      count(*) FILTER (WHERE NOT is_spam AND status='new')       AS c_new,
      count(*) FILTER (WHERE NOT is_spam AND status='contacted') AS c_contacted,
      count(*) FILTER (WHERE NOT is_spam AND status='booked')    AS c_booked,
      count(*) FILTER (WHERE is_spam)                            AS c_spam,
      count(*) FILTER (WHERE NOT is_spam)                        AS c_all,
      count(*) FILTER (WHERE NOT is_spam AND status NOT IN ('booked','cold')
                        AND next_follow_up IS NOT NULL
                        AND next_follow_up <= CURRENT_DATE)      AS c_due
    FROM leads`);
  const n = c.rows[0];

  const tab = (key, label, extra) =>
    `<a class="tab ${extra || ''} ${view === key ? 'on' : ''}"
        href="/?view=${key}${q ? '&q=' + encodeURIComponent(q) : ''}">${label}</a>`;

  const tabs = [
    tab('due', 'Due (' + n.c_due + ')', 'due'),
    tab('new', 'New (' + n.c_new + ')'),
    tab('contacted', 'Contacted (' + n.c_contacted + ')'),
    tab('booked', 'Booked (' + n.c_booked + ')'),
    tab('speaking', 'Speaking'),
    tab('book', 'Book'),
    tab('guide', 'Guide'),
    tab('all', 'All (' + n.c_all + ')'),
    tab('spam', 'Spam (' + n.c_spam + ')')
  ].join('');

  const today = new Date().toISOString().slice(0, 10);

  const items = rows.length ? rows.map(l => {
    const overdue = l.next_follow_up &&
      new Date(l.next_follow_up).toISOString().slice(0, 10) <= today &&
      !['booked', 'cold'].includes(l.status);
    const when = new Date(l.received_at).toLocaleDateString('en-US',
      { month: 'short', day: 'numeric' });
    return `<div class="lead ${l.is_spam ? 'spam' : ''} ${overdue ? 'overdue' : ''}">
      <input type="checkbox" name="ids" value="${l.id}" form="bulk">
      <div class="body">
        <div class="meta">
          <span>${esc(when)}</span>
          <span class="pill">${esc(l.tag)}</span>
          ${l.is_spam ? `<span class="pill spam">${esc(l.spam_reason || 'spam')}</span>` : ''}
          ${overdue ? `<span class="pill due">follow up</span>` : ''}
        </div>
        <p class="who"><a href="/lead/${l.id}">${esc(l.name || l.email || 'No name')}</a></p>
        <div class="meta">${esc(l.organization || '')}${l.email ? ' &middot; ' + esc(l.email) : ''}</div>
        ${l.message ? `<div class="snip">${esc(String(l.message).slice(0, 160))}</div>` : ''}
      </div></div>`;
  }).join('') : `<div class="empty">Nothing here.</div>`;

  res.send(layout('Leads', `
    <header><h1>Melody &mdash; leads</h1><a href="/logout">Sign out</a></header>
    <div class="wrap">
      <div class="tabs">${tabs}</div>
      <form class="search" method="get" action="/">
        <input type="hidden" name="view" value="${esc(view)}">
        <input name="q" value="${esc(q)}" placeholder="Search name, email, organisation, message">
        <button type="submit">Search</button>
      </form>
      <form id="bulk" method="post" action="/bulk">
        <input type="hidden" name="back" value="${esc(view)}">
        <div class="bulkbar">
          <label><input type="checkbox" onclick="document.querySelectorAll('input[name=ids]').forEach(function(c){c.checked=event.target.checked})"> All</label>
          <select name="action">
            <option value="spam">Mark as spam</option>
            <option value="not_spam">Not spam &rarr; new</option>
            <option value="contacted">Mark contacted</option>
            <option value="booked">Mark booked</option>
            <option value="cold">Mark cold</option>
          </select>
          <button type="submit">Apply</button>
        </div>
      </form>
      <p class="count">${rows.length} shown</p>
      ${items}
    </div>`));
});

/* --------------------------------------------------------------- detail */

app.get('/lead/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');

  const { rows } = await pool.query('SELECT * FROM leads WHERE id=$1', [id]);
  if (!rows.length) return res.status(404).send('not found');
  const l = rows[0];

  const ev = await pool.query(
    'SELECT * FROM lead_events WHERE lead_id=$1 ORDER BY at DESC LIMIT 100', [id]);

  const also = l.email
    ? await pool.query(
        'SELECT id, received_at, form_name FROM leads WHERE email=$1 AND id<>$2 ORDER BY received_at DESC',
        [l.email, id])
    : { rows: [] };

  const statusOpts = STATUSES.map(s =>
    `<option value="${s}" ${s === l.status ? 'selected' : ''}>${s}</option>`).join('');
  const tagOpts = TAGS.map(t =>
    `<option value="${t}" ${t === l.tag ? 'selected' : ''}>${t}</option>`).join('');

  const timeline = ev.rows.map(e => `<li>
      <div class="when">${new Date(e.at).toLocaleString('en-US',
        { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })}
        &middot; ${esc(e.kind)}</div>
      ${e.body ? `<div class="what">${esc(e.body)}</div>` : ''}</li>`).join('');

  res.send(layout(l.name || 'Lead', `
    <header><h1><a href="/" style="color:#fff;text-decoration:none">&larr; Leads</a></h1>
      <a href="/logout">Sign out</a></header>
    <div class="wrap">
      <div class="card">
        <h2>${esc(l.name || 'No name given')}</h2>
        <div class="meta">${esc(l.organization || '')}</div>
        <div class="meta">Received ${new Date(l.received_at).toLocaleString('en-US',
          { month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit' })}
          via ${esc(l.form_name || 'form')}</div>
        ${l.message ? `<div class="msg">${esc(l.message)}</div>` : ''}
        <div class="row">
          ${l.email ? `<a class="btn" href="mailto:${esc(l.email)}">Email</a>` : ''}
          ${l.phone ? `<a class="btn ghost" href="tel:${esc(l.phone)}">Call</a>` : ''}
        </div>
        <form method="post" action="/lead/${l.id}/contacted" class="row">
          <button class="btn ghost" type="submit">Log that I contacted them</button>
        </form>
        ${l.last_contacted ? `<div class="meta" style="margin-top:8px">Last contacted
          ${new Date(l.last_contacted).toLocaleDateString('en-US',
            { month: 'short', day: 'numeric' })}</div>` : ''}
      </div>

      <div class="card">
        <form method="post" action="/lead/${l.id}">
          <div class="row">
            <select name="status">${statusOpts}</select>
            <select name="tag">${tagOpts}</select>
            <input type="date" name="next_follow_up"
              value="${l.next_follow_up ? new Date(l.next_follow_up).toISOString().slice(0,10) : ''}">
          </div>
          <div class="row"><textarea name="note" placeholder="Add a note"></textarea></div>
          <div class="row"><button class="btn" type="submit">Save</button></div>
        </form>
      </div>

      ${also.rows.length ? `<div class="card">
        <div class="meta">Also submitted ${also.rows.length} other time(s)</div>
        ${also.rows.map(o => `<div><a href="/lead/${o.id}">
          ${new Date(o.received_at).toLocaleDateString('en-US',
            { month: 'short', day: 'numeric', year: 'numeric' })}
          &middot; ${esc(o.form_name || 'form')}</a></div>`).join('')}
      </div>` : ''}

      <div class="card">
        <div class="meta">History</div>
        <ul class="timeline">${timeline}</ul>
      </div>
    </div>`));
});

/* --------------------------------------------------------------- writes */

app.post('/lead/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  const { status, tag, next_follow_up, note } = req.body;
  const s = STATUSES.includes(status) ? status : 'new';

  const before = await pool.query('SELECT status FROM leads WHERE id=$1', [id]);

  await pool.query(
    `UPDATE leads SET status=$1, tag=$2, next_follow_up=NULLIF($3,'')::date,
       is_spam=($1='spam'), updated_at=now() WHERE id=$4`,
    [s, TAGS.includes(tag) ? tag : 'general', next_follow_up || '', id]);

  if (before.rows.length && before.rows[0].status !== s)
    await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'status',$2)`,
      [id, before.rows[0].status + ' -> ' + s]);

  if (note && note.trim())
    await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'note',$2)`,
      [id, note.trim()]);

  res.redirect('/lead/' + id);
});

app.post('/lead/:id/contacted', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  await pool.query(
    `UPDATE leads SET last_contacted=now(),
       status=CASE WHEN status='new' THEN 'contacted' ELSE status END,
       updated_at=now() WHERE id=$1`, [id]);
  await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'contacted',NULL)`, [id]);
  res.redirect('/lead/' + id);
});

app.post('/bulk', requireAuth, async (req, res) => {
  let ids = req.body.ids || [];
  if (!Array.isArray(ids)) ids = [ids];
  ids = ids.map(n => parseInt(n, 10)).filter(Number.isInteger);
  const action = req.body.action;
  const back = req.body.back || 'due';

  if (ids.length) {
    if (action === 'spam') {
      await pool.query(`UPDATE leads SET is_spam=true, status='spam',
        spam_reason='marked by hand', updated_at=now() WHERE id = ANY($1)`, [ids]);
    } else if (action === 'not_spam') {
      await pool.query(`UPDATE leads SET is_spam=false, status='new', spam_reason=NULL,
        updated_at=now() WHERE id = ANY($1)`, [ids]);
    } else if (['contacted', 'booked', 'cold'].includes(action)) {
      await pool.query(`UPDATE leads SET status=$1, is_spam=false, updated_at=now()
        WHERE id = ANY($2)`, [action, ids]);
      if (action === 'contacted')
        await pool.query(`UPDATE leads SET last_contacted=now() WHERE id = ANY($1)`, [ids]);
    }
    for (const id of ids)
      await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'bulk',$2)`,
        [id, action]);
  }
  res.redirect('/?view=' + encodeURIComponent(back));
});

app.get('/health', (req, res) => res.json({ ok: true }));

init().then(() => app.listen(PORT, () => console.log('listening on ' + PORT)))
      .catch(e => { console.error('startup failed', e); process.exit(1); });
