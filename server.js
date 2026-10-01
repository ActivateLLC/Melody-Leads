'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 5 } });

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
app.use(express.static('public', { maxAge: '7d' }));

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
ALTER TABLE leads ADD COLUMN IF NOT EXISTS intent TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS event_date TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS audience TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS urgency TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS draft_reply TEXT;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS fee NUMERIC(10,2);

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

DROP TABLE IF EXISTS briefs;

CREATE TABLE IF NOT EXISTS engagements (
  id        TEXT PRIMARY KEY,
  name      TEXT NOT NULL,
  starts_at TIMESTAMPTZ,
  date_label TEXT,
  location  TEXT,
  link      TEXT,
  notes     TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
  id         SERIAL PRIMARY KEY,
  lead_id    INTEGER REFERENCES leads(id) ON DELETE CASCADE,
  sent_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  to_email   TEXT NOT NULL,
  subject    TEXT,
  body       TEXT NOT NULL,
  kind       TEXT NOT NULL DEFAULT 'reply'
);
CREATE INDEX IF NOT EXISTS messages_lead_idx ON messages (lead_id, sent_at DESC);
ALTER TABLE messages ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'out';
ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_id TEXT;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS from_email TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS messages_msgid_idx ON messages (message_id)
  WHERE message_id IS NOT NULL;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'form';

CREATE TABLE IF NOT EXISTS requests (
  id         SERIAL PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  body       TEXT NOT NULL,
  page       TEXT,
  urgency    TEXT NOT NULL DEFAULT 'whenever',
  status     TEXT NOT NULL DEFAULT 'open',
  reply      TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS event_files (
  token      TEXT PRIMARY KEY,
  event_id   TEXT NOT NULL,
  filename   TEXT NOT NULL,
  mime       TEXT NOT NULL,
  bytes      BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS event_files_event_idx ON event_files (event_id);

CREATE TABLE IF NOT EXISTS request_files (
  id         SERIAL PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  filename   TEXT NOT NULL,
  mime       TEXT NOT NULL,
  bytes      BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS request_files_idx ON request_files (request_id);

CREATE TABLE IF NOT EXISTS briefs (
  day   TEXT PRIMARY KEY,
  body  TEXT NOT NULL,
  made  TIMESTAMPTZ NOT NULL DEFAULT now()
);
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
const AI_KEY = process.env.ANTHROPIC_API_KEY || '';
const AI_MODEL = process.env.AI_MODEL || 'claude-sonnet-4-6';

async function askClaude(system, user, maxTokens) {
  if (!AI_KEY) return null;
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': AI_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: AI_MODEL,
        max_tokens: maxTokens || 700,
        system: system,
        messages: [{ role: 'user', content: user }]
      })
    });
    if (!r.ok) { console.error('claude', r.status, await r.text()); return null; }
    const d = await r.json();
    return (d.content || []).filter(b => b.type === 'text').map(b => b.text).join('').trim();
  } catch (e) { console.error('claude call failed', e); return null; }
}

const CLASSIFY_SYSTEM = `You triage enquiries for Melody Vachal, a keynote speaker and author on caregiving.
Return ONLY a JSON object, no prose, no code fences, with these keys:
  "tag": one of "speaking","book","guide","general"
  "is_spam": true or false
  "spam_reason": short string or null
  "intent": one short sentence describing what they want
  "event_date": ISO date string if an event date is mentioned, else null
  "audience": approximate audience size as a string, else null
  "organization": organisation name if stated or inferable, else null
  "urgency": "high","normal" or "low"
Mark is_spam true only for bulk marketing, SEO/backlink offers, or obvious bot submissions.
A short or blunt genuine enquiry is NOT spam.`;

async function aiClassify(formName, fields, message) {
  const out = await askClaude(CLASSIFY_SYSTEM,
    'Form: ' + formName + '\nFields: ' + JSON.stringify(fields).slice(0, 2500), 500);
  if (!out) return null;
  try { return JSON.parse(out.replace(/```json|```/g, '').trim()); }
  catch (e) { console.error('classify parse failed', out.slice(0, 200)); return null; }
}

const BOOKING_LINK = process.env.BOOKING_LINK ||
  'https://bookings.cloud.microsoft/bookwithme/user/943ee483881a40259b5b38356efce638%40arisecares.com';

const REPLY_SYSTEM = `You draft email replies as Melody Vachal: keynote speaker, author of
"Still, I Rise: A Guide to Navigating the Caregiver Journey", speech-language pathologist,
Master Certified Health and Wellness Coach. She cared for her son for thirty years and was
herself a care recipient after an accident.
Her voice is warm, direct and unfussy. Short paragraphs. No exclamation marks, no corporate
filler, no "I hope this finds you well". She never overpromises on dates she has not confirmed.
Write only the body of the email. No subject line, no signature block — she adds her own.
If the enquiry is about booking her to speak, ask the two questions she always needs:
the date and the audience, and offer a call using this exact link on its own line:
${BOOKING_LINK}
Keep it under 160 words.`;

const BRIEF_SYSTEM = `You write a two or three sentence orientation for Melody Vachal, a
keynote speaker, before she works through her enquiry queue.
Be concrete and specific: name organisations, dates and numbers where they exist.
Lead with whatever is most time-sensitive. Plain sentences, no bullet points, no greeting,
no sign-off, no exclamation marks. If there is genuinely nothing pressing, say so briefly.
Never invent detail that is not in the data.`;

async function buildBrief() {
  const { rows } = await pool.query(`
    SELECT name, organization, tag, status, intent, event_date, audience, urgency,
           next_follow_up, received_at
      FROM leads
     WHERE is_spam = false AND status NOT IN ('booked','cold')
     ORDER BY (next_follow_up IS NOT NULL AND next_follow_up <= CURRENT_DATE) DESC,
              received_at DESC
     LIMIT 40`);
  if (!rows.length) return 'Nothing open right now. The queue is clear.';
  const lines = rows.map(r =>
    [r.name || 'unnamed', r.organization, r.tag, r.status,
     r.intent, r.event_date ? 'date ' + r.event_date : null,
     r.audience ? 'audience ' + r.audience : null,
     r.urgency === 'high' ? 'urgent' : null,
     r.next_follow_up ? 'follow up ' + new Date(r.next_follow_up).toISOString().slice(0,10) : null
    ].filter(Boolean).join(' | ')).join(String.fromCharCode(10));
  const out = await askClaude(BRIEF_SYSTEM,
    'Today is ' + new Date().toISOString().slice(0,10) + '.\nOpen enquiries:\n' + lines, 300);
  return out || null;
}

async function todaysBrief() {
  if (!AI_KEY) return null;
  try {
    // The key includes what is actually open, so the brief can never describe
    // a state that has since changed.
    const sig = await pool.query(`
      SELECT count(*)::int AS open,
             COALESCE(max(updated_at), now())::text AS touched
        FROM leads WHERE is_spam = false AND status NOT IN ('booked','cold')`);
    const open = sig.rows[0].open;
    const key = new Date().toISOString().slice(0, 10) + '|' + open + '|' +
                sig.rows[0].touched.slice(0, 16);

    if (open === 0) return null;   // nothing open, nothing to brief

    const cached = await pool.query('SELECT body FROM briefs WHERE day = $1', [key]);
    if (cached.rows.length) return cached.rows[0].body;

    const body = await buildBrief();
    if (!body) return null;
    await pool.query('DELETE FROM briefs WHERE day <> $1', [key]);   // only ever one
    await pool.query(
      `INSERT INTO briefs (day, body) VALUES ($1,$2)
       ON CONFLICT (day) DO UPDATE SET body = EXCLUDED.body, made = now()`, [key, body]);
    return body;
  } catch (e) { console.error('brief failed', e); return null; }
}

const FOLLOWUP_SYSTEM = REPLY_SYSTEM + `
This is a FOLLOW-UP: she already replied and has not heard back. Acknowledge that lightly
without guilt-tripping, keep it shorter than a first reply, and make it easy to answer with
one line. Do not repeat everything from the first message.`;

const REVISE_MODES = {
  shorter:  'Cut it down. Keep every point that matters, lose everything else. Aim for half the length.',
  warmer:   'Make it warmer and more personal, without becoming gushing or adding exclamation marks.',
  direct:   'Make it more direct and businesslike. Shorter sentences, clearer ask, no softening.',
  grammar:  'Fix spelling, grammar and punctuation only. Do not change the wording, tone, length or meaning otherwise.'
};

async function aiRevise(text, mode, lead) {
  var instruction = REVISE_MODES[mode];
  if (!instruction) return null;
  var sys = mode === 'grammar'
    ? 'You correct spelling, grammar and punctuation in an email draft. Return only the corrected text, nothing else. Change nothing but errors.'
    : REPLY_SYSTEM + '\nYou are revising an existing draft. Return only the revised body.';
  return askClaude(sys,
    instruction + '\n\nContext: enquiry from ' + (lead.name || 'someone') +
    (lead.organization ? ' at ' + lead.organization : '') +
    '\n\nDraft to revise:\n' + text, 700);
}

async function aiDraftFollowUp(lead) {
  return askClaude(FOLLOWUP_SYSTEM,
    'Write a follow-up.\n\nTo: ' + (lead.name || 'unknown') +
    (lead.organization ? ' at ' + lead.organization : '') +
    '\nTheir original message: ' + (lead.message || '(none)') +
    '\nYou last contacted them: ' + (lead.last_contacted ? new Date(lead.last_contacted).toDateString() : 'unknown') +
    (lead.draft_reply ? '\nWhat you sent before:\n' + lead.draft_reply : ''), 600);
}

const ASK_SYSTEM = `You are the assistant inside Melody Vachal's enquiry inbox.
Answer her question using ONLY the data given to you. If the data does not contain the answer,
say so plainly rather than guessing. Be brief: two or three sentences, plain language, no lists
unless she asked for one. Never invent a name, number, date or organisation.

You have no memory of anything you said before: every question arrives fresh, with only the
data below. So never claim to remember an earlier answer, never apologise for an earlier
answer, and never speculate about what you might have said. If she refers to something you
supposedly told her, just say what the data shows now and leave it there.

Return ONLY a JSON object, no prose, no code fences:
{"answer": "...", "view": one of "due","new","contacted","booked","speaking","book","guide","all","spam" or null}
Set "view" only when that list actually has something in it and looking at it would help her
act. If the relevant list is empty, set view to null.`;

async function aiAsk(question) {
  const counts = await pool.query(`
    SELECT count(*) FILTER (WHERE NOT is_spam AND status='new')::int AS new,
           count(*) FILTER (WHERE NOT is_spam AND status='contacted')::int AS contacted,
           count(*) FILTER (WHERE NOT is_spam AND status='booked')::int AS booked,
           count(*) FILTER (WHERE NOT is_spam AND status='cold')::int AS cold,
           count(*) FILTER (WHERE is_spam)::int AS spam,
           count(*) FILTER (WHERE NOT is_spam AND status NOT IN ('booked','cold')
                     AND next_follow_up IS NOT NULL AND next_follow_up <= CURRENT_DATE)::int AS due,
           COALESCE(sum(fee) FILTER (WHERE NOT is_spam AND status='booked'),0)::numeric AS booked_value
      FROM leads`);

  const leads = await pool.query(`
    SELECT id,name,organization,email,tag,status,intent,event_date,audience,fee,
           next_follow_up,last_contacted,received_at
      FROM leads WHERE is_spam = false
     ORDER BY received_at DESC LIMIT 60`);

  const spam = await pool.query(
    `SELECT name,organization,spam_reason,received_at FROM leads WHERE is_spam ORDER BY received_at DESC LIMIT 20`);

  const eng = await pool.query(
    `SELECT name,date_label,location,notes,starts_at FROM engagements ORDER BY starts_at ASC LIMIT 10`);

  const context =
    'Today is ' + new Date().toISOString().slice(0,10) + '.\n' +
    'Counts: ' + JSON.stringify(counts.rows[0]) + '\n' +
    'Enquiries (most recent first): ' + JSON.stringify(leads.rows) + '\n' +
    'Filed as spam: ' + JSON.stringify(spam.rows) + '\n' +
    'Upcoming engagements: ' + JSON.stringify(eng.rows);

  const out = await askClaude(ASK_SYSTEM, 'Her question: ' + question + '\n\nData:\n' + context, 500);
  if (!out) return null;
  try { return JSON.parse(out.replace(/```json|```/g, '').trim()); }
  catch (e) { return { answer: out.slice(0, 600), view: null }; }
}

async function aiDraftReply(lead) {
  return askClaude(REPLY_SYSTEM,
    'Reply to this enquiry.\n\nFrom: ' + (lead.name || 'unknown') +
    (lead.organization ? ' at ' + lead.organization : '') +
    '\nForm: ' + (lead.form_name || 'contact') +
    '\nMessage: ' + (lead.message || '(no message)'), 600);
}


function inferTag(formName, message) {
  const f = (formName || '').toLowerCase();
  const m = (message || '').toLowerCase();
  if (f.includes('guide') || f.includes('email')) return 'guide';
  if (/keynote|speak|conference|workshop|panel|event|booking/.test(m + ' ' + f))
    return 'speaking';
  if (/book|still, i rise|copies|signed/.test(m)) return 'book';
  return 'general';
}

// Webflow field labels vary per form: "Name", "Message Form - Name",
// "Message/Email Address". Match on the meaningful part, not the whole label.
function pick(fields, keys) {
  const norm = x => String(x).toLowerCase().replace(/[^a-z]+/g, ' ').trim();
  const entries = Object.keys(fields)
    .filter(a => fields[a] !== null && fields[a] !== undefined && String(fields[a]).trim() !== '')
    .map(a => [a, norm(a)]);

  for (const k of keys) {
    const nk = norm(k);
    for (const [a, na] of entries) if (na === nk) return String(fields[a]).trim();
  }
  for (const k of keys) {
    const nk = norm(k);
    for (const [a, na] of entries) {
      const words = na.split(' ');
      if (words.includes(nk) || na.endsWith(' ' + nk) || na.startsWith(nk + ' '))
        return String(fields[a]).trim();
    }
  }
  for (const k of keys) {
    const nk = norm(k);
    for (const [a, na] of entries) if (na.includes(nk)) return String(fields[a]).trim();
  }
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
    const message = pick(fields, ['write about your project','inquiry details','event details','your message','comments','notes','message']);

    // Honeypot is decided locally and is never overridden by the model.
    const hp = (fields.Website || fields.website || '').toString().trim();

    let spam, reason, tag, intent = null, eventDate = null, audience = null, urgency = null;
    const ai = hp ? null : await aiClassify(formName, fields, message);

    const guideOnly = /guide|email form/i.test(formName) && !message;

    if (ai) {
      spam = hp ? true : (!!ai.is_spam || guideOnly);
      reason = hp ? 'honeypot filled'
             : (ai.spam_reason || (guideOnly ? 'guide signup, nothing to reply to' : null));
      tag = TAGS.includes(ai.tag) ? ai.tag : inferTag(formName, message);
      intent = ai.intent || null;
      eventDate = ai.event_date || null;
      audience = ai.audience || null;
      urgency = ['high','normal','low'].includes(ai.urgency) ? ai.urgency : 'normal';
    } else {
      const t = triage(fields, message);
      spam = t.spam || guideOnly;
      reason = t.reason || (guideOnly ? 'guide signup, nothing to reply to' : null);
      tag = inferTag(formName, message);
      urgency = 'normal';
    }

    const org = pick(fields, ['organization','organisation','company'])
             || (ai && ai.organization) || null;

    const r = await pool.query(
      `INSERT INTO leads (form_name,page_url,name,email,phone,organization,message,raw,
                          is_spam,spam_reason,status,tag,intent,event_date,audience,urgency)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
      [formName, payload.pageUrl || null,
       pick(fields, ['name','full name','your name','first name']),
       pick(fields, ['email','email address','e mail','email cta']),
       pick(fields, ['phone','phone number','telephone']),
       org, message, JSON.stringify(payload), spam, reason,
       spam ? 'spam' : 'new', tag, intent, eventDate, audience, urgency]
    );
    const id = r.rows[0].id;
    await pool.query(
      `INSERT INTO lead_events (lead_id, kind, body) VALUES ($1,'received',$2)`,
      [id, 'via ' + formName + (ai ? ' \u00b7 classified by AI' : '')]);

    // Draft a reply up front for genuine enquiries, so it is waiting when she opens it.
    if (!spam && AI_KEY) {
      const lead = { name: pick(fields, ['name','full name']), organization: org,
                     form_name: formName, message };
      aiDraftReply(lead).then(draft => {
        if (draft) pool.query('UPDATE leads SET draft_reply=$1 WHERE id=$2', [draft, id])
          .catch(e => console.error('draft save failed', e));
      });
    }

    if (!spam) alertNewEnquiry(id);
    res.json({ ok: true, id, spam, tag, ai: !!ai });
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
:root{
  /* Anchor — her brand purple */
  --purple:#7670B3; --deep:#5C5695; --lav:#C7C4E2; --lav-soft:#E8E7F3;
  /* Warm paper base: comfort comes from warmth, not grey */
  --paper:#FAF7F3; --card:#FFFFFF; --line:#EAE3DC;
  /* Ink, warmed slightly so it never reads as cold black */
  --ink:#241F2B; --mid:#544E5C; --soft:#8A8291;
  /* Meaning colours, used only where they mean something */
  --due:#C2613C;      /* terracotta — attention, not alarm */
  --due-bg:#FBEFE9;
  --good:#5B8F72;     /* sage — booked, settled */
  --good-bg:#EDF4EF;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);
     font:17px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     -webkit-font-smoothing:antialiased}
a{color:var(--deep)}
header{background:var(--purple);color:#fff;padding:14px 18px;position:sticky;top:0;z-index:20;
       display:flex;justify-content:space-between;align-items:center;gap:10px}
header h1{margin:0;font-size:1rem;font-weight:600;letter-spacing:.01em;
  display:flex;align-items:center;gap:9px}
.hdr-logo{height:38px;width:38px;object-fit:contain;display:block;flex:none;padding:5px;
  border-radius:50%;
  background:radial-gradient(circle,rgba(255,255,255,.95) 0%,rgba(255,255,255,.86) 38%,
             rgba(255,255,255,.28) 60%,rgba(255,255,255,0) 72%)}
header a{color:#fff;opacity:.88;text-decoration:none;font-size:.8rem}
.hdr-nav{display:flex;gap:14px;align-items:center}
.wrap{max-width:900px;margin:0 auto;padding:16px 14px 80px}

/* Summary */
.summary{background:linear-gradient(158deg,#5C5695 0%,#7670B3 62%,#8A7FC0 100%);
         color:#fff;border-radius:16px;padding:20px 18px 17px;margin-bottom:16px;
         box-shadow:0 10px 26px -14px rgba(92,86,149,.55)}
.summary .hello{font-size:.7rem;letter-spacing:.24em;text-transform:uppercase;
                color:#D6CFEE;margin-bottom:9px}
.summary .line{font-size:1.34rem;font-weight:600;line-height:1.28;margin:0}
.summary .sub{font-size:.85rem;color:rgba(255,255,255,.8);margin-top:6px;max-width:34em}
.stats{display:flex;gap:16px;margin-top:15px;padding-top:14px;
       border-top:1px solid rgba(255,255,255,.24)}
.stat{flex:1}
.stat b{display:block;font-size:1.55rem;font-weight:700;line-height:1.1;
        font-variant-numeric:tabular-nums}
.stat span{font-size:.68rem;letter-spacing:.11em;text-transform:uppercase;
           color:rgba(255,255,255,.74)}

.uplabel{font-size:.82rem;font-weight:600;color:var(--mid);margin-bottom:7px}
.upfile{width:100%;padding:13px;border:1px dashed var(--lav);border-radius:11px;
  background:var(--paper);font-family:inherit;font-size:.92rem}
.uphint{font-size:.82rem;color:var(--soft);margin-top:7px;line-height:1.45}
.shots{display:flex;gap:9px;flex-wrap:wrap;margin-top:11px}
.shots img{width:104px;height:104px;object-fit:cover;border-radius:10px;
  border:1px solid var(--line);display:block}
.toast{background:var(--good-bg);border:1px solid #CFE3D6;border-radius:13px;
  padding:13px 15px;margin-bottom:13px}
.toast-text{font-size:.95rem;line-height:1.5;color:var(--ink)}
.toast-acts{display:flex;gap:9px;margin-top:10px;align-items:center}
.toast-acts form{margin:0}
.toast-btn{border:1px solid #CFE3D6;background:var(--card);color:var(--good);
  border-radius:999px;padding:9px 16px;font-size:.85rem;font-weight:600;font-family:inherit;
  text-decoration:none;display:inline-block;cursor:pointer}
.ask{display:flex;gap:7px;margin-bottom:12px}
.ask input{flex:1;padding:14px;border:1px solid var(--lav);border-radius:11px;font-size:1rem;
  background:var(--card);min-height:48px;font-family:inherit}
.ask input:focus{outline:none;box-shadow:0 0 0 3px var(--lav-soft)}
.ask button{padding:14px 20px;border:0;border-radius:11px;background:var(--deep);color:#fff;
  font-weight:600;font-size:.95rem;min-height:48px;font-family:inherit}
.answer{background:var(--card);border:1px solid var(--lav);border-radius:13px;
  padding:14px 15px;margin-bottom:14px}
.answer-q{font-size:.8rem;color:var(--soft);margin-bottom:7px}
.answer-q::before{content:"You asked: "}
.answer-a{font-size:1rem;line-height:1.55;color:var(--ink)}
.answer-go{display:inline-block;margin-top:11px;font-size:.86rem;font-weight:600;color:var(--deep);
  text-decoration:none;border-bottom:1px solid var(--lav);padding-bottom:2px}
@keyframes mvpulse{0%{box-shadow:0 0 0 0 rgba(118,112,179,.55)}
                   70%{box-shadow:0 0 0 12px rgba(118,112,179,0)}
                   100%{box-shadow:0 0 0 0 rgba(118,112,179,0)}}
.tab.flash{animation:mvpulse 1.15s ease-out 2}
.diary{background:var(--card);border:1px solid var(--line);border-radius:13px;
  padding:14px 15px;margin-bottom:14px}
.diary-label{font-size:.72rem;letter-spacing:.2em;text-transform:uppercase;
  color:var(--soft);margin-bottom:10px}
.diary-row{display:flex;gap:13px;padding:10px 0;border-top:1px solid var(--line)}
.diary-row:first-of-type{border-top:0;padding-top:0}
.diary-when{flex:none;min-width:5.6em;font-size:.82rem;font-weight:700;color:var(--due)}
.diary-name{font-weight:600;font-size:1rem;line-height:1.35}
.diary-meta{font-size:.86rem;color:var(--soft);margin-top:2px}
.diary-link{display:inline-block;margin-top:6px;font-size:.82rem;font-weight:600;color:var(--deep)}
.tabs{display:flex;gap:7px;overflow-x:auto;padding-bottom:4px;margin-bottom:14px}
.tab{white-space:nowrap;padding:12px 18px;border-radius:999px;border:1px solid var(--line);
     background:var(--card);color:var(--mid);text-decoration:none;font-size:.95rem;
     display:inline-flex;align-items:center;min-height:44px}
.tab.on{background:var(--deep);border-color:var(--deep);color:#fff;font-weight:600}
.tab.due{border-color:#E8CDBF;color:var(--due);background:var(--due-bg)}
.tab.due.on{background:var(--due);border-color:var(--due);color:#fff}
.search{display:flex;gap:7px;margin-bottom:14px}
.search input{flex:1;padding:14px 14px;border:1px solid var(--line);border-radius:10px;
              font-size:1rem;background:var(--card);min-height:48px}
.search input:focus{outline:none;border-color:var(--lav);box-shadow:0 0 0 3px var(--lav-soft)}
.search button{padding:14px 20px;border:0;border-radius:10px;background:var(--purple);
               color:#fff;font-weight:600;font-size:.95rem;min-height:48px}
.bulkbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:var(--card);
         border:1px solid var(--line);border-radius:11px;padding:10px 12px;margin-bottom:12px}
.bulkbar select{flex:1;min-width:140px;padding:9px;border:1px solid var(--line);border-radius:8px}
.bulkbar button{padding:9px 14px;border:0;border-radius:8px;background:var(--deep);
                color:#fff;font-weight:600;font-size:.82rem}
.bulkbar label{font-size:.8rem;color:var(--soft)}

.lead{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:14px;
      margin-bottom:10px;display:flex;gap:11px;align-items:flex-start}
.lead.spam{opacity:.58}
.lead.overdue{border-left:3px solid var(--due)}
.lead input[type=checkbox]{margin-top:4px;width:26px;height:26px;flex:none;accent-color:var(--purple)}
.body{flex:1;min-width:0}
.meta{font-size:.86rem;color:var(--mid);margin-bottom:6px;
      display:flex;gap:7px;flex-wrap:wrap;align-items:center}
.who{font-weight:700;font-size:1.15rem;margin:0 0 3px;letter-spacing:-.01em}
.who a{text-decoration:none;color:var(--ink)}
.snip{font-size:.98rem;color:var(--mid);margin-top:7px;overflow:hidden}
.pill{font-size:.76rem;letter-spacing:.06em;text-transform:uppercase;padding:3px 8px;
      border-radius:999px;background:var(--lav-soft);color:var(--deep);border:1px solid #DDD7EE}
.pill.spam{color:#9A5A48;background:#F6EDE8;border-color:#E9DAD1}
.pill.due{color:var(--due);background:var(--due-bg);border-color:#EFD6C8}
.pill.good{color:var(--good);background:var(--good-bg);border-color:#D6E6DB}
.empty{background:var(--card);border:1px dashed var(--line);border-radius:13px;padding:34px 18px;
       text-align:center;color:var(--soft)}
.count{font-size:.9rem;color:var(--mid);margin:0 0 10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:13px;padding:16px;
      margin-bottom:12px}
.card h2{margin:0 0 4px;font-size:1.2rem;letter-spacing:-.01em}
.draft-box{width:100%;min-height:190px;border:1px solid var(--line);border-radius:11px;
  padding:14px;font-size:1rem;line-height:1.6;font-family:inherit;background:var(--paper);
  color:var(--ink);resize:vertical}
.draft-box:focus{outline:none;border-color:var(--lav);box-shadow:0 0 0 3px var(--lav-soft);background:#fff}
.revise-label{font-size:.74rem;letter-spacing:.14em;text-transform:uppercase;color:var(--soft);
  margin:14px 0 7px}
.revise{display:flex;gap:7px;flex-wrap:wrap}
.chip{border:1px solid var(--lav);background:var(--card);color:var(--deep);border-radius:999px;
  padding:10px 15px;font-size:.86rem;font-family:inherit;font-weight:600;cursor:pointer;
  min-height:44px}
.chip:active{background:var(--lav-soft)}
.nextstep{margin:12px 0 4px;padding:12px 14px;border-radius:11px;
  background:var(--lav-soft);border:1px solid #DDD7EE;color:var(--deep);
  font-size:.96rem;line-height:1.5;font-weight:500}
.row{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
.btn{padding:14px 20px;border:0;border-radius:10px;background:var(--deep);color:#fff;
     font-weight:600;font-size:.95rem;text-decoration:none;display:inline-flex;
     align-items:center;justify-content:center;min-height:48px}
.btn.ghost{background:var(--card);color:var(--deep);border:1px solid var(--lav)}
select,input[type=date],textarea,input[type=text]{border:1px solid var(--line);border-radius:9px;
     padding:14px 13px;font-size:1rem;font-family:inherit;background:var(--card);color:var(--ink);
     min-height:48px}
textarea{width:100%;min-height:70px;resize:vertical}
textarea:focus,select:focus,input:focus{outline:none;border-color:var(--lav);
     box-shadow:0 0 0 3px var(--lav-soft)}
.msg{font-size:.92rem;color:var(--mid);background:var(--paper);border-radius:10px;
     padding:11px 12px;white-space:pre-wrap;margin:9px 0;border:1px solid var(--line)}
.timeline{list-style:none;margin:10px 0 0;padding:0}
.timeline li{border-left:2px solid var(--line);padding:0 0 12px 13px;position:relative}
.timeline li::before{content:"";position:absolute;left:-5px;top:5px;width:8px;height:8px;
     border-radius:50%;background:var(--lav)}
.timeline .when{font-size:.72rem;color:var(--soft)}
.timeline .what{font-size:.92rem;color:var(--mid);white-space:pre-wrap}
.ev-icon{display:inline-block;width:1.3em;color:var(--purple);font-weight:600}
.brief{margin-top:14px;padding:13px 14px;border-radius:11px;max-height:9.5em;overflow:auto;
  -webkit-overflow-scrolling:touch;
  background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.2);
  font-size:.95rem;line-height:1.55;color:rgba(255,255,255,.94)}
.brief::before{content:"Today";display:block;font-size:.66rem;letter-spacing:.2em;
  text-transform:uppercase;color:rgba(255,255,255,.66);margin-bottom:6px}
footer.credit{text-align:center;padding:26px 16px 34px;font-size:.8rem;color:var(--soft);
  letter-spacing:.02em}
footer.credit b{font-weight:600;color:var(--mid)}
.signin-wrap{position:relative;min-height:100vh;display:flex;align-items:center;
  justify-content:center;padding:24px;overflow:hidden;background:#2A2440}
.signin-photo{position:absolute;inset:0;background-image:url('https://cdn.prod.website-files.com/62e1efa2754a35fc7aa455a9/6aa8b14c4402034b6c3745df_melody-vachal-speaking.jpg');
  background-size:cover;background-position:56% 6%;filter:saturate(.95) contrast(1.03)}
.signin-veil{position:absolute;inset:0;
  background:linear-gradient(170deg,
      rgba(42,36,64,.46) 0%,
      rgba(58,50,92,.42) 26%,
      rgba(70,63,120,.72) 52%,
      rgba(26,22,40,.94) 100%)}
#signin-canvas{position:absolute;inset:0;width:100%;height:100%;display:block;
  pointer-events:none;opacity:0;transition:opacity 1.2s ease}
#signin-canvas.on{opacity:.55}
.signin{position:relative;z-index:2;width:100%;max-width:400px;margin-top:9vh}
.signin .mark{display:flex;align-items:center;gap:12px;margin-bottom:24px}
.signin-logo{width:74px;height:74px;object-fit:contain;flex:none;display:block;padding:12px;
  border-radius:50%;margin:-8px -6px -8px -10px;
  background:radial-gradient(circle,rgba(255,255,255,.95) 0%,rgba(255,255,255,.86) 36%,
             rgba(255,255,255,.3) 58%,rgba(255,255,255,0) 72%)}
.signin .mark .name{font-weight:700;font-size:1.08rem;letter-spacing:-.01em;line-height:1.2;color:#fff}
.signin .mark .role{font-size:.84rem;color:rgba(255,255,255,.72);line-height:1.35}
.signin .card{background:rgba(255,255,255,.96);border:1px solid rgba(255,255,255,.5);
  border-radius:20px;padding:26px 24px 24px;
  box-shadow:0 34px 70px -30px rgba(12,9,22,.75);
  -webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px)}
.signin h1{margin:0 0 6px;font-size:1.3rem;font-weight:700;letter-spacing:-.015em}
.signin .lede{margin:0 0 20px;font-size:.95rem;color:var(--mid);line-height:1.5}
.signin label{display:block;font-size:.78rem;font-weight:600;letter-spacing:.09em;
  text-transform:uppercase;color:var(--soft);margin-bottom:7px}
.signin input{width:100%;padding:15px 14px;border:1px solid var(--line);border-radius:11px;
  font-size:1.05rem;background:var(--paper);min-height:52px;font-family:inherit}
.signin input:focus{outline:none;border-color:var(--lav);box-shadow:0 0 0 4px var(--lav-soft);
  background:#fff}
.signin button{width:100%;margin-top:16px;padding:15px;border:0;border-radius:11px;
  background:var(--purple);color:#fff;font-weight:600;font-size:1rem;min-height:52px;
  font-family:inherit;cursor:pointer}
.signin button:active{filter:brightness(.93)}
.signin .foot{margin-top:18px;font-size:.82rem;color:rgba(255,255,255,.72);
  text-align:center;line-height:1.5}
@media (prefers-reduced-motion: reduce){#signin-canvas{display:none}}
.err{color:#9A5A48;font-size:.84rem;margin-bottom:9px}

.quick{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.quick form{margin:0}
.quick button{border:1px solid var(--line);background:var(--paper);color:var(--mid);
  border-radius:999px;padding:12px 18px;font-size:.92rem;font-family:inherit;cursor:pointer;
  min-height:44px}
.quick button:active{background:var(--lav-soft);border-color:var(--lav)}
.quick button.muted{color:var(--soft)}
.lead{transition:border-color .12s ease,background .12s ease}
.lead:active{background:#FCFAF7}
.btn,.tab,.search button,.bulkbar button{transition:filter .12s ease}
.btn:active,.search button:active,.bulkbar button:active{filter:brightness(.93)}
@media (prefers-reduced-motion: reduce){*{transition:none !important}}
`;

const layout = (title, body) => `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Every enquiry from melodyvachal.com in one place — spam filed on its own, replies drafted, nothing waiting that you cannot see.">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Melody Vachal">
<meta property="og:title" content="Melody Vachal — enquiries &amp; follow-ups">
<meta property="og:description" content="Every enquiry in one place. Spam filed on its own. Replies drafted for you.">
<meta property="og:url" content="https://leads.melodyvachal.com/">
<meta property="og:image" content="https://leads.melodyvachal.com/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Melody Vachal — every enquiry, in one place">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Melody Vachal — enquiries &amp; follow-ups">
<meta name="twitter:description" content="Every enquiry in one place. Spam filed on its own. Replies drafted for you.">
<meta name="twitter:image" content="https://leads.melodyvachal.com/og.png">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='9' fill='%237670B3'/%3E%3Cpath d='M9 22V10l7 7 7-7v12' fill='none' stroke='%23fff' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<title>${esc(title)}</title>
<style>${CSS}</style></head><body>${body}
<footer class="credit">Custom CRM by <b>Activate</b></footer>
</body></html>`;

/* ---------------------------------------------------------------- login */

app.get('/login', (req, res) => res.send(layout('Sign in', `
  <div class="signin-wrap">
    <div class="signin-photo"></div>
    <div class="signin-veil"></div>
    <canvas id="signin-canvas"></canvas>
    <div class="signin">
      <div class="mark">
        <img class="signin-logo" src="https://cdn.prod.website-files.com/62e1efa2754a35fc7aa455a9/67185ab06bdef51e5ff2b7ab_3-Color%20MV%20Bird.png" alt="Melody Vachal">
        <div>
          <div class="name">Melody Vachal</div>
          <div class="role">Enquiries &amp; follow-ups</div>
        </div>
      </div>
      <div class="card">
        <h1>Welcome back</h1>
        <p class="lede">Everything that came in through melodyvachal.com, in one place.</p>
        ${req.query.bad ? '<div class="err">That password did not work. Try again.</div>' : ''}
        <form method="post" action="/login">
          <label for="pw">Password</label>
          <input id="pw" type="password" name="password" autofocus autocomplete="current-password">
          <button type="submit">Sign in</button>
        </form>
      </div>
      <p class="foot">Spam is filed separately, so this list stays worth reading.</p>
    </div>
  </div>
  <script>
  // Loaded after the form is usable, so signing in is never delayed.
  (function(){
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) return;
    if (navigator.connection && navigator.connection.saveData) return;
    var canvas = document.getElementById('signin-canvas');
    if (!canvas) return;

    function start(){
      if (typeof THREE === 'undefined') return;
      var w = canvas.clientWidth, h = canvas.clientHeight;
      var renderer;
      try {
        renderer = new THREE.WebGLRenderer({ canvas: canvas, alpha: true, antialias: true });
      } catch (e) { return; }
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.setSize(w, h, false);

      var scene = new THREE.Scene();
      var camera = new THREE.PerspectiveCamera(60, w / h, 0.1, 100);
      camera.position.z = 16;

      // A drifting flock: each mote wanders its own path, shimmers on its own
      // wingbeat, and carries one of the colours from her hummingbird.
      var COUNT = 260;
      var pos   = new Float32Array(COUNT * 3);
      var col   = new Float32Array(COUNT * 3);
      var size  = new Float32Array(COUNT);
      var seed  = new Float32Array(COUNT);
      var rise  = new Float32Array(COUNT);
      var sway  = new Float32Array(COUNT);
      var beat  = new Float32Array(COUNT);
      var baseX = new Float32Array(COUNT);

      var HUES = [[0.78,0.77,0.89],[0.45,0.76,0.74],[0.88,0.62,0.66]];

      for (var i = 0; i < COUNT; i++) {
        baseX[i]     = (Math.random() - 0.5) * 36;
        pos[i*3]     = baseX[i];
        pos[i*3 + 1] = (Math.random() - 0.5) * 26;
        pos[i*3 + 2] = (Math.random() - 0.5) * 16;
        var c = HUES[(Math.random() * HUES.length) | 0];
        col[i*3] = c[0]; col[i*3+1] = c[1]; col[i*3+2] = c[2];
        size[i] = 0.07 + Math.random() * 0.20;
        seed[i] = Math.random() * Math.PI * 2;
        rise[i] = 0.05 + Math.random() * 0.20;
        sway[i] = 0.5 + Math.random() * 1.6;
        beat[i] = 5 + Math.random() * 9;
      }

      var geo = new THREE.BufferGeometry();
      geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
      geo.setAttribute('customColor', new THREE.BufferAttribute(col, 3));
      geo.setAttribute('customSize', new THREE.BufferAttribute(size, 1));
      geo.setAttribute('alpha', new THREE.BufferAttribute(new Float32Array(COUNT), 1));

      var mat = new THREE.ShaderMaterial({
        transparent: true, depthWrite: false, blending: THREE.AdditiveBlending,
        uniforms: { uScale: { value: h * 0.5 } },
        vertexShader: [
          'attribute vec3 customColor;',
          'attribute float customSize;',
          'attribute float alpha;',
          'uniform float uScale;',
          'varying vec3 vColor;',
          'varying float vAlpha;',
          'void main(){',
          '  vColor = customColor; vAlpha = alpha;',
          '  vec4 mv = modelViewMatrix * vec4(position, 1.0);',
          '  gl_PointSize = customSize * (uScale / -mv.z);',
          '  gl_Position = projectionMatrix * mv;',
          '}'
        ].join(String.fromCharCode(10)),
        fragmentShader: [
          'varying vec3 vColor;',
          'varying float vAlpha;',
          'void main(){',
          '  vec2 d = gl_PointCoord - vec2(0.5);',
          '  float r = length(d);',
          '  if (r > 0.5) discard;',
          '  float soft = smoothstep(0.5, 0.06, r);',
          '  gl_FragColor = vec4(vColor, soft * vAlpha);',
          '}'
        ].join(String.fromCharCode(10))
      });

      var points = new THREE.Points(geo, mat);
      scene.add(points);

      var tiltX = 0, tiltY = 0, aimX = 0, aimY = 0;
      function aim(e){
        var t = (e.touches && e.touches[0]) || e;
        if (t.clientX == null) return;
        aimX = (t.clientX / window.innerWidth - 0.5) * 2;
        aimY = (t.clientY / window.innerHeight - 0.5) * 2;
      }
      window.addEventListener('mousemove', aim, { passive: true });
      window.addEventListener('touchmove', aim, { passive: true });

      var t0 = performance.now();
      var raf, running = true;
      function frame(){
        if (!running) return;
        var t = (performance.now() - t0) / 1000;
        var p = geo.attributes.position.array;
        var a = geo.attributes.alpha.array;
        for (var i = 0; i < COUNT; i++) {
          p[i*3 + 1] += rise[i] * 0.014;
          if (p[i*3 + 1] > 13) { p[i*3 + 1] = -13; baseX[i] = (Math.random() - 0.5) * 36; }
          p[i*3] = baseX[i] + Math.sin(t * 0.5 + seed[i]) * sway[i];
          a[i] = 0.45 + 0.55 * (0.5 + 0.5 * Math.sin(t * beat[i] + seed[i]));
        }
        geo.attributes.position.needsUpdate = true;
        geo.attributes.alpha.needsUpdate = true;

        tiltX += (aimX * 0.25 - tiltX) * 0.04;
        tiltY += (aimY * 0.18 - tiltY) * 0.04;
        points.rotation.y = tiltX + t * 0.02;
        points.rotation.x = -tiltY;

        renderer.render(scene, camera);
        raf = requestAnimationFrame(frame);
      }

      canvas.classList.add('on');
      frame();

      window.addEventListener('resize', function(){
        var nw = canvas.clientWidth, nh = canvas.clientHeight;
        camera.aspect = nw / nh; camera.updateProjectionMatrix();
        renderer.setSize(nw, nh, false);
        mat.uniforms.uScale.value = nh * 0.5;
      });
      document.addEventListener('visibilitychange', function(){
        running = !document.hidden;
        if (running) frame(); else cancelAnimationFrame(raf);
      });
    }

    function load(){
      var sc = document.createElement('script');
      sc.src = 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js';
      sc.async = true;
      sc.onload = start;
      document.body.appendChild(sc);
    }
    if (document.readyState === 'complete') load();
    else window.addEventListener('load', load);
  })();
  </script>`)));

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
  // Default to whichever view actually has something in it, so she never lands on an empty screen.
  let defaultView = 'due';
  if (!req.query.view) {
    try {
      const d = await pool.query(`
        SELECT count(*) FILTER (WHERE NOT is_spam AND status NOT IN ('booked','cold')
                 AND next_follow_up IS NOT NULL AND next_follow_up <= CURRENT_DATE)::int AS due,
               count(*) FILTER (WHERE NOT is_spam AND status='new')::int AS fresh,
               count(*) FILTER (WHERE NOT is_spam)::int AS any
          FROM leads`);
      const r = d.rows[0];
      defaultView = r.due > 0 ? 'due' : (r.fresh > 0 ? 'new' : (r.any > 0 ? 'all' : 'due'));
    } catch (e) { console.error('default view check failed', e); }
  }
  const view = (req.query.view || defaultView).toLowerCase();
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
  const PAGE = 50;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const offset = (page - 1) * PAGE;

  const totalQ = await pool.query(
    `SELECT count(*)::int AS n FROM leads WHERE ${where.join(' AND ')}`, params);
  const total = totalQ.rows[0].n;

  const { rows } = await pool.query(
    `SELECT l.*,
            (SELECT count(*)::int FROM leads o
              WHERE o.email IS NOT NULL AND o.email = l.email) AS submissions
       FROM leads l WHERE ${where.join(' AND ')}
      ORDER BY ${order} LIMIT ${PAGE} OFFSET ${offset}`, params);

  const c = await pool.query(`
    SELECT
      count(*) FILTER (WHERE NOT is_spam AND status='new')       AS c_new,
      count(*) FILTER (WHERE NOT is_spam AND status='contacted') AS c_contacted,
      count(*) FILTER (WHERE NOT is_spam AND status='booked')    AS c_booked,
      COALESCE(sum(fee) FILTER (WHERE NOT is_spam AND status='booked'), 0)::numeric AS v_booked,
      COALESCE(sum(fee) FILTER (WHERE NOT is_spam AND status NOT IN ('booked','cold','spam')), 0)::numeric AS v_pipeline,
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

  const brief = (!req.query.view && page === 1) ? await todaysBrief() : null;

  let upcoming = [];
  if (page === 1) {
    try {
      const u = await pool.query(
        `SELECT * FROM engagements
          WHERE starts_at IS NULL OR starts_at >= now() - interval '12 hours'
          ORDER BY starts_at ASC NULLS LAST LIMIT 3`);
      upcoming = u.rows;
    } catch (e) { console.error('engagements read failed', e); }
  }

  const hour = new Date().getHours();
  const greeting = hour < 12 ? 'Good morning' : hour < 17 ? 'Good afternoon' : 'Good evening';
  const due = Number(n.c_due), fresh = Number(n.c_new);
  const headline = due > 0
    ? (due === 1 ? 'One follow-up is due.' : due + ' follow-ups are due.')
    : fresh > 0
      ? (fresh === 1 ? 'One new enquiry to read.' : fresh + ' new enquiries to read.')
      : (Number(n.c_all) > 0 ? 'Nothing needs you right now.' : 'Nothing has come in yet.');
  const subline = due > 0
    ? 'Oldest first, so the ones waiting longest come up top.'
    : fresh > 0
      ? 'Nothing overdue — these came in since you last looked.'
      : (Number(n.c_all) > 0
          ? 'Everything is answered, booked or waiting on them. Use the tabs to look back over any of it.'
          : 'When someone fills in a form on your website, it appears here.');

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
          ${l.source === 'email' ? '<span class="pill">by email</span>' : ''}
          ${l.is_spam ? `<span class="pill spam">${esc(l.spam_reason || 'spam')}</span>` : ''}
          ${overdue ? `<span class="pill due">follow up</span>` : ''}
          ${l.submissions > 1 ? `<span class="pill">${l.submissions}\u00d7</span>` : ''}
          ${l.fee != null ? `<span class="pill good">$${Number(l.fee).toLocaleString('en-US',{maximumFractionDigits:0})}</span>` : ''}
        </div>
        <p class="who"><a href="/lead/${l.id}">${esc(l.name || l.email || 'No name')}</a></p>
        <div class="meta">${esc(l.organization || '')}${l.email ? ' &middot; ' + esc(l.email) : ''}</div>
        ${l.message ? `<div class="snip">${esc(String(l.message).slice(0, 160))}</div>` : ''}
        ${l.is_spam ? `<div class="quick">
          <form method="post" action="/lead/${l.id}/quick"><input type="hidden" name="to" value="new">
            <input type="hidden" name="back" value="${esc(view)}"><button type="submit">Not spam</button></form>
          <form method="post" action="/lead/${l.id}/delete"
                onsubmit="return confirm('Delete this permanently?')">
            <input type="hidden" name="back" value="${esc(view)}">
            <button type="submit" class="muted">Delete</button></form>
        </div>` : `<div class="quick">
          <form method="post" action="/lead/${l.id}/snooze"><input type="hidden" name="days" value="1">
            <input type="hidden" name="back" value="${esc(view)}"><button type="submit">Tomorrow</button></form>
          <form method="post" action="/lead/${l.id}/snooze"><input type="hidden" name="days" value="7">
            <input type="hidden" name="back" value="${esc(view)}"><button type="submit">Next week</button></form>
          <form method="post" action="/lead/${l.id}/quick"><input type="hidden" name="to" value="contacted">
            <input type="hidden" name="back" value="${esc(view)}"><button type="submit">Contacted</button></form>
          <form method="post" action="/lead/${l.id}/quick"><input type="hidden" name="to" value="spam">
            <input type="hidden" name="back" value="${esc(view)}"><button type="submit" class="muted">Spam</button></form>
        </div>`}
      </div></div>`;
  }).join('') : `<div class="empty">${
      view === 'due'       ? 'Nothing is due today. Anything you saved for later appears here on the day.'
    : view === 'new'       ? 'No unread enquiries. Ones you have answered are under Contacted.'
    : view === 'contacted' ? 'Enquiries you have replied to will be listed here.'
    : view === 'booked'    ? 'No confirmed bookings recorded yet.'
    : view === 'spam'      ? 'Nothing has been filed as spam.'
    : view === 'all'       ? 'No enquiries yet. They appear here as they come in.'
    : 'Nothing under this heading yet.'}</div>`;

  res.send(layout('Leads', `
    <header><h1><img class="hdr-logo" src="https://cdn.prod.website-files.com/62e1efa2754a35fc7aa455a9/67185ab06bdef51e5ff2b7ab_3-Color%20MV%20Bird.png" alt="">Melody</h1>
      <span class="hdr-nav"><a href="/events">Events</a><a href="/requests">Requests</a>
      <a href="/logout">Sign out</a></span></header>
    <div class="wrap">
      <div class="summary">
        <div class="hello">${esc(greeting)}</div>
        <p class="line">${esc(headline)}</p>
        <div class="sub">${esc(subline)}</div>
        ${brief ? `<div class="brief">${esc(brief)}</div>` : ''}
        <div class="stats">
          <div class="stat"><b data-to="${n.c_due}">0</b><span>Due</span></div>
          <div class="stat"><b data-to="${n.c_new}">0</b><span>New</span></div>
          <div class="stat"><b data-to="${n.c_booked}">0</b><span>Booked</span></div>
          ${Number(n.v_booked) > 0 || Number(n.v_pipeline) > 0 ? `
          <div class="stat"><b data-money="${Number(n.v_booked)}">$0</b><span>Booked $</span></div>` : ''}
        </div>
      </div>
      ${upcoming.length ? `<div class="diary">
        <div class="diary-label">Coming up</div>
        ${upcoming.map(function(u){
          var days = u.starts_at
            ? Math.ceil((new Date(u.starts_at) - Date.now()) / 86400000) : null;
          var when = days === null ? '' :
            days <= 0 ? 'Today' : days === 1 ? 'Tomorrow' : 'In ' + days + ' days';
          return '<div class="diary-row">' +
            '<div class="diary-when">' + esc(when) + '</div>' +
            '<div><div class="diary-name">' + esc(u.name) + '</div>' +
            '<div class="diary-meta">' + esc([u.date_label, u.location].filter(Boolean).join(' \u00b7 ')) + '</div>' +
            (u.notes ? '<div class="diary-meta">' + esc(u.notes) + '</div>' : '') +
            (u.link ? '<a class="diary-link" href="' + esc(u.link) + '" target="_blank" rel="noopener">Details</a>' : '') +
            '</div></div>';
        }).join('')}
      </div>` : ''}
      ${req.query.done ? (function(){
        var act = String(req.query.act || '');
        var who = esc(req.query.who || 'That enquiry');
        var lid = parseInt(req.query.done, 10) || 0;
        var snoozed = act.indexOf('snoozed-') === 0;
        var days = snoozed ? parseInt(act.split('-')[1], 10) : 0;
        var label = snoozed ? (days === 1 ? 'saved for tomorrow' : 'saved for ' + days + ' days time')
          : act === 'contacted' ? 'marked as contacted'
          : act === 'booked'    ? 'marked as booked'
          : act === 'cold'      ? 'set aside'
          : act === 'spam'      ? 'filed as spam'
          : act === 'new'       ? 'put back in New' : 'updated';
        var where = snoozed ? ' It comes back to Due on the day.'
          : ' Still saved \u2014 now under ' + (act === 'spam' ? 'Spam'
              : act.charAt(0).toUpperCase() + act.slice(1)) + '.';
        return '<div class="toast"><div class="toast-text"><b>' + who + '</b> ' + label + '.' +
          where + '</div><div class="toast-acts">' +
          '<a class="toast-btn" href="/lead/' + lid + '">Open it</a>' +
          (req.query.was ? '<form method="post" action="/lead/' + lid + '/undo">' +
            '<input type="hidden" name="to" value="' + esc(req.query.was) + '">' +
            '<input type="hidden" name="back" value="' + esc(view) + '">' +
            '<button class="toast-btn" type="submit">Undo</button></form>' : '') +
          '</div></div>';
      })() : ''}
      <form class="ask" method="post" action="/ask">
        <input name="q" placeholder="Ask about your enquiries\u2026"
               value="" autocomplete="off" aria-label="Ask a question">
        <button type="submit">Ask</button>
      </form>
      ${req.query.answer ? `<div class="answer">
        <div class="answer-q">${esc(req.query.q_asked || '')}</div>
        <div class="answer-a">${esc(req.query.answer)}</div>
        ${req.query.focus ? `<a class="answer-go" href="/?view=${esc(req.query.focus)}&amp;hl=1">Show me \u2192</a>` : ''}
      </div>` : ''}
      <div class="tabs"${req.query.hl ? ' data-highlight="1"' : ''}>${tabs}</div>
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
            <option value="delete">Delete permanently</option>
          </select>
          <button type="submit">Apply</button>
        </div>
      </form>
      <p class="count">${total} total${total > PAGE ? ` \u00b7 page ${page} of ${Math.ceil(total / PAGE)}` : ''}</p>
      ${items}
      ${total > PAGE ? `<div class="row" style="justify-content:space-between">
        ${page > 1 ? `<a class="btn ghost" href="/?view=${esc(view)}&page=${page - 1}${q ? '&q=' + encodeURIComponent(q) : ''}">Newer</a>` : '<span></span>'}
        ${offset + rows.length < total ? `<a class="btn ghost" href="/?view=${esc(view)}&page=${page + 1}${q ? '&q=' + encodeURIComponent(q) : ''}">Older</a>` : '<span></span>'}
      </div>` : ''}
      <div class="row"><a class="btn ghost" href="/export?view=${esc(view)}">Download CSV</a></div>
    </div>
    <script>
    (function(){
      var tabs = document.querySelector('.tabs[data-highlight]');
      if (tabs) {
        var on = tabs.querySelector('.tab.on');
        if (on) {
          on.classList.add('flash');
          on.scrollIntoView({ block: 'nearest', inline: 'center' });
        }
      }
    })();
    (function(){
      var reduce = window.matchMedia &&
                   window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      document.querySelectorAll('.stat b[data-money]').forEach(function(el){
        var v = Number(el.getAttribute('data-money')) || 0;
        el.textContent = '$' + v.toLocaleString('en-US', { maximumFractionDigits: 0 });
      });
      document.querySelectorAll('.stat b[data-to]').forEach(function(el){
        var to = parseInt(el.getAttribute('data-to'), 10) || 0;
        if (reduce || to === 0) { el.textContent = to; return; }
        var start = performance.now(), ms = 420;
        function step(now){
          var p = Math.min((now - start) / ms, 1);
          el.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
          if (p < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
      });
    })();
    </script>
`));
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
  const sent = await pool.query(
    'SELECT * FROM messages WHERE lead_id=$1 ORDER BY sent_at DESC LIMIT 20', [id]);

  const also = l.email
    ? await pool.query(
        'SELECT id, received_at, form_name FROM leads WHERE email=$1 AND id<>$2 ORDER BY received_at DESC',
        [l.email, id])
    : { rows: [] };

  // One sentence telling her what this lead needs from her right now.
  function nextStep(l) {
    const days = l.last_contacted
      ? Math.floor((Date.now() - new Date(l.last_contacted)) / 86400000) : null;
    const due = l.next_follow_up
      ? new Date(l.next_follow_up).toISOString().slice(0, 10) : null;
    const today = new Date().toISOString().slice(0, 10);

    if (l.is_spam) return 'Filed as spam' + (l.spam_reason ? ' (' + l.spam_reason + ')' : '') +
                           '. If that is wrong, change the status below.';
    if (l.status === 'booked') return 'Booked. Nothing needed unless plans change.';
    if (l.status === 'cold')   return 'Set aside. Change the status if it comes back to life.';
    if (l.status === 'new') {
      if (l.tag === 'speaking')
        return 'A speaking enquiry waiting on a first reply' +
               (l.event_date ? ' \u2014 they mentioned ' + l.event_date : '') + '.';
      if (l.tag === 'guide') return 'Signed up for the guide. It was sent automatically \u2014 no reply needed unless you want to.';
      return 'Waiting on a first reply from you.';
    }
    if (l.status === 'contacted') {
      if (due && due <= today) return 'You said you would come back to this today.';
      if (due) return 'You are due to follow up on ' + due + '.';
      if (days !== null && days >= 5) return 'You replied ' + days + ' days ago with no answer. Worth a nudge.';
      if (days !== null) return 'You replied ' + (days === 0 ? 'today' : days + ' days ago') + '. Give them a little time.';
      return 'Marked contacted. Set a follow-up date so it does not go quiet.';
    }
    return 'Choose a status below so this does not get lost.';
  }

  const statusOpts = STATUSES.map(s =>
    `<option value="${s}" ${s === l.status ? 'selected' : ''}>${s}</option>`).join('');
  const tagOpts = TAGS.map(t =>
    `<option value="${t}" ${t === l.tag ? 'selected' : ''}>${t}</option>`).join('');

  // Each event says plainly what happened and, where it matters, what it means now.
  function describe(e) {
    var b = e.body || '';
    switch (e.kind) {
      case 'received':   return { icon: '\u2709', line: 'Enquiry arrived ' + b.replace(/^via /, 'through the ') };
      case 'draft':      return { icon: '\u270E', line: b ? b.charAt(0).toUpperCase() + b.slice(1) : 'A reply was drafted for you to review' };
      case 'revise':     return { icon: '\u2726', line: 'Draft ' + b };
      case 'undo':       return { icon: '\u21A9', line: 'Undone \u2014 ' + b };
      case 'sent':       return { icon: '\u2709', line: 'You sent a reply ' + b };
      case 'inbound':    return { icon: '\u21A9', line: b };
      case 'alert':      return { icon: '\u2022', line: b };
      case 'contacted':  return { icon: '\u2192', line: 'You marked this as contacted' };
      case 'status':     return { icon: '\u21BB', line: 'Status changed: ' + b };
      case 'note':       return { icon: '\u201C', line: b };
      case 'snooze':     return { icon: '\u23F1', line: 'Put off \u2014 ' + b };
      case 'quick':      return { icon: '\u2713', line: 'Marked ' + b + ' from the list' };
      case 'bulk':       return { icon: '\u2713', line: 'Marked ' + b + ' along with others' };
      case 'nudge':      return { icon: '\u26A0', line: 'No reply after five days, so it came back to your queue' };
      default:           return { icon: '\u2022', line: (e.kind + (b ? ': ' + b : '')) };
    }
  }

  const timeline = ev.rows.map(e => {
    const d = describe(e);
    return `<li>
      <div class="when">${new Date(e.at).toLocaleString('en-US',
        { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })}</div>
      <div class="what"><span class="ev-icon">${d.icon}</span>${esc(d.line)}</div></li>`;
  }).join('');

  res.send(layout(l.name || 'Lead', `
    <header><h1><img class="hdr-logo" src="https://cdn.prod.website-files.com/62e1efa2754a35fc7aa455a9/67185ab06bdef51e5ff2b7ab_3-Color%20MV%20Bird.png" alt=""><a href="/" style="color:#fff;text-decoration:none">&larr; Leads</a></h1>
      <a href="/logout">Sign out</a></header>
    <div class="wrap">
      ${req.query.msg ? `<div class="toast"><div class="toast-text">${esc(req.query.msg)}</div></div>` : ''}
      <div class="card">
        <h2>${esc(l.name || 'No name given')}</h2>
        <div class="meta">${esc(l.organization || '')}</div>
        <div class="meta">Received ${new Date(l.received_at).toLocaleString('en-US',
          { month: 'long', day: 'numeric', hour: 'numeric', minute: '2-digit' })}
          via ${esc(l.form_name || 'form')}</div>
        <div class="nextstep">${esc(nextStep(l))}</div>
        ${l.intent ? `<div class="meta" style="margin-top:6px"><span class="pill">${esc(l.urgency || 'normal')}</span> ${esc(l.intent)}</div>` : ''}
        ${(l.event_date || l.audience) ? `<div class="meta">${l.event_date ? 'Date mentioned: ' + esc(l.event_date) : ''}${(l.event_date && l.audience) ? ' &middot; ' : ''}${l.audience ? 'Audience: ' + esc(l.audience) : ''}</div>` : ''}
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
        <div class="meta">Reply${l.draft_reply ? '' : ' &mdash; nothing drafted yet'}</div>

        <form method="post" action="/lead/${l.id}/draft" class="row">
          <button class="btn ghost" type="submit" name="kind" value="reply">
            ${l.draft_reply ? 'Rewrite from scratch' : 'Draft a reply'}</button>
          ${l.last_contacted ? `<button class="btn ghost" type="submit" name="kind" value="followup">Draft a follow-up</button>` : ''}
        </form>

        ${l.draft_reply ? `
        <form method="post" action="/lead/${l.id}/draft-save">
          <div class="row"><input type="text" name="subject" style="flex:1;min-width:14em"
            value="Re: your enquiry" placeholder="Subject"></div>
          <textarea name="draft" id="draft" class="draft-box" spellcheck="true"
            autocapitalize="sentences" autocorrect="on">${esc(l.draft_reply)}</textarea>
          <div class="revise-label">Revise</div>
          <div class="revise">
            <button class="chip" type="submit" formaction="/lead/${l.id}/revise" name="mode" value="shorter">Shorter</button>
            <button class="chip" type="submit" formaction="/lead/${l.id}/revise" name="mode" value="warmer">Warmer</button>
            <button class="chip" type="submit" formaction="/lead/${l.id}/revise" name="mode" value="direct">More direct</button>
            <button class="chip" type="submit" formaction="/lead/${l.id}/revise" name="mode" value="grammar">Fix spelling</button>
          </div>
          <div class="row">
            <button class="btn" type="submit" formaction="/lead/${l.id}/send"
              onclick="return confirm('Send this to ${esc(l.email || 'them')}?')">Send it</button>
            <button class="btn ghost" type="submit">Save draft</button>
            <a class="btn ghost" href="mailto:${esc(l.email || '')}?subject=${encodeURIComponent('Re: your enquiry')}&body=${encodeURIComponent(l.draft_reply)}">Open in email</a>
            <button class="btn ghost" type="button"
              onclick="navigator.clipboard.writeText(document.getElementById('draft').value);this.textContent='Copied'">Copy</button>
          </div>
        </form>` : ''}
      </div>

      <div class="card">
        <form method="post" action="/lead/${l.id}">
          <div class="row">
            <select name="status">${statusOpts}</select>
            <select name="tag">${tagOpts}</select>
            <input type="date" name="next_follow_up"
              value="${l.next_follow_up ? new Date(l.next_follow_up).toISOString().slice(0,10) : ''}">
            <input type="text" name="fee" inputmode="decimal" placeholder="Fee $"
              value="${l.fee != null ? esc(l.fee) : ''}" style="max-width:9em">
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

      ${sent.rows.length ? `<div class="card">
        <div class="meta">The conversation</div>
        ${sent.rows.map(m => `<div style="padding:11px 0;border-top:1px solid var(--line)">
          <div class="meta">${new Date(m.sent_at).toLocaleString('en-US',
            { month:'short', day:'numeric', hour:'numeric', minute:'2-digit' })}
            &middot; ${m.direction === 'in' ? 'from ' + esc(m.from_email || '')
                                            : 'you \u2192 ' + esc(m.to_email)}
            ${m.subject ? '&middot; ' + esc(m.subject) : ''}</div>
          <div class="msg" style="margin-top:6px">${esc(m.body)}</div>
        </div>`).join('')}
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
  const feeRaw = (req.body.fee || '').toString().replace(/[^0-9.]/g, '');
  const fee = feeRaw ? Number(feeRaw) : null;
  const s = STATUSES.includes(status) ? status : 'new';

  const before = await pool.query('SELECT status FROM leads WHERE id=$1', [id]);

  await pool.query(
    `UPDATE leads SET status=$1, tag=$2, next_follow_up=NULLIF($3,'')::date,
       fee=$4, is_spam=($1='spam'), updated_at=now() WHERE id=$5`,
    [s, TAGS.includes(tag) ? tag : 'general', next_follow_up || '', fee, id]);

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
    } else if (action === 'delete') {
      await pool.query('DELETE FROM leads WHERE id = ANY($1)', [ids]);
      return res.redirect('/?view=' + encodeURIComponent(back));
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

app.post('/lead/:id/draft', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  const { rows } = await pool.query('SELECT * FROM leads WHERE id=$1', [id]);
  if (!rows.length) return res.status(404).send('not found');
  const kind = req.body.kind === 'followup' ? 'followup' : 'reply';
  const draft = kind === 'followup' ? await aiDraftFollowUp(rows[0]) : await aiDraftReply(rows[0]);
  if (draft) {
    await pool.query('UPDATE leads SET draft_reply=$1 WHERE id=$2', [draft, id]);
    await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'draft',$2)`,
      [id, kind === 'followup' ? 'follow-up drafted' : 'reply drafted']);
  }
  res.redirect('/lead/' + id);
});

app.post('/lead/:id/draft-save', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  await pool.query('UPDATE leads SET draft_reply=$1, updated_at=now() WHERE id=$2',
    [req.body.draft || '', id]);
  await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'draft','you edited the draft')`, [id]);
  res.redirect('/lead/' + id);
});

app.post('/lead/:id/revise', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  const text = req.body.draft || '';
  const mode = req.body.mode;
  if (!text.trim()) return res.redirect('/lead/' + id);

  // Keep whatever she typed, even if the model is unavailable.
  await pool.query('UPDATE leads SET draft_reply=$1 WHERE id=$2', [text, id]);

  const { rows } = await pool.query('SELECT * FROM leads WHERE id=$1', [id]);
  const revised = rows.length ? await aiRevise(text, mode, rows[0]) : null;
  if (revised) {
    await pool.query('UPDATE leads SET draft_reply=$1, updated_at=now() WHERE id=$2', [revised, id]);
    const label = { shorter:'made shorter', warmer:'made warmer',
                    direct:'made more direct', grammar:'spelling and grammar fixed' }[mode] || mode;
    await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'revise',$2)`, [id, label]);
  }
  res.redirect('/lead/' + id);
});

// Nudge sweep: anything contacted 5+ days ago with no follow-up date gets one set for today,
// so it surfaces in Due rather than going quiet.
async function nudgeSweep() {
  try {
    const r = await pool.query(`
      UPDATE leads SET next_follow_up = CURRENT_DATE, updated_at = now()
      WHERE is_spam = false AND status = 'contacted'
        AND next_follow_up IS NULL
        AND last_contacted IS NOT NULL
        AND last_contacted < now() - interval '5 days'
      RETURNING id`);
    for (const row of r.rows)
      await pool.query(`INSERT INTO lead_events (lead_id,kind,body)
                        VALUES ($1,'nudge','no reply in 5 days - surfaced for follow-up')`, [row.id]);
    if (r.rows.length) console.log('nudged', r.rows.length);
  } catch (e) { console.error('nudge sweep failed', e); }
}
setInterval(nudgeSweep, 6 * 60 * 60 * 1000);
setTimeout(nudgeSweep, 60 * 1000);

app.post('/lead/:id/snooze', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const days = Math.min(90, Math.max(1, parseInt(req.body.days, 10) || 1));
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  await pool.query(
    `UPDATE leads SET next_follow_up = CURRENT_DATE + $1::int, updated_at = now() WHERE id = $2`,
    [days, id]);
  await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'snooze',$2)`,
    [id, 'follow up in ' + days + ' day' + (days === 1 ? '' : 's')]);
  const nmQ = await pool.query('SELECT name,email FROM leads WHERE id=$1', [id]);
  const whoS = nmQ.rows.length ? (nmQ.rows[0].name || nmQ.rows[0].email || 'That enquiry') : 'That enquiry';
  res.redirect('/?' + new URLSearchParams({ view: req.body.back || 'due',
    done: String(id), act: 'snoozed-' + days, who: whoS }).toString());
});

app.post('/lead/:id/quick', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const to = req.body.to;
  if (!Number.isInteger(id) || !STATUSES.includes(to)) return res.status(400).send('bad request');
  const prevQ = await pool.query('SELECT status, is_spam, name, email FROM leads WHERE id=$1', [id]);
  if (!prevQ.rows.length) return res.redirect('/');
  const was = prevQ.rows[0].is_spam ? 'spam' : prevQ.rows[0].status;
  const who = prevQ.rows[0].name || prevQ.rows[0].email || 'That enquiry';
  if (to === 'spam') {
    await pool.query(`UPDATE leads SET is_spam=true, status='spam',
      spam_reason='marked by hand', updated_at=now() WHERE id=$1`, [id]);
  } else {
    await pool.query(`UPDATE leads SET status=$1, is_spam=false,
      last_contacted=CASE WHEN $1='contacted' THEN now() ELSE last_contacted END,
      updated_at=now() WHERE id=$2`, [to, id]);
  }
  await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'quick',$2)`, [id, to]);
  res.redirect('/?' + new URLSearchParams({ view: req.body.back || 'due',
    done: String(id), act: to, was: was, who: who }).toString());
});

app.post('/brief/refresh', requireAuth, async (req, res) => {
  const day = new Date().toISOString().slice(0, 10);
  await pool.query('DELETE FROM briefs WHERE day = $1', [day]);
  await todaysBrief();
  res.redirect('/?view=due');
});

app.get('/export', requireAuth, async (req, res) => {
  const view = (req.query.view || 'all').toLowerCase();
  const clause = view === 'spam' ? 'is_spam = true' : 'is_spam = false';
  const { rows } = await pool.query(
    `SELECT received_at,name,email,phone,organization,form_name,tag,status,intent,
            event_date,audience,urgency,fee,next_follow_up,last_contacted,message
       FROM leads WHERE ${clause} ORDER BY received_at DESC`);

  const cell = v => {
    if (v == null) return '';
    const s = String(v).replace(/"/g, '""');
    return /[",\n]/.test(s) ? '"' + s + '"' : s;
  };
  const head = ['Received','Name','Email','Phone','Organisation','Form','Tag','Status',
                'Intent','Event date','Audience','Urgency','Fee','Next follow-up','Last contacted','Message'];
  const body = rows.map(r => [
    r.received_at ? new Date(r.received_at).toISOString() : '',
    r.name, r.email, r.phone, r.organization, r.form_name, r.tag, r.status, r.intent,
    r.event_date, r.audience, r.urgency, r.fee,
    r.next_follow_up ? new Date(r.next_follow_up).toISOString().slice(0,10) : '',
    r.last_contacted ? new Date(r.last_contacted).toISOString() : '',
    r.message
  ].map(cell).join(','));

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition',
    'attachment; filename="melody-leads-' + new Date().toISOString().slice(0,10) + '.csv"');
  res.send('\ufeff' + [head.join(','), ...body].join(String.fromCharCode(10)));
});

// Keeps the CRM's engagement list in step with the site's Events collection.
app.post('/engagements/sync', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) return res.status(401).json({ ok:false });
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  let n = 0;
  for (const it of items) {
    if (!it.id || !it.name) continue;
    await pool.query(
      `INSERT INTO engagements (id,name,starts_at,date_label,location,link,notes,updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,now())
       ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, starts_at=EXCLUDED.starts_at,
         date_label=EXCLUDED.date_label, location=EXCLUDED.location, link=EXCLUDED.link,
         notes=EXCLUDED.notes, updated_at=now()`,
      [it.id, it.name, it.starts_at || null, it.date_label || null,
       it.location || null, it.link || null, it.notes || null]);
    n++;
  }
  res.json({ ok: true, synced: n });
});

app.post('/lead/:id/delete', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  await pool.query('DELETE FROM leads WHERE id=$1', [id]);   // events cascade
  res.redirect('/?view=' + encodeURIComponent(req.body.back || 'all'));
});

app.post('/ask', requireAuth, async (req, res) => {
  const q = (req.body.q || '').toString().trim().slice(0, 500);
  if (!q) return res.redirect('/');
  const out = await aiAsk(q);
  const params = new URLSearchParams();
  params.set('q_asked', q);
  params.set('answer', out && out.answer ? out.answer :
    'I could not answer that from what is in here.');
  if (out && out.view) params.set('focus', out.view);
  res.redirect('/?' + params.toString());
});

app.post('/lead/:id/undo', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const to = req.body.to;
  if (!Number.isInteger(id) || !STATUSES.includes(to)) return res.status(400).send('bad request');
  await pool.query(`UPDATE leads SET status=$1, is_spam=($1='spam'), updated_at=now() WHERE id=$2`, [to, id]);
  await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'undo',$2)`,
    [id, 'put back to ' + to]);
  res.redirect('/?view=' + encodeURIComponent(req.body.back || 'due'));
});

// Bulk import of historical Webflow submissions. Deterministic triage only:
// no model calls, so importing thousands of rows stays fast and cheap.
function looksMachineGenerated(name) {
  if (!name) return false;
  const n = String(name).trim();
  if (!n) return false;
  if (n.indexOf(' ') !== -1) return false;          // a first and last name reads as human
  if (!/^[A-Za-z0-9]{3,16}$/.test(n)) return false; // anything with punctuation is left alone

  const hasUpper = /[A-Z]/.test(n), hasLower = /[a-z]/.test(n), hasDigit = /[0-9]/.test(n);
  const vowels = (n.match(/[aeiouAEIOU]/g) || []).length;
  const letters = (n.match(/[A-Za-z]/g) || []).length;

  if (hasDigit && letters >= 3) return true;                 // Kj3nP8qR
  if (hasUpper && hasLower && n.length >= 7) return true;    // 7IuQXJlJLB
  if (n.length >= 6 && n === n.toUpperCase()) return true;   // OOGDCRTDTP
  if (letters >= 4 && vowels === 0) return true;             // Xqfx, zzkjl
  if (letters >= 5 && vowels / letters < 0.25) return true;  // Dgoiwq, wChZFYT
  if (/[bcdfghjklmnpqrstvwxz]{4,}/i.test(n)) return true;    // four consonants running
  return false;
}

app.post('/import', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) return res.status(401).json({ ok:false });
  const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
  let added = 0, skipped = 0, flagged = 0;

  for (const it of items) {
    const f = it.fields || {};
    const formName = it.form || 'unknown';
    const name  = pick(f, ['name','full name','your name','first name']);
    const email = pick(f, ['email','email address','e mail','email cta']);
    const message = pick(f, ['write about your project','inquiry details','event details','your message','comments','notes','message']);

    // Same submission twice is the same row.
    const dupe = await pool.query(
      `SELECT 1 FROM leads WHERE raw->>'importId' = $1 LIMIT 1`, [String(it.id || '')]);
    if (dupe.rows.length) { skipped++; continue; }

    const t = triage(f, message);
    const machine = looksMachineGenerated(name);
    const spam = t.spam || machine;
    const reason = t.reason || (machine ? 'machine-generated name' : null);
    if (spam) flagged++;

    await pool.query(
      `INSERT INTO leads (received_at,form_name,page_url,name,email,phone,organization,message,
                          raw,is_spam,spam_reason,status,tag)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [it.at || new Date().toISOString(), formName, it.page || null, name, email,
       pick(f, ['phone','phone number','telephone']),
       pick(f, ['organization','organisation','company']), message,
       JSON.stringify({ importId: it.id, source: 'webflow', fields: f }),
       spam, reason, spam ? 'spam' : 'new', inferTag(formName, message)]);
    added++;
  }
  res.json({ ok: true, added, skipped, flagged });
});

// Pulls every historical submission straight from Webflow, pages and all.
const WEBFLOW_TOKEN = process.env.WEBFLOW_TOKEN || '';
const WEBFLOW_SITE  = process.env.WEBFLOW_SITE || '62e1efa2754a35fc7aa455a9';

app.post('/import/webflow', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) return res.status(401).json({ ok:false });
  if (!WEBFLOW_TOKEN) return res.status(400).json({ ok:false, error:'WEBFLOW_TOKEN not set' });

  let offset = 0, added = 0, skipped = 0, flagged = 0, total = null;
  const limit = 100;

  try {
    while (true) {
      const url = 'https://api.webflow.com/v2/sites/' + WEBFLOW_SITE +
                  '/form_submissions?limit=' + limit + '&offset=' + offset;
      const r = await fetch(url, { headers: {
        authorization: 'Bearer ' + WEBFLOW_TOKEN, 'accept-version': '2.0.0' } });
      if (!r.ok) return res.status(502).json({ ok:false, error:'webflow ' + r.status,
                                               detail: (await r.text()).slice(0,200) });
      const d = await r.json();
      const rows = d.formSubmissions || [];
      total = (d.pagination && d.pagination.total) || total;
      if (!rows.length) break;

      for (const sub of rows) {
        const f = sub.formResponse || {};
        const dupe = await pool.query(
          `SELECT 1 FROM leads WHERE raw->>'importId' = $1 LIMIT 1`, [String(sub.id)]);
        if (dupe.rows.length) { skipped++; continue; }

        const name  = pick(f, ['name','full name','your name','first name']);
        const message = pick(f, ['write about your project','inquiry details','event details','your message','comments','notes','message']);
        const t = triage(f, message);
        const machine = looksMachineGenerated(name);
        const guideOnly = /guide|email form/i.test(sub.displayName || '') && !message;
        const spam = t.spam || machine || guideOnly;
        if (spam) flagged++;

        await pool.query(
          `INSERT INTO leads (received_at,form_name,page_url,name,email,phone,organization,message,
                              raw,is_spam,spam_reason,status,tag)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
          [sub.dateSubmitted || new Date().toISOString(),
           sub.displayName || 'unknown', sub.publishedPath || null, name,
           pick(f, ['email','email address','e mail','email cta']),
           pick(f, ['phone','phone number','telephone']),
           pick(f, ['organization','organisation','company']), message,
           JSON.stringify({ importId: sub.id, source: 'webflow', fields: f }),
           spam, t.reason || (machine ? 'machine-generated name'
              : guideOnly ? 'guide signup, nothing to reply to' : null),
           spam ? 'spam' : 'new', inferTag(sub.displayName, message)]);
        added++;
      }
      offset += rows.length;
      if (total && offset >= total) break;
      if (offset > 5000) break;   // guard
    }
    res.json({ ok: true, total, added, skipped, flagged });
  } catch (e) {
    console.error('webflow import failed', e);
    res.status(500).json({ ok:false, error: String(e).slice(0,200), added, skipped });
  }
});

app.post('/retriage', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) return res.status(401).json({ ok:false });
  // Only rows nobody has worked yet — never re-file something she has acted on.
  const { rows } = await pool.query(
    `SELECT id, name, message, raw, form_name FROM leads
      WHERE is_spam = false AND status = 'new' AND last_contacted IS NULL`);
  let moved = 0;
  for (const r of rows) {
    const fields = (r.raw && r.raw.fields) || {};
    const t = triage(fields, r.message);
    const machine = looksMachineGenerated(r.name);
    const noName = !r.name && !r.message;   // a bare email with nothing else
    const guideOnly = /guide|email form/i.test(r.form_name || '') && !r.message;
    if (t.spam || machine || noName || guideOnly) {
      await pool.query(
        `UPDATE leads SET is_spam=true, status='spam', spam_reason=$1, updated_at=now()
          WHERE id=$2`,
        [t.reason || (machine ? 'machine-generated name'
           : guideOnly ? 'guide signup, nothing to reply to' : 'no name and no message'), r.id]);
      moved++;
    }
  }
  res.json({ ok: true, checked: rows.length, moved });
});

const EVENTS_COLLECTION = process.env.EVENTS_COLLECTION || '6a3549a4ba99226385574192';

async function webflow(path, method, body) {
  if (!WEBFLOW_TOKEN) return { ok:false, error:'no token' };
  const r = await fetch('https://api.webflow.com/v2' + path, {
    method: method || 'GET',
    headers: { authorization: 'Bearer ' + WEBFLOW_TOKEN,
               'accept-version': '2.0.0', 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await r.text();
  let data = null; try { data = JSON.parse(text); } catch (e) {}
  return { ok: r.ok, status: r.status, data, text: text.slice(0, 300) };
}

/* ------------------------------------------------- her own events page */

app.get('/events', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM engagements ORDER BY starts_at DESC NULLS LAST');
  const flyerRows = await pool.query(
    'SELECT token, event_id, filename FROM event_files ORDER BY created_at DESC');
  const flyersBy = {};
  for (const f of flyerRows.rows) (flyersBy[f.event_id] ||= []).push(f);
  const today = new Date().toISOString().slice(0,10);
  const card = e => {
    const d = e.starts_at ? new Date(e.starts_at).toISOString().slice(0,10) : '';
    const past = d && d < today;
    return `<div class="card">
      <form method="post" action="/events/save" enctype="multipart/form-data">
        <input type="hidden" name="id" value="${esc(e.id)}">
        <div class="meta">${past ? 'Past' : 'Upcoming'}</div>
        <div class="row"><input type="text" name="name" value="${esc(e.name)}"
          placeholder="Event name" style="flex:1;min-width:14em"></div>
        <div class="row">
          <input type="date" name="date" value="${d}">
          <input type="text" name="date_label" value="${esc(e.date_label||'')}"
            placeholder="How the date should read" style="flex:1;min-width:12em">
        </div>
        <div class="row"><input type="text" name="location" value="${esc(e.location||'')}"
          placeholder="Where" style="flex:1;min-width:14em"></div>
        <div class="row"><input type="text" name="link" value="${esc(e.link||'')}"
          placeholder="Link for details" style="flex:1;min-width:14em"></div>
        <div class="row"><textarea name="notes" placeholder="Notes just for you">${esc(e.notes||'')}</textarea></div>
        ${(flyersBy[e.id] || []).length ? `<div class="shots">${(flyersBy[e.id] || []).map(f =>
          `<a href="/flyer/${f.token}" target="_blank" rel="noopener">
             <img src="/flyer/${f.token}" alt="${esc(f.filename)}" loading="lazy"></a>`).join('')}</div>` : ''}
        <div class="row" style="flex-direction:column;align-items:stretch">
          <label class="uplabel">Flyer or poster</label>
          <input type="file" name="flyer" accept="image/*" class="upfile">
          <div class="uphint">Goes on your speaking page with the event.</div>
        </div>
        <div class="row">
          <button class="btn" type="submit">Save</button>
          <button class="btn ghost" type="submit" formaction="/events/publish">Save &amp; put on my website</button>
          <button class="btn ghost" type="submit" formaction="/events/remove"
            onclick="return confirm('Remove this event? It will come off your website too.')"
            style="color:var(--due);border-color:#E8CDBF">Remove</button>
        </div>
      </form>
    </div>`;
  };

  res.send(layout('Events', `
    <header><h1><img class="hdr-logo" src="https://cdn.prod.website-files.com/62e1efa2754a35fc7aa455a9/67185ab06bdef51e5ff2b7ab_3-Color%20MV%20Bird.png" alt=""><a href="/" style="color:#fff;text-decoration:none">&larr; Leads</a></h1>
      <a href="/logout">Sign out</a></header>
    <div class="wrap">
      ${req.query.msg ? `<div class="toast"><div class="toast-text">${esc(req.query.msg)}</div></div>` : ''}
      <div class="card">
        <h2>Add an engagement</h2>
        <p class="lede" style="color:var(--mid);font-size:.95rem">Anything you add here can be put
          straight onto your speaking page.</p>
        <form method="post" action="/events/save" enctype="multipart/form-data">
          <div class="row"><input type="text" name="name" placeholder="Event name" required
            style="flex:1;min-width:14em"></div>
          <div class="row">
            <input type="date" name="date">
            <input type="text" name="date_label" placeholder="e.g. November 7, 2026 \u00b7 12:00 pm CT"
              style="flex:1;min-width:12em">
          </div>
          <div class="row"><input type="text" name="location" placeholder="Where"
            style="flex:1;min-width:14em"></div>
          <div class="row"><input type="text" name="link" placeholder="Link for details"
            style="flex:1;min-width:14em"></div>
          <div class="row"><textarea name="notes" placeholder="Notes just for you"></textarea></div>
          <div class="row" style="flex-direction:column;align-items:stretch">
            <label class="uplabel">Flyer or poster (optional)</label>
            <input type="file" name="flyer" accept="image/*" class="upfile">
            <div class="uphint">If you add one, it goes on your speaking page with the event.</div>
          </div>
          <div class="row">
            <button class="btn" type="submit">Add</button>
            <button class="btn ghost" type="submit" formaction="/events/publish">Add &amp; put on my website</button>
          </div>
        </form>
      </div>
      ${rows.map(card).join('')}
    </div>`));
});

async function saveEngagement(b) {
  const id = b.id && String(b.id).trim() ? String(b.id) : 'local-' + Date.now();
  const startsAt = b.date ? new Date(b.date + 'T12:00:00Z').toISOString() : null;
  await pool.query(
    `INSERT INTO engagements (id,name,starts_at,date_label,location,link,notes,updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,now())
     ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, starts_at=EXCLUDED.starts_at,
       date_label=EXCLUDED.date_label, location=EXCLUDED.location, link=EXCLUDED.link,
       notes=EXCLUDED.notes, updated_at=now()`,
    [id, b.name || 'Untitled', startsAt, b.date_label || null,
     b.location || null, b.link || null, b.notes || null]);
  return { id, startsAt };
}

async function storeFlyer(eventId, file) {
  if (!file || !/^image\//.test(file.mimetype)) return null;
  const token = crypto.randomBytes(16).toString('hex');
  await pool.query('DELETE FROM event_files WHERE event_id=$1', [eventId]);  // one flyer per event
  await pool.query(
    `INSERT INTO event_files (token,event_id,filename,mime,bytes) VALUES ($1,$2,$3,$4,$5)`,
    [token, eventId, String(file.originalname || 'flyer').slice(0, 200), file.mimetype, file.buffer]);
  return token;
}

// Public on purpose: Webflow fetches the image by URL. The token is unguessable.
app.get('/flyer/:token', async (req, res) => {
  const t = String(req.params.token || '');
  if (!/^[0-9a-f]{32}$/.test(t)) return res.status(400).send('bad token');
  const { rows } = await pool.query('SELECT * FROM event_files WHERE token=$1', [t]);
  if (!rows.length) return res.status(404).send('not found');
  res.setHeader('Content-Type', rows[0].mime);
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(rows[0].bytes);
});

app.post('/events/save', requireAuth, upload.single('flyer'), async (req, res) => {
  const saved = await saveEngagement(req.body);
  await storeFlyer(saved.id, req.file);
  res.redirect('/events?msg=' + encodeURIComponent('Saved. It is not on your website yet.'));
});

app.post('/events/publish', requireAuth, upload.single('flyer'), async (req, res) => {
  const { id, startsAt } = await saveEngagement(req.body);
  await storeFlyer(id, req.file);
  if (!WEBFLOW_TOKEN) return res.redirect('/events?msg=' + encodeURIComponent('Saved here, but the website connection is not set up.'));

  const d = startsAt ? new Date(startsAt) : null;
  const MONTHS = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];

  const fieldData = {
    'day-number': d ? String(d.getUTCDate()) : null,
    'month-short': d ? MONTHS[d.getUTCMonth()] : null,
    name: req.body.name || 'Untitled',
    slug: String(req.body.name || 'event').toLowerCase()
            .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'event',
    'event-date': startsAt,
    'date-label': req.body.date_label || null,
    location: req.body.location || null,
    'registration-link': req.body.link || null,
    hide: false
  };

  const flyer = await pool.query(
    'SELECT token FROM event_files WHERE event_id=$1 ORDER BY created_at DESC LIMIT 1', [id]);
  if (flyer.rows.length) {
    fieldData['cover-image'] =
      { url: 'https://leads.melodyvachal.com/flyer/' + flyer.rows[0].token };
  }

  let out;
  if (/^[0-9a-f]{24}$/.test(id)) {
    out = await webflow('/collections/' + EVENTS_COLLECTION + '/items/' + id, 'PATCH',
      { fieldData });
  } else {
    out = await webflow('/collections/' + EVENTS_COLLECTION + '/items', 'POST',
      { isDraft: false, fieldData });
    if (out.ok && out.data && out.data.id) {
      await pool.query('UPDATE engagements SET id=$1 WHERE id=$2', [out.data.id, id])
        .catch(() => {});
      await pool.query('UPDATE event_files SET event_id=$1 WHERE event_id=$2',
        [out.data.id, id]).catch(() => {});
    }
  }
  if (!out.ok) {
    console.error('webflow write failed', out.status, out.text);
    return res.redirect('/events?msg=' + encodeURIComponent('Saved here, but the website did not accept it. Aaron has been told.'));
  }
  await webflow('/sites/' + WEBFLOW_SITE + '/publish', 'POST',
    { customDomains: ['63fe5f69885ca03484ed5548', '63fe562fae944c48aa00df88'] });
  res.redirect('/events?msg=' + encodeURIComponent('Saved and published to your speaking page.'));
});

app.post('/events/remove', requireAuth, async (req, res) => {
  const id = String(req.body.id || '');
  if (!id) return res.redirect('/events');
  await pool.query('DELETE FROM engagements WHERE id=$1', [id]);
  await pool.query('DELETE FROM event_files WHERE event_id=$1', [id]);
  let msg = 'Removed from your list.';
  if (/^[0-9a-f]{24}$/.test(id) && WEBFLOW_TOKEN) {
    const out = await webflow('/collections/' + EVENTS_COLLECTION + '/items/' + id, 'DELETE');
    if (out.ok) {
      await webflow('/sites/' + WEBFLOW_SITE + '/publish', 'POST',
        { customDomains: ['63fe5f69885ca03484ed5548', '63fe562fae944c48aa00df88'] });
      msg = 'Removed from your list and taken off your website.';
    } else {
      msg = 'Removed from your list, but it is still on the website. Aaron has been told.';
    }
  }
  res.redirect('/events?msg=' + encodeURIComponent(msg));
});

/* ---------------------------------------------------- change requests */

app.get('/requests', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM requests ORDER BY created_at DESC LIMIT 100');
  const fileRows = await pool.query(
    `SELECT id, request_id, filename FROM request_files
      WHERE request_id = ANY($1) ORDER BY id`, [rows.map(r => r.id)]);
  const filesBy = {};
  for (const f of fileRows.rows) (filesBy[f.request_id] ||= []).push(f);
  res.send(layout('Requests', `
    <header><h1><a href="/" style="color:#fff;text-decoration:none">&larr; Leads</a></h1>
      <a href="/logout">Sign out</a></header>
    <div class="wrap">
      ${req.query.msg ? `<div class="toast"><div class="toast-text">${esc(req.query.msg)}</div></div>` : ''}
      <div class="card">
        <h2>Ask for a change</h2>
        <p style="color:var(--mid);font-size:.95rem;margin:4px 0 0">
          Anything about the website that you would rather Aaron handled. It is logged here
          with the date, so nothing gets lost in a text message.</p>
        <form method="post" action="/requests" enctype="multipart/form-data">
          <div class="row"><textarea name="body" required
            placeholder="What would you like changed?"></textarea></div>
          <div class="row" style="flex-direction:column;align-items:stretch">
            <label class="uplabel" for="photos">Add photos or a screenshot (optional)</label>
            <input id="photos" type="file" name="photos" accept="image/*" multiple
              capture="environment" class="upfile">
            <div class="uphint">Up to five, 8&nbsp;MB each. A screenshot of the bit you mean is often quickest.</div>
          </div>
          <div class="row">
            <input type="text" name="page" placeholder="Which page? (optional)" style="flex:1;min-width:12em">
            <select name="urgency">
              <option value="whenever">Whenever suits</option>
              <option value="this week">This week</option>
              <option value="urgent">Urgent</option>
            </select>
          </div>
          <div class="row"><button class="btn" type="submit">Send it</button></div>
        </form>
      </div>
      ${rows.map(r => `<div class="card">
        <div class="meta">${new Date(r.created_at).toLocaleDateString('en-US',
          { month:'short', day:'numeric', year:'numeric' })}
          &middot; ${esc(r.urgency)} &middot; ${esc(r.status)}${r.page ? ' &middot; ' + esc(r.page) : ''}</div>
        <div class="msg">${esc(r.body)}</div>
        ${(filesBy[r.id] || []).length ? `<div class="shots">${(filesBy[r.id] || []).map(f =>
          `<a href="/requests/file/${f.id}" target="_blank" rel="noopener">
             <img src="/requests/file/${f.id}" alt="${esc(f.filename)}" loading="lazy"></a>`).join('')}</div>` : ''}
        ${r.reply ? `<div class="nextstep">${esc(r.reply)}</div>` : ''}
      </div>`).join('')}
    </div>`));
});

app.post('/requests', requireAuth, upload.array('photos', 5), async (req, res) => {
  const body = (req.body.body || '').toString().trim();
  if (!body) return res.redirect('/requests');
  const r = await pool.query(
    `INSERT INTO requests (body, page, urgency) VALUES ($1,$2,$3) RETURNING id`,
    [body.slice(0, 4000), (req.body.page || '').slice(0, 200) || null,
     ['whenever','this week','urgent'].includes(req.body.urgency) ? req.body.urgency : 'whenever']);
  const id = r.rows[0].id;

  let saved = 0;
  for (const f of (req.files || [])) {
    if (!/^image\//.test(f.mimetype)) continue;      // images only
    await pool.query(
      `INSERT INTO request_files (request_id, filename, mime, bytes) VALUES ($1,$2,$3,$4)`,
      [id, String(f.originalname || 'photo').slice(0, 200), f.mimetype, f.buffer]);
    saved++;
  }
  res.redirect('/requests?msg=' + encodeURIComponent(
    'Sent. Aaron can see it' + (saved ? ' along with ' + saved + ' photo' + (saved > 1 ? 's' : '') : '') + '.'));
});

app.get('/requests/file/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');
  const { rows } = await pool.query('SELECT * FROM request_files WHERE id=$1', [id]);
  if (!rows.length) return res.status(404).send('not found');
  res.setHeader('Content-Type', rows[0].mime);
  res.setHeader('Cache-Control', 'private, max-age=86400');
  res.send(rows[0].bytes);
});

/* ------------------------------------------------------- sending mail */

const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const FROM_NAME = process.env.FROM_NAME || 'Melody Vachal';
const FROM_EMAIL = process.env.FROM_EMAIL || SMTP_USER;
const REPLY_TO  = process.env.REPLY_TO || FROM_EMAIL;
const canSend = () => !!(SMTP_USER && SMTP_PASS);

let transport = null;
function mailer() {
  if (!canSend()) return null;
  if (!transport) {
    transport = nodemailer.createTransport({
      host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    });
  }
  return transport;
}

const NOTIFY_EMAIL = process.env.NOTIFY_EMAIL || process.env.REPLY_TO || SMTP_USER;

// Tell her when something real arrives. Never for spam.
async function alertNewEnquiry(leadId) {
  if (!canSend() || !NOTIFY_EMAIL) return;
  try {
    const { rows } = await pool.query('SELECT * FROM leads WHERE id=$1', [leadId]);
    if (!rows.length) return;
    const l = rows[0];
    if (l.is_spam) return;

    const bits = [
      l.name ? 'From: ' + l.name : null,
      l.organization ? 'Organisation: ' + l.organization : null,
      l.email ? 'Email: ' + l.email : null,
      l.event_date ? 'Date mentioned: ' + l.event_date : null,
      l.audience ? 'Audience: ' + l.audience : null,
      l.intent ? '\nWhat they want: ' + l.intent : null
    ].filter(Boolean).join('\n');

    const body = [
      'A new enquiry just came in' + (l.source === 'email' ? ' by email.' : ' through your website.'),
      '', bits, '',
      l.message ? 'Their message:\n' + String(l.message).slice(0, 1200) : '',
      '', 'Open it: https://leads.melodyvachal.com/lead/' + l.id,
      '', 'A reply is being drafted for you there. Nothing sends on its own.'
    ].join('\n');

    await mailer().sendMail({
      from: '"Melody \u2014 enquiries" <' + FROM_EMAIL + '>',
      to: NOTIFY_EMAIL,
      replyTo: l.email || FROM_EMAIL,
      subject: 'New enquiry' + (l.name ? ' from ' + l.name : '') +
               (l.tag === 'speaking' ? ' (speaking)' : ''),
      text: body
    });
    await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'alert',$2)`,
      [l.id, 'you were emailed about this']);
  } catch (e) { console.error('alert failed', e.message); }
}

app.post('/lead/:id/send', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('bad id');

  const body = (req.body.draft || '').toString().trim();
  const subject = (req.body.subject || '').toString().trim() || 'Re: your enquiry';

  // Whatever she typed is kept first, whether or not the send succeeds.
  if (body) await pool.query('UPDATE leads SET draft_reply=$1 WHERE id=$2', [body, id]);

  const { rows } = await pool.query('SELECT * FROM leads WHERE id=$1', [id]);
  if (!rows.length) return res.status(404).send('not found');
  const lead = rows[0];

  if (!lead.email) return res.redirect('/lead/' + id + '?msg=' +
    encodeURIComponent('There is no email address on this enquiry.'));
  if (!body) return res.redirect('/lead/' + id + '?msg=' +
    encodeURIComponent('Write something first.'));
  if (!canSend()) return res.redirect('/lead/' + id + '?msg=' +
    encodeURIComponent('Sending is not switched on yet. Use Open in email for now.'));

  try {
    await mailer().sendMail({
      from: '"' + FROM_NAME + '" <' + FROM_EMAIL + '>',
      replyTo: REPLY_TO,
      to: lead.email,
      subject: subject,
      text: body
    });
  } catch (e) {
    console.error('send failed', e.message);
    return res.redirect('/lead/' + id + '?msg=' +
      encodeURIComponent('That did not send. Your draft is saved. ' + String(e.message).slice(0, 90)));
  }

  await pool.query(
    `INSERT INTO messages (lead_id,to_email,subject,body,kind) VALUES ($1,$2,$3,$4,$5)`,
    [id, lead.email, subject, body, lead.last_contacted ? 'follow-up' : 'reply']);
  await pool.query(
    `UPDATE leads SET last_contacted=now(),
       status=CASE WHEN status='new' THEN 'contacted' ELSE status END,
       updated_at=now() WHERE id=$1`, [id]);
  await pool.query(`INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'sent',$2)`,
    [id, 'to ' + lead.email]);

  res.redirect('/lead/' + id + '?msg=' + encodeURIComponent('Sent to ' + lead.email + '.'));
});

app.post('/reparse', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) return res.status(401).json({ ok:false });
  const { rows } = await pool.query(
    `SELECT id, raw, form_name FROM leads WHERE raw IS NOT NULL`);
  let fixed = 0;
  for (const r of rows) {
    const f = (r.raw && (r.raw.fields || (r.raw.payload && r.raw.payload.data))) || {};
    if (!Object.keys(f).length) continue;
    const name = pick(f, ['name','full name','your name','first name']);
    const email = pick(f, ['email','email address','e mail','email cta']);
    const message = pick(f, ['write about your project','inquiry details','event details','your message','comments','notes','message']);
    const org = pick(f, ['organization','organisation','company']);
    const phone = pick(f, ['phone','phone number','telephone']);
    if (!name && !email && !message && !org) continue;
    await pool.query(
      `UPDATE leads SET name=COALESCE(name,$1), email=COALESCE(email,$2),
         message=COALESCE(message,$3), organization=COALESCE(organization,$4),
         phone=COALESCE(phone,$5)
       WHERE id=$6 AND (name IS NULL OR email IS NULL OR message IS NULL)`,
      [name, email, message, org, phone, r.id]);
    fixed++;
  }
  res.json({ ok: true, checked: rows.length, fixed });
});

/* ------------------------------------------------- reading her inbox */

const IMAP_USER = process.env.IMAP_USER || SMTP_USER;
const IMAP_PASS = process.env.IMAP_PASS || SMTP_PASS;
const IMAP_HOST = process.env.IMAP_HOST || 'imap.gmail.com';
const IMAP_PORT = Number(process.env.IMAP_PORT || 993);
const INBOX_DAYS = Number(process.env.INBOX_DAYS || 30);
const canRead = () => !!(IMAP_USER && IMAP_PASS);

// Mail that is plainly not an enquiry. Cheap check before spending a model call.
const NOT_AN_ENQUIRY = /(no-?reply|do-?not-?reply|mailer-daemon|postmaster|notifications?@|newsletter|unsubscribe@|calendar-notification|bounce)/i;

const ENQUIRY_SYSTEM = `You decide whether an email is a genuine enquiry for Melody Vachal,
a keynote speaker and author on caregiving, that she would want in her enquiries list.

Enquiries include: speaking or booking requests, media and podcast invitations, questions
about her book or her work, and follow-ups on any of those.

Not enquiries: newsletters, marketing, receipts, calendar notifications, automated alerts,
social media notices, personal admin, and anything from a no-reply address.

Return ONLY JSON: {"is_enquiry": true|false, "tag": "speaking"|"book"|"guide"|"general",
"intent": "one short sentence", "organization": string or null,
"event_date": ISO date or null, "audience": string or null,
"urgency": "high"|"normal"|"low"}`;

async function classifyEmail(from, subject, body) {
  const out = await askClaude(ENQUIRY_SYSTEM,
    'From: ' + from + '\nSubject: ' + subject + '\n\n' + String(body || '').slice(0, 3000), 400);
  if (!out) return null;
  try { return JSON.parse(out.replace(/```json|```/g, '').trim()); } catch (e) { return null; }
}

async function readInbox() {
  if (!canRead()) return { ok:false, error:'no mailbox credentials' };
  const client = new ImapFlow({
    host: IMAP_HOST, port: IMAP_PORT, secure: true,
    auth: { user: IMAP_USER, pass: IMAP_PASS }, logger: false
  });
  let seen = 0, added = 0, threaded = 0, skipped = 0;

  try {
    await client.connect();
    const lock = await client.getMailboxLock('INBOX');
    try {
      const since = new Date(Date.now() - INBOX_DAYS * 86400000);
      for await (const msg of client.fetch({ since }, { source: true, envelope: true })) {
        seen++;
        const parsed = await simpleParser(msg.source);
        const messageId = parsed.messageId || null;
        const from = (parsed.from && parsed.from.value && parsed.from.value[0]) || {};
        const fromEmail = (from.address || '').toLowerCase();
        const fromName = from.name || null;
        const subject = parsed.subject || '(no subject)';
        const body = (parsed.text || '').trim();

        if (!fromEmail) { skipped++; continue; }
        if (fromEmail === String(IMAP_USER).toLowerCase()) { skipped++; continue; }
        if (NOT_AN_ENQUIRY.test(fromEmail) || NOT_AN_ENQUIRY.test(subject)) { skipped++; continue; }

        if (messageId) {
          const dupe = await pool.query('SELECT 1 FROM messages WHERE message_id=$1', [messageId]);
          if (dupe.rows.length) { skipped++; continue; }
        }

        // Already talking to this person? Thread it onto their record.
        const existing = await pool.query(
          'SELECT id FROM leads WHERE lower(email)=$1 ORDER BY received_at DESC LIMIT 1',
          [fromEmail]);

        if (existing.rows.length) {
          const leadId = existing.rows[0].id;
          await pool.query(
            `INSERT INTO messages (lead_id,sent_at,to_email,from_email,subject,body,kind,direction,message_id)
             VALUES ($1,$2,$3,$4,$5,$6,'reply','in',$7)
             ON CONFLICT (message_id) WHERE message_id IS NOT NULL DO NOTHING`,
            [leadId, parsed.date || new Date(), IMAP_USER, fromEmail, subject, body, messageId]);
          await pool.query(
            `UPDATE leads SET status=CASE WHEN status IN ('cold','spam') THEN status ELSE 'new' END,
               next_follow_up=NULL, updated_at=now() WHERE id=$1`, [leadId]);
          await pool.query(
            `INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'inbound',$2)`,
            [leadId, 'they replied \u2014 ' + subject]);
          threaded++;
          continue;
        }

        const verdict = await classifyEmail(fromEmail, subject, body);
        if (!verdict || !verdict.is_enquiry) { skipped++; continue; }

        const r = await pool.query(
          `INSERT INTO leads (received_at,form_name,name,email,message,raw,status,tag,
                              intent,event_date,audience,urgency,organization,source)
           VALUES ($1,$2,$3,$4,$5,$6,'new',$7,$8,$9,$10,$11,$12,'email') RETURNING id`,
          [parsed.date || new Date(), 'Email \u00b7 ' + subject, fromName, fromEmail, body,
           JSON.stringify({ source:'imap', messageId, subject }),
           TAGS.includes(verdict.tag) ? verdict.tag : 'general',
           verdict.intent || null, verdict.event_date || null, verdict.audience || null,
           ['high','normal','low'].includes(verdict.urgency) ? verdict.urgency : 'normal',
           verdict.organization || null]);
        const leadId = r.rows[0].id;
        await pool.query(
          `INSERT INTO messages (lead_id,sent_at,to_email,from_email,subject,body,kind,direction,message_id)
           VALUES ($1,$2,$3,$4,$5,$6,'reply','in',$7) ON CONFLICT (message_id) WHERE message_id IS NOT NULL DO NOTHING`,
          [leadId, parsed.date || new Date(), IMAP_USER, fromEmail, subject, body, messageId]);
        await pool.query(
          `INSERT INTO lead_events (lead_id,kind,body) VALUES ($1,'received',$2)`,
          [leadId, 'by email \u2014 ' + subject]);
        alertNewEnquiry(leadId);
        added++;
      }
    } finally { lock.release(); }
    await client.logout();
    return { ok:true, seen, added, threaded, skipped };
  } catch (e) {
    console.error('inbox read failed', e.message);
    try { await client.logout(); } catch (x) {}
    return { ok:false, error: String(e.message).slice(0, 200), seen, added, threaded };
  }
}

app.post('/inbox/sync', async (req, res) => {
  if (!HOOK_KEY || req.query.key !== HOOK_KEY) return res.status(401).json({ ok:false });
  res.json(await readInbox());
});

// Check her inbox on a schedule as well.
if (canRead()) {
  setInterval(() => { readInbox().catch(e => console.error('inbox poll', e.message)); },
    Number(process.env.INBOX_POLL_MINUTES || 15) * 60 * 1000);
  setTimeout(() => { readInbox().catch(() => {}); }, 90 * 1000);
}

app.get('/health', (req, res) => res.json({
  ok: true, ai: !!AI_KEY, canSend: canSend(), canReadInbox: canRead() }));

init().then(() => app.listen(PORT, () => console.log('listening on ' + PORT)))
      .catch(e => { console.error('startup failed', e); process.exit(1); });
