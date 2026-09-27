# melody-leads

Lead inbox and follow-up tracker for melodyvachal.com form submissions.

Runs alongside the existing Google Apps Script automation — that keeps
delivering the guide and writing its own log. This app is the follow-up layer.

## What it does

- Receives every Webflow form submission at `POST /hook?key=…`
- Triages on arrival: honeypot hits, link-stuffed messages, known spam terms,
  non-Latin script and throwaway email domains go straight to a Spam bucket
- Stores everything, including the raw payload, so nothing is lost if a
  triage rule turns out to be wrong
- Gives one screen to work from: filter by status, search, set a status,
  add notes, set a next follow-up date

Statuses: `new`, `contacted`, `booked`, `cold`, `spam`.

## Environment variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Postgres connection string (Railway provides this) |
| `APP_PASSWORD` | The password Melody signs in with |
| `HOOK_KEY` | Shared secret in the webhook URL |
| `SESSION_SECRET` | Random string used to sign the session cookie |

## Deploying on Railway

1. Deploy this repo into the `melody-leads` project (Postgres already exists there).
2. Reference the database: `DATABASE_URL=${{Postgres.DATABASE_URL}}`.
3. Set `APP_PASSWORD`, `HOOK_KEY` and `SESSION_SECRET`.
4. Generate a public domain for the service.
5. Add a Webflow webhook (`form_submission`, no filter) pointing at
   `https://<your-domain>/hook?key=<HOOK_KEY>`.

The table is created automatically on first boot.

## Notes

- The Webflow webhook that feeds the Apps Script is filtered to the
  `Guide Signup` form. This one should be left unfiltered so every form
  — contact, speaking enquiries, guide signups — lands in the inbox.
- Triage marks, it never deletes. Anything filed as spam is still in the
  Spam tab with the reason shown, and can be moved back in one tap.
