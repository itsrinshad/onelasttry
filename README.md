# SYMBIOTES 2.0 — setup
1. Supabase: create project. Database > Extensions > enable **pg_cron**.
2. SQL Editor: paste and run `SYMBIOTES_SUPABASE_SETUP.sql` (once).
3. Auth > URL Configuration: add your Netlify URL as Site URL + redirect. Keep email confirmation ON.
4. Register on the site, verify email, then run the super-admin line at the bottom of the SQL file with your email.
5. Local: `cp .env.example .env`, fill URL + anon key, `npm install`, `npm run dev`.
6. Netlify: connect repo/upload, set env vars `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY`. Build `npm run build`, publish `dist`.
Never use or expose the service_role key. Not yet tested against a live Supabase project — report any SQL error and it gets fixed.


## Login system (no email verification)
1. Supabase > Authentication > Providers > Email: turn OFF "Confirm email".
2. Run SYMBIOTES_SUPABASE_SETUP.sql once, then SYMBIOTES_AUTH_UPGRADE.sql once.
3. Sign up on the site, then run the last line of the upgrade SQL (with your username) to become the first admin.
Pages: /signup, /login, /admin-login, /admin (approve, remove, change passwords).
