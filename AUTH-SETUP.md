# Authentication

The private Sites/ChatGPT access boundary is preserved. Additional SHADOWGRAPH accounts are tied to that authenticated Site identity. Registration issues a 256-bit random key once; the database stores only its SHA-256 hash. Sessions use random tokens with hashed database records and HttpOnly, Secure, SameSite=Strict cookies. Registration/login are same-origin POST requests with rate limits. No secrets are embedded in the browser.

Google, Telegram and GitHub buttons are explicitly marked as not connected. There are no fake successful social logins. Register provider applications and configure secrets through the Sites runtime configuration before implementing/enabling their verified server-side callback flows. The reserved Sites paths /callback and /signin-with-chatgpt must not be replaced. Use separate /api/auth/provider/* callback paths when the hosting platform supports these integrations.

Project files remain local to the browser and are separated by SHADOWGRAPH account ID. The first key account on the current browser adopts existing local projects without deleting the old database. Other key accounts get separate browser databases. Accounts/sessions are server-side; this is not cloud synchronization of project files.
