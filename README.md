# Player Lookup – Free Fire info API (Vercel)

    GET /info?uid=123456789&secret=ncs        (also /api/info; header  X-API-Key: ncs  works too)

PK server only. Returns name, level, rank, clan, likes, dates, tags, avatar/banner/outfit links.
No leaderboard. Pictures come from `https://getitems.thug4ff.xyz/item?id=<id>`; the page shows them via
`/api/item?id=<id>` (cached, with a fallback icon source).

## Deploy (nothing to configure)
1. Put this folder in a **private** GitHub repo (the PK game account is built into `api/index.py`).
2. Vercel -> Add New Project -> import the repo -> Deploy.
3. Open the site, type a UID. On the first visit the page asks for the access key (default `ncs`).
   Check `/api/health?secret=ncs` if a lookup fails.

Change the key: Vercel env var `FF_API_SECRET`. Use another game account: env var `FF_ACCOUNTS_JSON`
(`[{"uid":"...","password":"...","region":"PK"}]`). Env values override the built-in ones.

## Optional environment variables
| name | default | meaning |
|---|---|---|
| FF_API_SECRET | ncs | the access key |
| FF_REGION | PK | the only server this deployment searches |
| FF_ITEM_API | https://getitems.thug4ff.xyz/item | image API (`?id=` is added) |
| FF_RATE_PER_MIN | 20 | requests per IP per minute (also slows key guessing) |
| FF_SEARCH_BUDGET | 24 | seconds spent trying regions (keep below the function limit) |
| FF_LOGIN_GAP | 1.5 | seconds between two Garena logins |
| FF_EGRESS_IP | auto | the server's public IP sent in the login request |
| FF_GAME_VERSION | 1.132.21 | fallback game version |

## Things to know
- Vercel runs functions on shared datacenter IPs. Garena can answer `429 error_too_many_requests` or refuse
  logins from such IPs. `/api/health` then shows the reason; the site shows "Garena rate limit".
- Serverless = no memory between cold starts, so a cold request logs in again (a few seconds). Warm
  requests reuse the login. More accounts per region = safer.
- Function limit is 30 s (`vercel.json`). If your plan allows less, lower FF_SEARCH_BUDGET.
