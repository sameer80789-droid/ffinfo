# Player Lookup – Free Fire info API (Vercel)

    GET /info?uid=123456789        (same as /api/info?uid=...)

Returns name, level, rank, clan, likes, dates, tags, avatar/banner/outfit links. The region is detected
automatically. No leaderboard. Avatar, banner and outfit pictures come from
`https://getitems.thug4ff.xyz/item?id=<id>`; the site shows them through `/api/item?id=<id>`
(cached, with a fallback icon source).

## Deploy
1. Put this folder in a **private** GitHub repo (or run `vercel` in it).
2. Vercel -> Add New Project -> import the repo. No build settings needed.
3. Project Settings -> Environment Variables -> add  **FF_ACCOUNTS_JSON**  (Production):

       [{"uid":"YOUR_UID","password":"YOUR_PASSWORD","region":"PK"},
        {"uid":"...","password":"...","region":"BD"}]

   Never put accounts in the code or the repo.
4. Redeploy, then open `/api/health` (shows accounts per region and the last login error) and
   try `/info?uid=<a real uid>`.

## Optional environment variables
| name | default | meaning |
|---|---|---|
| FF_ITEM_API | https://getitems.thug4ff.xyz/item | image API (`?id=` is added) |
| FF_RATE_PER_MIN | 20 | requests per IP per minute on /info |
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
