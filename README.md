# WebSecLab

A containerised, DVWA-style training lab with **9 hands-on challenges** across
three modern web-attack categories:

| Category                | Levels | Focus                                              |
| ----------------------- | :----: | -------------------------------------------------- |
| 2nd-Order SQL Injection |   3    | Stored, delayed-execution SQLi                     |
| Blind SQL Injection     |   3    | Boolean / time / header oracles                    |
| DOM-based XSS           |   3    | Client-side sinks, filter bypass, allow-list break |

Each challenge page has four panels:

1. **Challenge** – the interactive vulnerable UI
2. **Walkthrough** – stepwise methodology with progressive hints (never a ready-made payload)
3. **Source (relevant)** – the exact snippet that is vulnerable, for post-exploitation review
4. A **Reset Lab Data** button in the sidebar re-seeds the database in one click

> ⚠️ **Deliberately insecure.** Never expose this app to a network outside your
> lab. Run it on `localhost` or an isolated LAN only.

---

## 1. Prerequisites

- Docker and Docker Compose (v2+)
- A browser – Firefox recommended
- Burp Suite (Community edition is enough)

## 2. Start the lab

```bash
docker compose up --build
```

- First run downloads the MySQL 8 image and builds the Python backend (~1 min).
- When you see `webseclab_web` ready, open **http://localhost:8080**.

### Stopping / resetting

```bash
docker compose down           # stop
docker compose down -v        # stop AND wipe the MySQL volume (full reset)
```

The sidebar **⟳ Reset Lab Data** button re-seeds `users`, `comments`
and `reset_tokens` without restarting containers. Use it whenever a challenge
gets into a confusing state.

## 3. Port map

| Service | Internal | Exposed          |
| ------- | -------- | ---------------- |
| web     | 5000     | `localhost:8080` |
| db      | 3306     | not exposed      |

Change the host port in `docker-compose.yml → services.web.ports` if it
clashes with Burp's default listener.

## 4. Using Burp Suite with the lab

Burp's default proxy also listens on 8080, which clashes with the lab's host
port. Pick ONE of the options below:

### Option A · Move Burp's listener (recommended)

1. Burp → **Proxy → Options → Proxy Listeners**
2. Edit the default entry, change port to **8081**
3. In Firefox, set proxy to `127.0.0.1:8081` (or install **FoxyProxy** and add a
   rule for `localhost:8080` forwarding through `127.0.0.1:8081`)
4. Visit `http://localhost:8080` — requests appear in Burp HTTP history.

### Option B · Move the lab

Edit `docker-compose.yml`:

```yaml
ports:
  - "9090:5000"
```

Rebuild (`docker compose up -d --build`) and proxy `localhost:9090` through
Burp's default 8080.

### Must-have Burp tools per category

| Category           | Recommended tools                                                 |
| ------------------ | ----------------------------------------------------------------- |
| 2nd-Order SQLi     | **Repeater** (craft stored payload, then trigger second request)  |
| Blind SQLi         | **Repeater** + **Intruder** (automate boolean/time loops)         |
| DOM XSS            | **Proxy** + **DOM Invader** (Burp's built-in Chromium tab)        |

## 5. Lab accounts (seeded)

| Username  | Password             | Role  |
| --------- | -------------------- | ----- |
| `admin`   | `S3cretAdminPass!2026` | admin |
| `alice`   | `alice123`           | user  |
| `bob`     | `qwerty`             | user  |
| `charlie` | `letmein`            | user  |

The **goal** for SQLi levels is usually to become admin or exfiltrate an
admin-only secret; for DOM XSS the goal is to execute your JS in the
context of the page.

## 6. Folder layout

```
Web-App-Lab/
├── docker-compose.yml
├── README.md
├── db/
│   └── init.sql                      # schema + seed data
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py                        # all 9 routes, intentionally vulnerable
    ├── static/
    │   ├── css/style.css             # dark theme
    │   └── js/app.js                 # tab controller
    └── templates/
        ├── base.html                 # sidebar + layout
        ├── home.html
        ├── login.html
        ├── sqli2/  l1.html l2.html l3.html
        ├── bsqli/  l1.html l2.html l3.html
        └── domxss/ l1.html l2.html l3.html
```

## 7. Flags

Each level has a unique flag of the form `FLAG{...}`. The master list is
available to instructors in `db/init.sql → flags` table, or via:

```bash
docker compose exec db mysql -u labuser -plabpass weblab -e "SELECT * FROM flags;"
```

## 8. Instructor walkthrough

See **[WALKTHROUGH.md](./WALKTHROUGH.md)** for complete solutions, verified
payloads, and automation scripts for every level. Keep this file private —
don't ship it to students before they've attempted the challenges.

## 9. Teaching tips

- Encourage students to work the **Walkthrough** panel in order. Each step's
  hint is hidden behind a disclosure toggle, so they must first think, then
  peek.
- For Blind SQLi L2 and L3, pair students with a small Python helper script
  (using `requests` + `time.perf_counter`) instead of Burp Intruder – the
  exercise becomes about careful oracles, not tool friction.
- After a student captures a flag, have them open the **Source** panel and
  propose a patch. That's where the real learning hardens.

## 10. Extending the lab

To add a new level:

1. Add a route in `backend/app.py`
2. Add a template under the appropriate `templates/<category>/` folder
3. Register the level in `MENU` at the top of `app.py`
4. (Optional) seed extra tables in `db/init.sql`


