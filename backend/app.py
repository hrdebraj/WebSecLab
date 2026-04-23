"""
WebSecLab - An intentionally vulnerable web application for teaching:
  * 2nd Order SQL Injection   (3 levels)
  * Blind SQL Injection       (3 levels)
  * DOM-based XSS             (3 levels)

DO NOT expose outside a classroom / lab network.
"""

import os
import time
import secrets
from functools import wraps

import pymysql
from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, flash, jsonify, make_response, abort
)

# ---------------------------------------------------------------------------
# App + DB setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev_secret_change_me")

DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "db"),
    "user": os.environ.get("DB_USER", "labuser"),
    "password": os.environ.get("DB_PASSWORD", "labpass"),
    "database": os.environ.get("DB_NAME", "weblab"),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
}


def get_db():
    if "db" not in g:
        g.db = pymysql.connect(**DB_CONFIG)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def query(sql, params=None, one=False):
    """Parameterized helper (SAFE - used for the app's own infra)."""
    cur = get_db().cursor()
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def raw_execute(sql):
    """Raw execute used ONLY by intentionally vulnerable endpoints."""
    cur = get_db().cursor()
    cur.execute(sql)
    try:
        rows = cur.fetchall()
    except Exception:
        rows = []
    cur.close()
    return rows


# ---------------------------------------------------------------------------
# Menu definition (used by sidebar)
# ---------------------------------------------------------------------------
MENU = [
    {
        "id": "sqli2",
        "title": "2nd Order SQL Injection",
        "icon": "database",
        "levels": [
            {"id": "l1", "title": "Level 1 · Profile Password Change",    "difficulty": "easy"},
            {"id": "l2", "title": "Level 2 · Stored Comment Moderation", "difficulty": "medium"},
            {"id": "l3", "title": "Level 3 · Password Reset Flow",       "difficulty": "hard"},
        ],
    },
    {
        "id": "bsqli",
        "title": "Blind SQL Injection",
        "icon": "eye-off",
        "levels": [
            {"id": "l1", "title": "Level 1 · Boolean-Based Login Probe", "difficulty": "easy"},
            {"id": "l2", "title": "Level 2 · Time-Based Product Search", "difficulty": "medium"},
            {"id": "l3", "title": "Level 3 · Cookie-Based Tracking",     "difficulty": "hard"},
        ],
    },
    {
        "id": "domxss",
        "title": "DOM-based XSS",
        "icon": "code",
        "levels": [
            {"id": "l1", "title": "Level 1 · URL Hash Sink",      "difficulty": "easy"},
            {"id": "l2", "title": "Level 2 · Naive Tag Filter",   "difficulty": "medium"},
            {"id": "l3", "title": "Level 3 · Strict Allow-list",  "difficulty": "hard"},
        ],
    },
]


@app.context_processor
def inject_menu():
    return {
        "MENU": MENU,
        "current_user": session.get("user"),
    }


# ---------------------------------------------------------------------------
# Utility: create a scenario-local session user (per level, to keep data tidy)
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return f(*a, **kw)
    return wrapper


# ---------------------------------------------------------------------------
# Core pages
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html")


@app.route("/reset-lab", methods=["POST"])
def reset_lab():
    """Re-seeds mutable tables so students can redo a level from scratch."""
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM users")
    cur.execute("DELETE FROM comments")
    cur.execute("DELETE FROM reset_tokens")
    cur.execute("ALTER TABLE users AUTO_INCREMENT = 1")
    cur.execute("ALTER TABLE comments AUTO_INCREMENT = 1")
    cur.execute("ALTER TABLE reset_tokens AUTO_INCREMENT = 1")
    cur.executemany(
        "INSERT INTO users (username, password, email, role, api_key, private_note) VALUES (%s,%s,%s,%s,%s,%s)",
        [
            ("admin",   "S3cretAdminPass!2026", "admin@lab.local",   "admin",
             "FLAG{blind_boolean_admin_pwn}",  "FLAG{2nd_order_admin_reset_success}"),
            ("alice",   "alice123", "alice@lab.local",   "user", "ak_alice_7f2a",   "Reminder: renew TLS cert."),
            ("bob",     "qwerty",   "bob@lab.local",     "user", "ak_bob_9c1b",     "TODO: write unit tests."),
            ("charlie", "letmein",  "charlie@lab.local", "user", "ak_charlie_3e4d", "Nothing to see here."),
        ],
    )
    cur.executemany(
        "INSERT INTO comments (author, content) VALUES (%s,%s)",
        [("alice", "Great product!"), ("bob", "Shipping was fast.")],
    )
    cur.close()
    session.clear()
    flash("Lab data has been reset.", "success")
    return redirect(request.referrer or url_for("home"))


# ---------------------------------------------------------------------------
# Simple app-wide login (used for the "Profile" scenarios)
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # Safe parameterized query (lab login uses safe code on purpose)
        row = query("SELECT id, username, role FROM users WHERE username=%s AND password=%s",
                    (u, p), one=True)
        if row:
            session["user"] = row
            nxt = request.args.get("next") or url_for("home")
            return redirect(nxt)
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ===========================================================================
# 2ND-ORDER SQL INJECTION
# ===========================================================================

# -------------------- Level 1 : Profile password change --------------------
# Scenario:
#   * Registration uses a SAFE parameterized INSERT -> student can store any
#     username, including SQL metacharacters.
#   * "Change password" builds UPDATE ... WHERE username='<stored>' by string
#     concatenation -> the stored username is now a SQL payload on second use.
# Goal: change admin's password, login as admin, capture flag.
# ---------------------------------------------------------------------------
@app.route("/sqli2/l1", methods=["GET"])
def sqli2_l1():
    return render_template("sqli2/l1.html", flag=None)


@app.route("/sqli2/l1/register", methods=["POST"])
def sqli2_l1_register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        flash("Both fields required.", "error")
        return redirect(url_for("sqli2_l1"))
    try:
        # SAFE insert - we do not want injection on this step.
        cur = get_db().cursor()
        cur.execute("INSERT INTO users (username, password, role) VALUES (%s,%s,'user')",
                    (username, password))
        cur.close()
        session["sqli2_l1_user"] = username
        flash(f"Account '{username}' registered. You are now logged in for L1.", "success")
    except pymysql.err.IntegrityError:
        flash("That username already exists.", "error")
    return redirect(url_for("sqli2_l1"))


@app.route("/sqli2/l1/change-password", methods=["POST"])
def sqli2_l1_change_password():
    stored_user = session.get("sqli2_l1_user")
    if not stored_user:
        flash("Register and log in first.", "error")
        return redirect(url_for("sqli2_l1"))
    new_pw = request.form.get("new_password", "")
    # *** VULNERABLE: stored username concatenated into UPDATE ***
    sql = f"UPDATE users SET password='{new_pw}' WHERE username='{stored_user}'"
    try:
        raw_execute(sql)
        flash("Password updated successfully.", "success")
    except Exception as e:
        flash(f"DB error: {e}", "error")
    return redirect(url_for("sqli2_l1"))


@app.route("/sqli2/l1/login", methods=["POST"])
def sqli2_l1_login():
    """Separate login form shown in L1 so students can verify admin takeover."""
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    row = query("SELECT username, role, private_note FROM users WHERE username=%s AND password=%s",
                (u, p), one=True)
    if row and row["role"] == "admin":
        return render_template("sqli2/l1.html", flag=row["private_note"], logged_admin=True)
    if row:
        flash(f"Logged in as '{row['username']}' (role: {row['role']}). Not admin.", "info")
    else:
        flash("Login failed.", "error")
    return redirect(url_for("sqli2_l1"))


# -------------------- Level 2 : Stored comment moderation ------------------
# Scenario:
#   * Users post comments (SAFE insert).
#   * Moderator page runs: SELECT ... FROM comments WHERE author='<author>'
#     built via concatenation when the moderator "inspects" a comment.
#   * Student can register an account with an SQL-meta username, post a
#     comment, and when the moderator (simulated via /sqli2/l2/moderate)
#     inspects that comment, the second query fires and discloses data.
# ---------------------------------------------------------------------------
@app.route("/sqli2/l2", methods=["GET"])
def sqli2_l2():
    comments = query("SELECT id, author, content, flagged, created_at FROM comments ORDER BY id DESC")
    return render_template("sqli2/l2.html", comments=comments, moderation_result=None)


@app.route("/sqli2/l2/post", methods=["POST"])
def sqli2_l2_post():
    author = request.form.get("author", "").strip()
    content = request.form.get("content", "").strip()
    if not author or not content:
        flash("Fields required.", "error")
        return redirect(url_for("sqli2_l2"))
    cur = get_db().cursor()
    cur.execute("INSERT INTO comments (author, content) VALUES (%s,%s)", (author, content))
    cur.close()
    flash("Comment posted.", "success")
    return redirect(url_for("sqli2_l2"))


@app.route("/sqli2/l2/moderate/<int:cid>", methods=["GET"])
def sqli2_l2_moderate(cid):
    """Simulated moderator action. Builds a vulnerable second query from the
    comment's *author* field (stored earlier). UNION-ready."""
    row = query("SELECT author, content FROM comments WHERE id=%s", (cid,), one=True)
    if not row:
        abort(404)
    author = row["author"]
    # *** VULNERABLE: author is concatenated into a statistics query ***
    sql = (
        "SELECT COUNT(*) AS total, MAX(id) AS last_id "
        f"FROM comments WHERE author='{author}'"
    )
    try:
        result = raw_execute(sql)
    except Exception as e:
        result = [{"error": str(e)}]
    comments = query("SELECT id, author, content, flagged, created_at FROM comments ORDER BY id DESC")
    return render_template("sqli2/l2.html",
                           comments=comments,
                           moderation_result={"sql": sql, "rows": result, "comment": row})


# -------------------- Level 3 : Password reset flow ------------------------
# Scenario:
#   * Request password reset: user supplies an email. Token is stored together
#     with the *supplied email string* (SAFE insert).
#   * When the user submits the token, the app looks up the stored email and
#     uses it (concatenated) to run an UPDATE on the users table:
#        UPDATE users SET password='<new>' WHERE email='<stored_email>'
#   * Student crafts an email value that, when re-used server-side, updates
#     admin's password.
# ---------------------------------------------------------------------------
@app.route("/sqli2/l3", methods=["GET"])
def sqli2_l3():
    token = session.get("sqli2_l3_token")
    return render_template("sqli2/l3.html", token=token, flag=None)


@app.route("/sqli2/l3/request", methods=["POST"])
def sqli2_l3_request():
    email = request.form.get("email", "")
    token = secrets.token_hex(8)
    # SAFE insert
    cur = get_db().cursor()
    cur.execute("INSERT INTO reset_tokens (email, token) VALUES (%s,%s)", (email, token))
    cur.close()
    session["sqli2_l3_token"] = token
    flash(f"Reset request created. Your token: {token}", "info")
    return redirect(url_for("sqli2_l3"))


@app.route("/sqli2/l3/reset", methods=["POST"])
def sqli2_l3_reset():
    token = request.form.get("token", "")
    new_pw = request.form.get("new_password", "")
    # Fetch stored email for this token (SAFE)
    row = query("SELECT email FROM reset_tokens WHERE token=%s AND used=0",
                (token,), one=True)
    if not row:
        flash("Invalid or used token.", "error")
        return redirect(url_for("sqli2_l3"))
    stored_email = row["email"]
    # *** VULNERABLE second-order use ***
    sql = f"UPDATE users SET password='{new_pw}' WHERE email='{stored_email}'"
    try:
        raw_execute(sql)
        cur = get_db().cursor()
        cur.execute("UPDATE reset_tokens SET used=1 WHERE token=%s", (token,))
        cur.close()
        flash("Password reset performed.", "success")
    except Exception as e:
        flash(f"DB error: {e}", "error")
    return redirect(url_for("sqli2_l3"))


@app.route("/sqli2/l3/login", methods=["POST"])
def sqli2_l3_login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    row = query("SELECT username, role, private_note FROM users WHERE username=%s AND password=%s",
                (u, p), one=True)
    if row and row["role"] == "admin":
        return render_template("sqli2/l3.html",
                               token=session.get("sqli2_l3_token"),
                               flag=row["private_note"],
                               logged_admin=True)
    flash("Login failed or not admin.", "error")
    return redirect(url_for("sqli2_l3"))


# ===========================================================================
# BLIND SQL INJECTION
# ===========================================================================

# -------------------- Level 1 : Boolean-based login probe ------------------
# Endpoint: /bsqli/l1/check?username=...
# Behaviour:
#   * Runs  SELECT id FROM users WHERE username='<input>'  (concat).
#   * Returns  {"exists": true}  or  {"exists": false}.
#   * No error messages, no password check here - pure boolean oracle.
# Goal: extract admin's api_key, character by character.
# ---------------------------------------------------------------------------
@app.route("/bsqli/l1", methods=["GET"])
def bsqli_l1():
    return render_template("bsqli/l1.html")


@app.route("/bsqli/l1/check", methods=["GET"])
def bsqli_l1_check():
    username = request.args.get("username", "")
    sql = f"SELECT id FROM users WHERE username='{username}'"
    try:
        rows = raw_execute(sql)
        return jsonify({"exists": len(rows) > 0})
    except Exception:
        # Keep the oracle "clean" - no error leak
        return jsonify({"exists": False})


# -------------------- Level 2 : Time-based product search ------------------
# Endpoint: /bsqli/l2/search?category=...
# Behaviour:
#   * Always returns the same HTML ("Results loading").
#   * Vulnerable query: SELECT name,price FROM products WHERE category='<x>'
#   * Student has to infer data via SLEEP()/BENCHMARK() timing.
# ---------------------------------------------------------------------------
@app.route("/bsqli/l2", methods=["GET"])
def bsqli_l2():
    return render_template("bsqli/l2.html")


@app.route("/bsqli/l2/search", methods=["GET"])
def bsqli_l2_search():
    cat = request.args.get("category", "")
    sql = f"SELECT name, price FROM products WHERE category='{cat}'"
    start = time.time()
    try:
        raw_execute(sql)
    except Exception:
        pass
    elapsed = time.time() - start
    # Generic response: never reveals rows or errors
    return jsonify({"status": "ok", "server_elapsed_ms": int(elapsed * 1000)})


# -------------------- Level 3 : Cookie-based blind -------------------------
# Endpoint: /bsqli/l3/ping  (reads cookie 'track')
# Behaviour:
#   * SELECT username FROM tracking WHERE token='<cookie>'
#   * If a row is returned -> response header X-Status: OK
#     else                 -> X-Status: UNKNOWN
#   * No body variation. Student must use Burp to tamper the cookie and use
#     boolean inference via headers (or time-based).
# ---------------------------------------------------------------------------
@app.route("/bsqli/l3", methods=["GET"])
def bsqli_l3():
    resp = make_response(render_template("bsqli/l3.html"))
    if not request.cookies.get("track"):
        resp.set_cookie("track", "tk_alice", httponly=False)
    return resp


@app.route("/bsqli/l3/ping", methods=["GET"])
def bsqli_l3_ping():
    token = request.cookies.get("track", "")
    sql = f"SELECT username FROM tracking WHERE token='{token}'"
    status = "UNKNOWN"
    try:
        rows = raw_execute(sql)
        if rows:
            status = "OK"
    except Exception:
        status = "UNKNOWN"
    resp = make_response("", 204)
    resp.headers["X-Status"] = status
    return resp


# ===========================================================================
# DOM-based XSS
# ===========================================================================
# All three levels are purely client-side: the server sends static HTML that
# contains a vulnerable sink. The student must craft a URL that causes JS
# execution WITHOUT the payload ever being reflected through the server.
# ---------------------------------------------------------------------------
@app.route("/domxss/l1", methods=["GET"])
def domxss_l1():
    return render_template("domxss/l1.html")


@app.route("/domxss/l2", methods=["GET"])
def domxss_l2():
    return render_template("domxss/l2.html")


@app.route("/domxss/l3", methods=["GET"])
def domxss_l3():
    return render_template("domxss/l3.html")


# ---------------------------------------------------------------------------
# Dev entry-point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
