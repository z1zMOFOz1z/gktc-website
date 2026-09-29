"""GateKeeperTC card enrollment website.

Public visitors enroll a card holder (name + card number) after picking
their supervisor and entering the supervisor password. Supervisors are
managed in the GKTC desktop app and synced here through the admin API.
The GateKeeperTC device polls /api/cards for newly enrolled cards.

Deploy: Vercel Hobby (free) + Neon Postgres (free) + Gmail (free SMTP/IMAP).
See install.txt for the full step-by-step guide.
"""

import hashlib
import hmac
import imaplib
import json
import os
import re
import secrets
import smtplib
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from email.message import EmailMessage
from email.utils import parseaddr

from flask import Flask, jsonify, render_template, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Configuration (all from environment variables, see install.txt)
# ---------------------------------------------------------------------------

def env(name, default=""):
    return (os.environ.get(name, default) or "").strip()


def using_postgres():
    return bool(env("DATABASE_URL"))


def site_url():
    base = env("SITE_URL") or request.host_url.rstrip("/")
    return base.rstrip("/")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value):
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Database (Neon Postgres in production, local SQLite for testing)
# ---------------------------------------------------------------------------

class DB:
    def __init__(self):
        url = env("DATABASE_URL")
        if url:
            try:
                import psycopg2
            except ImportError:
                raise RuntimeError("DATABASE_URL is set but psycopg2 is not installed.")
            self.con = psycopg2.connect(url)
            self.con.autocommit = True
            self.pg = True
        else:
            here = os.path.dirname(os.path.abspath(__file__))
            self.con = sqlite3.connect(os.path.join(here, "site.db"))
            self.con.row_factory = sqlite3.Row
            self.pg = False
        self.cur = self.con.cursor()

    def sql(self, text):
        return text.replace("?", "%s") if self.pg else text

    def all(self, text, params=()):
        self.cur.execute(self.sql(text), params)
        cols = [d[0] for d in self.cur.description]
        out = []
        for row in self.cur.fetchall():
            if isinstance(row, (tuple, list)):
                out.append(dict(zip(cols, row)))
            else:
                out.append({c: row[c] for c in cols})
        return out

    def one(self, text, params=()):
        rows = self.all(text, params)
        return rows[0] if rows else None

    def run(self, text, params=()):
        self.cur.execute(self.sql(text), params)
        if not self.pg:
            self.con.commit()

    def close(self):
        try:
            self.cur.close()
        except Exception:
            pass
        try:
            self.con.close()
        except Exception:
            pass


_schema_ready = False


def ensure_schema():
    """Create tables on first use (safe to call repeatedly)."""
    global _schema_ready
    if _schema_ready:
        return
    db = DB()
    try:
        if db.pg:
            db.cur.execute("""CREATE TABLE IF NOT EXISTS supervisors(
                id SERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL DEFAULT '', pw_hash TEXT NOT NULL DEFAULT '',
                notify BOOLEAN NOT NULL DEFAULT TRUE,
                reset_token TEXT NOT NULL DEFAULT '', reset_expiry TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT '')""")
            db.cur.execute("""CREATE TABLE IF NOT EXISTS cards(
                id SERIAL PRIMARY KEY, holder TEXT NOT NULL, number TEXT NOT NULL,
                supervisor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '')""")
            db.cur.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '')")
        else:
            db.cur.execute("""CREATE TABLE IF NOT EXISTS supervisors(
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL DEFAULT '', pw_hash TEXT NOT NULL DEFAULT '',
                notify INTEGER NOT NULL DEFAULT 1,
                reset_token TEXT NOT NULL DEFAULT '', reset_expiry TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT '')""")
            db.cur.execute("""CREATE TABLE IF NOT EXISTS cards(
                id INTEGER PRIMARY KEY AUTOINCREMENT, holder TEXT NOT NULL, number TEXT NOT NULL,
                supervisor TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT '')""")
            db.cur.execute("CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL DEFAULT '')")
            db.con.commit()
    finally:
        db.close()
    _schema_ready = True


@app.before_request
def _prepare():
    ensure_schema()


def get_setting(key, default=""):
    db = DB()
    try:
        row = db.one("SELECT v FROM settings WHERE k = ?", (key,))
        return row["v"] if row else default
    finally:
        db.close()


def set_setting(key, value):
    db = DB()
    try:
        if db.pg:
            db.run("INSERT INTO settings(k, v) VALUES(?, ?) "
                   "ON CONFLICT(k) DO UPDATE SET v = EXCLUDED.v", (key, value))
        else:
            db.run("INSERT OR REPLACE INTO settings(k, v) VALUES(?, ?)", (key, value))
    finally:
        db.close()


def notify_enabled():
    return get_setting("notify_enabled", "1") == "1"


def enrollment_enabled():
    return get_setting("enrollment_enabled", "0") == "1"


EMAIL_PROVIDERS = ("gmail", "outlook", "brevo", "sendgrid", "smtp", "none")


def email_config():
    """Email settings: values synced from GKTC win, env vars are fallback."""
    provider = (get_setting("email_provider", "") or env("EMAIL_PROVIDER", "gmail")).strip().lower()
    if provider not in EMAIL_PROVIDERS:
        provider = "gmail"
    cfg = {
        "provider": provider,
        "smtp_host": get_setting("email_smtp_host", "") or env("SMTP_HOST", ""),
        "smtp_port": get_setting("email_smtp_port", "") or env("SMTP_PORT", "587"),
        "smtp_user": get_setting("email_smtp_user", "") or env("SMTP_USER", ""),
        "smtp_pass": get_setting("email_smtp_pass", "") or env("SMTP_PASS", ""),
        "mail_from": get_setting("email_from", "") or env("MAIL_FROM", ""),
        "imap_host": get_setting("email_imap_host", "") or env("IMAP_HOST", ""),
        "imap_user": get_setting("email_imap_user", "") or env("IMAP_USER", ""),
        "imap_pass": get_setting("email_imap_pass", "") or env("IMAP_PASS", ""),
        "api_key": get_setting("email_api_key", "") or env("EMAIL_API_KEY", ""),
    }
    if not cfg["mail_from"]:
        cfg["mail_from"] = cfg["smtp_user"]
    if not cfg["imap_user"]:
        cfg["imap_user"] = cfg["smtp_user"]
    if not cfg["imap_pass"]:
        cfg["imap_pass"] = cfg["smtp_pass"]
    if provider == "gmail":
        cfg["smtp_host"] = cfg["smtp_host"] or "smtp.gmail.com"
        cfg["imap_host"] = cfg["imap_host"] or "imap.gmail.com"
    elif provider == "outlook":
        cfg["smtp_host"] = cfg["smtp_host"] or "smtp.office365.com"
        cfg["imap_host"] = cfg["imap_host"] or "outlook.office365.com"
    try:
        cfg["smtp_port"] = int(cfg["smtp_port"] or 587)
    except ValueError:
        cfg["smtp_port"] = 587
    return cfg


def email_usable(cfg=None):
    cfg = cfg or email_config()
    if cfg["provider"] in ("brevo", "sendgrid"):
        return bool(cfg["api_key"] and cfg["mail_from"])
    if cfg["provider"] in ("gmail", "outlook", "smtp"):
        return bool(cfg["smtp_host"] and cfg["smtp_user"] and cfg["smtp_pass"])
    return False


def stop_available(cfg=None):
    cfg = cfg or email_config()
    return cfg["provider"] in ("gmail", "outlook", "smtp") and bool(
        cfg["imap_host"] and cfg["imap_user"] and cfg["imap_pass"])


# ---------------------------------------------------------------------------
# Email (Gmail SMTP) and STOP-by-reply handling (Gmail IMAP)
# ---------------------------------------------------------------------------

def _send_via_smtp(to_addr, subject, body, cfg):
    if not to_addr or not email_usable(cfg):
        print("EMAIL SKIPPED: missing recipient or SMTP credentials")
        return False
    msg = EmailMessage()
    msg["From"] = cfg["mail_from"]
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=25) as s:
        s.starttls()
        s.login(cfg["smtp_user"], cfg["smtp_pass"])
        s.send_message(msg)
    return True


def _post_json(url, payload, headers):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=25) as resp:
        return 200 <= resp.status < 300


def _send_via_brevo(to_addr, subject, body, cfg):
    if not to_addr or not email_usable(cfg):
        print("EMAIL SKIPPED: missing recipient or Brevo key")
        return False
    return _post_json("https://api.brevo.com/v3/smtp/email",
                      {"sender": {"email": cfg["mail_from"]},
                       "to": [{"email": to_addr}],
                       "subject": subject, "textContent": body},
                      {"api-key": cfg["api_key"], "Content-Type": "application/json"})


def _send_via_sendgrid(to_addr, subject, body, cfg):
    if not to_addr or not email_usable(cfg):
        print("EMAIL SKIPPED: missing recipient or SendGrid key")
        return False
    return _post_json("https://api.sendgrid.com/v3/mail/send",
                      {"personalizations": [{"to": [{"email": to_addr}]}],
                       "from": {"email": cfg["mail_from"]},
                       "subject": subject,
                       "content": [{"type": "text/plain", "value": body}]},
                      {"Authorization": "Bearer " + cfg["api_key"],
                       "Content-Type": "application/json"})


def send_email(to_addr, subject, body):
    """Send one plain-text email. Returns True on success, never raises."""
    try:
        cfg = email_config()
        if cfg["provider"] == "brevo":
            return _send_via_brevo(to_addr, subject, body, cfg)
        if cfg["provider"] == "sendgrid":
            return _send_via_sendgrid(to_addr, subject, body, cfg)
        if cfg["provider"] in ("gmail", "outlook", "smtp"):
            return _send_via_smtp(to_addr, subject, body, cfg)
        print("EMAIL SKIPPED: email provider is 'none'")
        return False
    except Exception as exc:
        print("EMAIL FAILED:", exc)
        return False


def _decode_mime(value):
    parts = []
    for text, charset in decode_header(value or ""):
        if isinstance(text, bytes):
            try:
                parts.append(text.decode(charset or "utf-8", "replace"))
            except Exception:
                parts.append(text.decode("utf-8", "replace"))
        else:
            parts.append(text)
    return "".join(parts)


def maybe_process_stop_replies():
    """If a supervisor replies with subject STOP, stop their notifications.

    Runs at most every 15 minutes and never breaks the calling request.
    """
    try:
        last = parse_iso(get_setting("last_stop_check", ""))
        if last and datetime.now(timezone.utc) - last < timedelta(minutes=15):
            return
        set_setting("last_stop_check", now_iso())
        cfg = email_config()
        if not stop_available(cfg):
            return
        box = imaplib.IMAP4_SSL(cfg["imap_host"])
        try:
            box.login(cfg["imap_user"], cfg["imap_pass"])
            box.select("INBOX")
            status, data = box.search(None, '(UNSEEN SUBJECT "stop")')
            if status != "OK":
                return
            for num in data[0].split()[:25]:
                try:
                    status, fetched = box.fetch(num, "(BODY[HEADER.FIELDS (FROM SUBJECT)])")
                    if status != "OK" or not fetched or not fetched[0]:
                        continue
                    raw = fetched[0][1].decode("utf-8", "replace")
                    from_line = ""
                    subject = ""
                    for header_line in raw.splitlines():
                        low = header_line.lower()
                        if low.startswith("from:"):
                            from_line = _decode_mime(header_line[5:].strip())
                        elif low.startswith("subject:"):
                            subject = _decode_mime(header_line[8:].strip())
                    if "stop" in subject.lower():
                        addr = parseaddr(from_line)[1].strip().lower()
                        if addr:
                            db = DB()
                            try:
                                if db.pg:
                                    db.run("UPDATE supervisors SET notify = FALSE "
                                           "WHERE lower(email) = ?", (addr,))
                                else:
                                    db.run("UPDATE supervisors SET notify = 0 "
                                           "WHERE lower(email) = ?", (addr,))
                            finally:
                                db.close()
                            print("STOP PROCESSED for", addr)
                    box.store(num, "+FLAGS", "\\Seen")
                except Exception as exc:
                    print("STOP message skipped:", exc)
        finally:
            try:
                box.logout()
            except Exception:
                pass
    except Exception as exc:
        print("STOP check failed:", exc)


def unsubscribe_sig(supervisor_id):
    key = env("ADMIN_KEY").encode("utf-8")
    return hmac.new(key, str(supervisor_id).encode("utf-8"),
                    hashlib.sha256).hexdigest()[:24]


def unsubscribe_link(supervisor_id):
    return site_url() + "/unsubscribe/%s/%s" % (supervisor_id, unsubscribe_sig(supervisor_id))


def notice_footer(link):
    if stop_available():
        return ("You get this message because you are listed as a supervisor. To stop\n"
                "these notifications, reply to this email with the subject STOP, or\n"
                "open this link:\n  %s\n" % link)
    return ("You get this message because you are listed as a supervisor.\n"
            "To stop these notifications, open this link:\n  %s\n" % link)


# ---------------------------------------------------------------------------
# Enrollment form
# ---------------------------------------------------------------------------

_last_submit = {}


def rate_ok(ip):
    now = datetime.now(timezone.utc).timestamp()
    if now - _last_submit.get(ip, 0) < 10:
        return False
    _last_submit[ip] = now
    if len(_last_submit) > 500:
        _last_submit.clear()
    return True


def clean_number(raw):
    # Keep hex chip IDs (e.g. E4307163 from a GKTC scan) as well as printed
    # decimal numbers; strip spacing, dashes and any other punctuation.
    return re.sub(r"[^0-9A-Fa-f]", "", raw or "")


@app.route("/", methods=["GET", "POST"])
def enroll():
    if not enrollment_enabled():
        return render_template("message.html", title="Enrollment disabled",
                               body="Card enrollment is turned off right now. "
                                    "Ask your GateKeeperTC administrator to turn it back on.")
    db = DB()
    try:
        supervisors = db.all("SELECT id, name FROM supervisors ORDER BY name")
    finally:
        db.close()
    if request.method == "GET":
        return render_template("enroll.html", supervisors=supervisors,
                               holder="", number="", supervisor="", error="")

    maybe_process_stop_replies()
    holder = (request.form.get("holder") or "").strip()
    number = clean_number(request.form.get("number"))
    supervisor = (request.form.get("supervisor") or "").strip()
    password = request.form.get("password") or ""
    error = ""
    if len(holder) < 2 or len(holder) > 60:
        error = "Enter the card holder's name (2-60 characters)."
    elif len(number) < 3 or len(number) > 24:
        error = "That card number does not look right. Check the example on the card back and try again."
    elif not supervisor:
        error = "Pick your supervisor from the list."
    elif not password:
        error = "Enter the supervisor password."
    if error:
        return render_template("enroll.html", supervisors=supervisors,
                               holder=holder, number=request.form.get("number", ""),
                               supervisor=supervisor, error=error)
    if not rate_ok(request.remote_addr or ""):
        return render_template("enroll.html", supervisors=supervisors,
                               holder=holder, number=request.form.get("number", ""),
                               supervisor=supervisor,
                               error="Please wait a few seconds and try again.")

    db = DB()
    try:
        row = db.one("SELECT id, name, email, pw_hash, notify FROM supervisors WHERE name = ?", (supervisor,))
    finally:
        db.close()
    if not row or not row["pw_hash"] or not check_password_hash(row["pw_hash"], password):
        return render_template("enroll.html", supervisors=supervisors,
                               holder=holder, number=request.form.get("number", ""),
                               supervisor=supervisor,
                               error="Supervisor name or password is not correct.")

    db = DB()
    try:
        db.run("INSERT INTO cards(holder, number, supervisor, created_at) VALUES(?, ?, ?, ?)",
               (holder, number, row["name"], now_iso()))
    finally:
        db.close()

    wants_mail = (str(row["notify"]) in ("1", "True", "true", "t"))
    if notify_enabled() and wants_mail and row["email"]:
        link = unsubscribe_link(row["id"])
        footer = notice_footer(link)
        send_email(row["email"], "New card holder added: " + holder,
                   "Hello %s,\n\n"
                   "A new card holder was added to the GateKeeperTC system under your name:\n\n"
                   "  Card holder: %s\n  Card number: %s\n  Added: %s (UTC)\n\n"
                   "The card will be picked up by the device automatically.\n\n"
                   "%s" % (row["name"], holder, number, now_iso(), footer))
    return render_template("done.html", holder=holder, supervisor=row["name"])


# ---------------------------------------------------------------------------
# Supervisor password reset + unsubscribe
# ---------------------------------------------------------------------------

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if not email_usable():
        return render_template("message.html", title="Email not set up",
                               body="Password resets by email are not set up on this site. "
                                    "Ask your GateKeeperTC administrator to reset your password.")
    if request.method == "GET":
        return render_template("forgot.html", sent=False)
    email_addr = (request.form.get("email") or "").strip().lower()
    if email_addr:
        db = DB()
        try:
            row = db.one("SELECT id, name FROM supervisors WHERE lower(email) = ?", (email_addr,))
            if row:
                token = secrets.token_urlsafe(32)
                expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                db.run("UPDATE supervisors SET reset_token = ?, reset_expiry = ? WHERE id = ?",
                       (token, expiry, row["id"]))
                link = site_url() + "/reset/" + token
                send_email(email_addr, "GateKeeperTC supervisor password reset",
                           "Hello %s,\n\n"
                           "Someone asked to reset your GateKeeperTC supervisor password.\n"
                           "Open this link in the next hour to choose a new password:\n  %s\n\n"
                           "If you did not ask for this, just ignore this email.\n"
                           % (row["name"], link))
        finally:
            db.close()
    return render_template("forgot.html", sent=True)


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset(token):
    db = DB()
    try:
        row = db.one("SELECT id, name, reset_expiry FROM supervisors WHERE reset_token = ?",
                     ((token or ""),))
    finally:
        db.close()
    expiry = parse_iso(row["reset_expiry"]) if row else None
    if not row or not expiry or expiry < datetime.now(timezone.utc):
        return render_template("message.html", title="Link expired",
                               body="This password reset link is wrong or has expired. "
                                    "Ask for a new one from the sign-in page."), 400
    if request.method == "GET":
        return render_template("reset.html", name=row["name"], error="")
    pw1 = request.form.get("password") or ""
    pw2 = request.form.get("password2") or ""
    if len(pw1) < 6:
        return render_template("reset.html", name=row["name"],
                               error="Password must be at least 6 characters.")
    if pw1 != pw2:
        return render_template("reset.html", name=row["name"],
                               error="The two passwords do not match.")
    db = DB()
    try:
        db.run("UPDATE supervisors SET pw_hash = ?, reset_token = '', reset_expiry = '' WHERE id = ?",
               (generate_password_hash(pw1), row["id"]))
    finally:
        db.close()
    return render_template("message.html", title="Password changed",
                           body="Your supervisor password was changed. You can use it on the "
                                "enrollment form now.")


@app.route("/unsubscribe/<int:sup_id>/<sig>")
def unsubscribe(sup_id, sig):
    if not env("ADMIN_KEY") or not hmac.compare_digest(sig or "", unsubscribe_sig(sup_id)):
        return render_template("message.html", title="Bad link",
                               body="This unsubscribe link is not valid."), 400
    db = DB()
    try:
        if db.pg:
            db.run("UPDATE supervisors SET notify = FALSE WHERE id = ?", (sup_id,))
        else:
            db.run("UPDATE supervisors SET notify = 0 WHERE id = ?", (sup_id,))
    finally:
        db.close()
    return render_template("message.html", title="Notifications off",
                           body="You will no longer get new-card emails. Your supervisor "
                                "login still works.")


# ---------------------------------------------------------------------------
# Device API (polled by the GateKeeperTC device over HTTPS)
# ---------------------------------------------------------------------------

@app.route("/api/cards")
def api_cards():
    if not env("DEVICE_KEY") or request.args.get("key", "") != env("DEVICE_KEY"):
        return jsonify(ok=False, error="bad key"), 403
    maybe_process_stop_replies()
    if not enrollment_enabled():
        return jsonify(ok=True, enabled=False, count=0, latest_id=0, cards=[])
    try:
        since = max(0, int(request.args.get("since", "0")))
    except ValueError:
        since = 0
    try:
        limit = min(200, max(1, int(request.args.get("limit", "100"))))
    except ValueError:
        limit = 100
    db = DB()
    try:
        rows = db.all("SELECT id, holder, number, supervisor, created_at FROM cards "
                      "WHERE id > ? ORDER BY id ASC LIMIT %d" % limit, (since,))
        latest = db.one("SELECT COALESCE(MAX(id), 0) AS m FROM cards")
    finally:
        db.close()
    cards = [{"id": r["id"], "holder": r["holder"] or "", "number": r["number"] or "",
              "supervisor": r["supervisor"] or "", "added": r["created_at"] or ""}
             for r in rows]
    return jsonify(ok=True, enabled=True, count=len(cards),
                   latest_id=latest["m"] if latest else 0, cards=cards)


# ---------------------------------------------------------------------------
# Admin API (used by the GKTC desktop app)
# ---------------------------------------------------------------------------

def admin_key_ok(data):
    key = (data.get("admin_key") or request.headers.get("X-API-Key") or "")
    return bool(env("ADMIN_KEY")) and hmac.compare_digest(key, env("ADMIN_KEY"))


@app.route("/api/admin/status")
def api_status():
    if not admin_key_ok(request.args):
        return jsonify(ok=False, error="bad key"), 403
    db = DB()
    try:
        sups = db.one("SELECT COUNT(*) AS n FROM supervisors")
        cards = db.one("SELECT COUNT(*) AS n FROM cards")
    finally:
        db.close()
    return jsonify(ok=True, supervisors=(sups["n"] if sups else 0),
                   cards=(cards["n"] if cards else 0),
                   notify_enabled=notify_enabled(),
                   enrollment_enabled=enrollment_enabled(),
                   email_provider=email_config()["provider"],
                   web_service=get_setting("web_service", "vercel"))


@app.route("/api/admin/sync", methods=["POST"])
def api_sync():
    data = request.get_json(force=True, silent=True) or {}
    if not admin_key_ok(data):
        return jsonify(ok=False, error="bad key"), 403
    if "notify_enabled" in data:
        set_setting("notify_enabled", "1" if data["notify_enabled"] else "0")
    if "enrollment_enabled" in data:
        set_setting("enrollment_enabled", "1" if data["enrollment_enabled"] else "0")
    if "web_service" in data:
        svc = str(data["web_service"] or "vercel").strip().lower() or "vercel"
        set_setting("web_service", svc)
    email_in = data.get("email") or {}
    if isinstance(email_in, dict) and email_in:
        prov = str(email_in.get("provider") or "").strip().lower()
        if prov in EMAIL_PROVIDERS:
            set_setting("email_provider", prov)
        for key in ("smtp_host", "smtp_port", "smtp_user", "smtp_pass", "from",
                    "imap_host", "imap_user", "imap_pass", "api_key"):
            if key in email_in:
                set_setting("email_" + key, str(email_in[key] or ""))
    incoming = data.get("supervisors") or []
    clean = []
    seen = set()
    for entry in incoming:
        name = str(entry.get("name") or "").strip()
        if not name or len(name) > 60 or name.lower() in seen:
            continue
        seen.add(name.lower())
        clean.append({
            "name": name,
            "email": str(entry.get("email") or "").strip()[:120],
            "password": str(entry.get("password") or ""),
        })
    db = DB()
    applied = 0
    try:
        existing = {r["name"].lower(): r for r in
                    db.all("SELECT id, name, email, pw_hash, notify FROM supervisors")}
        for sup in clean:
            old = existing.get(sup["name"].lower())
            pw_hash = old["pw_hash"] if old else ""
            if sup["password"]:
                pw_hash = generate_password_hash(sup["password"])
            elif not pw_hash:
                continue
            if old:
                db.run("UPDATE supervisors SET name = ?, email = ?, pw_hash = ?, updated_at = ? WHERE id = ?",
                       (sup["name"], sup["email"], pw_hash, now_iso(), old["id"]))
                applied += 1
            else:
                db.run("INSERT INTO supervisors(name, email, pw_hash, notify, updated_at) "
                       "VALUES(?, ?, ?, ?, ?)",
                       (sup["name"], sup["email"], pw_hash, 1 if not db.pg else True, now_iso()))
                applied += 1
        keep = set(s["name"].lower() for s in clean)
        for low_name, row in existing.items():
            if low_name not in keep:
                db.run("DELETE FROM supervisors WHERE id = ?", (row["id"],))
    finally:
        db.close()
    return jsonify(ok=True, supervisors=applied,
                   notify_enabled=notify_enabled(),
                   enrollment_enabled=enrollment_enabled())


def _test_step(steps, name, ok, detail=""):
    steps.append({"name": name, "ok": bool(ok), "detail": str(detail or "")})


def _email_cfg_with_override(email_in):
    """email_config() with GKTC form values layered on top (blank = default)."""
    cfg = email_config()
    if isinstance(email_in, dict) and email_in:
        prov = str(email_in.get("provider") or "").strip().lower()
        if prov in EMAIL_PROVIDERS:
            cfg["provider"] = prov
        for key in ("smtp_host", "smtp_port", "smtp_user", "smtp_pass",
                    "imap_host", "imap_user", "imap_pass", "api_key"):
            if email_in.get(key):
                cfg[key] = str(email_in[key])
        if email_in.get("from"):
            cfg["mail_from"] = str(email_in["from"])
    if not cfg["mail_from"]:
        cfg["mail_from"] = cfg["smtp_user"]
    if not cfg["imap_user"]:
        cfg["imap_user"] = cfg["smtp_user"]
    if not cfg["imap_pass"]:
        cfg["imap_pass"] = cfg["smtp_pass"]
    if cfg["provider"] == "gmail":
        cfg["smtp_host"] = cfg["smtp_host"] or "smtp.gmail.com"
        cfg["imap_host"] = cfg["imap_host"] or "imap.gmail.com"
    elif cfg["provider"] == "outlook":
        cfg["smtp_host"] = cfg["smtp_host"] or "smtp.office365.com"
        cfg["imap_host"] = cfg["imap_host"] or "outlook.office365.com"
    try:
        cfg["smtp_port"] = int(cfg["smtp_port"] or 587)
    except (TypeError, ValueError):
        cfg["smtp_port"] = 587
    return cfg


def _run_email_test(to_addr, cfg):
    """Try to send one test email, collecting a step log. Never raises."""
    steps = []
    prov = cfg["provider"]
    if prov == "none":
        _test_step(steps, "Config", False, "email provider is 'none' - nothing would be sent")
        return False, steps
    missing = []
    if prov in ("brevo", "sendgrid"):
        if not cfg["api_key"]:
            missing.append("API key")
        if not cfg["mail_from"]:
            missing.append("'Send emails from' address")
    else:
        if not cfg["smtp_host"]:
            missing.append("SMTP host")
        if not cfg["smtp_user"]:
            missing.append("SMTP username")
        if not cfg["smtp_pass"]:
            missing.append("SMTP password")
    if missing:
        _test_step(steps, "Config", False, "missing: " + ", ".join(missing))
        return False, steps
    _test_step(steps, "Config", True, "provider " + prov)
    if "@" not in (to_addr or ""):
        _test_step(steps, "Address", False, "enter a valid 'To' address")
        return False, steps
    _test_step(steps, "Address", True, to_addr)
    subject = "GateKeeperTC email test"
    body = ("This is a test from your GateKeeperTC website (%s).\n\n"
            "If you got this email, supervisor notifications will work.\n" % now_iso())
    if prov in ("gmail", "outlook", "smtp"):
        msg = EmailMessage()
        msg["From"] = cfg["mail_from"] or cfg["smtp_user"]
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        try:
            server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=10)
        except Exception as exc:
            _test_step(steps, "SMTP connect", False,
                       "%s:%s: %s" % (cfg["smtp_host"], cfg["smtp_port"], exc))
            return False, steps
        _test_step(steps, "SMTP connect", True,
                   "%s:%s" % (cfg["smtp_host"], cfg["smtp_port"]))
        try:
            try:
                server.starttls()
                _test_step(steps, "STARTTLS", True, "encrypted")
            except smtplib.SMTPNotSupportedError:
                _test_step(steps, "STARTTLS", True,
                           "server does not advertise STARTTLS, continuing plain")
            server.login(cfg["smtp_user"], cfg["smtp_pass"])
            _test_step(steps, "SMTP login", True, cfg["smtp_user"])
            server.send_message(msg)
            _test_step(steps, "Send", True, "test email accepted")
            try:
                server.quit()
            except Exception:
                pass
        except smtplib.SMTPAuthenticationError as exc:
            _test_step(steps, "SMTP login", False,
                       "rejected: %s (use an app password, not the account password)" % exc)
            return False, steps
        except Exception as exc:
            _test_step(steps, "Send", False, str(exc))
            return False, steps
        if cfg["imap_host"] and cfg["imap_user"] and cfg["imap_pass"]:
            try:
                box = imaplib.IMAP4_SSL(cfg["imap_host"], 993)
                box.login(cfg["imap_user"], cfg["imap_pass"])
                box.logout()
                _test_step(steps, "IMAP login (STOP replies, optional)", True, cfg["imap_host"])
            except Exception as exc:
                _test_step(steps, "IMAP login (STOP replies, optional)", False, str(exc))
        else:
            _test_step(steps, "IMAP login (STOP replies, optional)", False,
                       "not configured - STOP-by-reply off")
        return True, steps
    url = ("https://api.brevo.com/v3/smtp/email" if prov == "brevo"
           else "https://api.sendgrid.com/v3/mail/send")
    _test_step(steps, "API endpoint", True, url)
    try:
        if prov == "brevo":
            _post_json(url,
                       {"sender": {"email": cfg["mail_from"]}, "to": [{"email": to_addr}],
                        "subject": subject, "textContent": body},
                       {"api-key": cfg["api_key"], "Content-Type": "application/json"})
        else:
            _post_json(url,
                       {"personalizations": [{"to": [{"email": to_addr}]}],
                        "from": {"email": cfg["mail_from"]}, "subject": subject,
                        "content": [{"type": "text/plain", "value": body}]},
                       {"Authorization": "Bearer " + cfg["api_key"],
                        "Content-Type": "application/json"})
        _test_step(steps, "Send", True, "test email accepted")
    except Exception as exc:
        code = getattr(exc, "code", "")
        detail = ""
        if code:
            try:
                detail = exc.read().decode("utf-8", "replace")[:200]
            except Exception:
                detail = ""
        _test_step(steps, "Send", False,
                   ("HTTP %s %s" % (code, detail)).strip() or str(exc))
        return False, steps
    _test_step(steps, "IMAP login (STOP replies, optional)", False,
               "not available with API providers")
    return True, steps


@app.route("/api/admin/test-email", methods=["POST"])
def api_test_email():
    data = request.get_json(force=True, silent=True) or {}
    if not admin_key_ok(data):
        return jsonify(ok=False, error="bad key"), 403
    to_addr = str(data.get("to") or "").strip()
    try:
        cfg = _email_cfg_with_override(data.get("email"))
        ok, steps = _run_email_test(to_addr, cfg)
    except Exception as exc:
        return jsonify(ok=False, summary="Email test crashed: %s" % exc,
                       steps=[], provider="")
    summary = ("Email test passed - supervisor notifications will work."
               if ok else "Email test failed - see steps.")
    return jsonify(ok=ok, summary=summary, steps=steps, provider=cfg["provider"])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
