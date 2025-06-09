#!/usr/bin/env python3
# /usr/local/bin/delphi-emailer.py
# stanley:stanley 0750
"""
Delphi Emailer – event-driven via Postgres LISTEN/NOTIFY
"""
import os
import sys
import time
import select
import signal
import logging
from logging.handlers import RotatingFileHandler
import pytz
import psycopg2
import smtplib
import html as html_lib

from string import Template
from typing import Tuple, Dict, List
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from email.header import Header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ───── 1. CONFIGURATION & ENV VALIDATION ───────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")

REQUIRED_ENV = [
    "PG_DSN",
    "MAILCOW_SMTP_HOST", "MAILCOW_SMTP_PORT",
    "MAILCOW_SMTP_USER", "MAILCOW_SMTP_PASS",
    "MAILCOW_FROM", "MAILCOW_TO",
    "SUPPORT_EMAIL",
]

_missing = [var for var in REQUIRED_ENV if not os.getenv(var)]
if _missing:
    print(f"FATAL: Missing environment variables: {', '.join(_missing)}", file=sys.stderr)
    sys.exit(1)

PG_DSN        = os.getenv("PG_DSN").strip()
SMTP_HOST     = os.getenv("MAILCOW_SMTP_HOST")
SMTP_PORT     = int(os.getenv("MAILCOW_SMTP_PORT"))
SMTP_USER     = os.getenv("MAILCOW_SMTP_USER")
SMTP_PASS     = os.getenv("MAILCOW_SMTP_PASS")
FROM_ADDR     = os.getenv("MAILCOW_FROM")
TO_ADDR       = os.getenv("MAILCOW_TO")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL")

TIMEZONE        = pytz.timezone("Australia/Perth")
LISTEN_CHANNEL  = "new_summarized"
SMTP_RETRIES    = 3
SMTP_RETRY_DELAY= 5  # seconds

# ───── 2. LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configure a rotating file logger and return it."""
    logger = logging.getLogger("delphi-emailer")
    logger.setLevel(logging.DEBUG)

    handler = RotatingFileHandler(
        "/var/log/stackstorm/delphi-emailer.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    logger.info("Logger initialized; listening on %r", LISTEN_CHANNEL)
    return logger

log = setup_logging()

# ───── 3. TEMPLATE LOADING ──────────────────────────────────
TEMPLATE_PATH = "/opt/stackstorm/packs/delphi/email.html"
try:
    with open(TEMPLATE_PATH, encoding="utf-8") as f:
        email_tpl = Template(f.read())
except Exception as e:
    log.error("Failed to load template %r: %s", TEMPLATE_PATH, e)
    sys.exit(1)

# ───── 4. DATABASE HELPERS ─────────────────────────────────
def connect_db() -> psycopg2.extensions.connection:
    """Connect to Postgres and return the connection (auto-commit on)."""
    try:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
        log.info("Connected to Postgres")
        return conn
    except Exception as e:
        log.exception("Could not connect to Postgres")
        sys.exit(1)

def fetch_unsent_alerts(conn) -> List[Dict]:
    """Fetch all alerts in 'summarized' but not yet sent."""
    sql = """
      SELECT id, prompt_text AS summary,
             response_text AS response,
             response_received_at,
             alert_hash, agent_id, rule_level
      FROM alerts
     WHERE state='summarized' AND alert_sent_at IS NULL
  ORDER BY response_received_at
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        return cur.fetchall()

def fetch_alert(conn, alert_id: int) -> Dict:
    """Fetch a single alert by ID."""
    sql = """
      SELECT id, prompt_text AS summary,
             response_text AS response,
             response_received_at,
             alert_hash, agent_id, rule_level
      FROM alerts WHERE id = %s
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        return cur.fetchone() or {}

def mark_sent(conn, alert_id: int) -> None:
    """Mark the given alert as sent in the DB."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET alert_sent_at=NOW(), state='sent' WHERE id=%s",
            (alert_id,)
        )
    log.debug("Marked alert %d as sent", alert_id)

# ───── 5. EMAIL FORMATTING HELPERS ─────────────────────────
def format_subject(row: Dict) -> str:
    """Build the email subject line."""
    summary = " ".join(row["summary"].split())[:50]
    suffix  = row["alert_hash"][:8]
    return f"[Delphi Notify] {row['agent_id']} L{row['rule_level']} A{suffix}: {summary}"

def format_plain(response: str, sent_at: str) -> str:
    """Create the plain-text email body."""
    return f"{response}\n\nSent at {sent_at}\n"

def format_html(response: str, subject: str, sent_at: str) -> str:
    """Substitute placeholders in the HTML template."""
    escaped = html_lib.escape(response).strip()
    paras   = "".join(f"<p>{p}</p>" for p in escaped.split("\n\n"))
    return email_tpl.safe_substitute(
        subject=subject,
        sent_at=sent_at,
        body=paras,
        support_email=SUPPORT_EMAIL
    )

def build_email(row: Dict) -> Tuple[str, str, str]:
    """Return (subject, plain_text, html_body) for a given DB row."""
    sent_at = row["response_received_at"].astimezone(TIMEZONE) \
                             .strftime("%A, %d %B %Y %I:%M %p AWST")

    subject   = format_subject(row)
    plain_txt = format_plain(row["response"], sent_at)
    html_body = format_html(row["response"], subject, sent_at)
    return subject, plain_txt, html_body

# ───── 6. SMTP SENDER ──────────────────────────────────────
def send_email(subject: str, plain: str, html_body: str) -> bool:
    """Attempt to send an email, retrying on failure."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"]    = FROM_ADDR
    msg["To"]      = TO_ADDR
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html",  "utf-8"))

    for attempt in range(1, SMTP_RETRIES + 1):
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
                s.starttls()
                s.login(SMTP_USER, SMTP_PASS)
                s.send_message(msg)
            log.info("Email sent: %r", subject)
            return True
        except smtplib.SMTPAuthenticationError as e:
            log.error("SMTP auth error: %s", e)
            break
        except Exception as e:
            log.warning("SMTP attempt %d failed: %s", attempt, e)
            time.sleep(SMTP_RETRY_DELAY)

    log.error("All SMTP attempts failed for: %r", subject)
    return False

# ───── 7. MAIN LOOP & SIGNALS ─────────────────────────────
shutdown = False

def on_signal(signum, frame):
    """Handle clean shutdown on SIGINT/SIGTERM."""
    global shutdown
    shutdown = True
    log.info("Signal %d received; shutting down", signum)

signal.signal(signal.SIGINT,  on_signal)
signal.signal(signal.SIGTERM, on_signal)

def catch_up(conn):
    """Send any alerts that were summarized before startup."""
    rows = fetch_unsent_alerts(conn)
    log.info("Backlog of %d unsent alerts", len(rows))
    for row in rows:
        subject, plain, html = build_email(row)
        if send_email(subject, plain, html):
            mark_sent(conn, row["id"])

def main():
    conn = connect_db()
    catch_up(conn)

    cur = conn.cursor()
    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    log.info("Listening on channel %r", LISTEN_CHANNEL)

    while not shutdown:
        try:
            if select.select([conn], [], [], 5)[0]:
                conn.poll()
                for notify in conn.notifies:
                    alert_id = int(notify.payload)
                    log.info("Got notify for alert %d", alert_id)
                    row = fetch_alert(conn, alert_id)
                    if not row:
                        log.warning("Alert %d not found", alert_id)
                    else:
                        subj, plain, html = build_email(row)
                        if send_email(subj, plain, html):
                            mark_sent(conn, alert_id)
                conn.notifies.clear()

        except psycopg2.OperationalError:
            log.exception("DB lost; reconnecting in 5s")
            time.sleep(5)
            conn = connect_db()
            cur  = conn.cursor()
            cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        except Exception:
            log.exception("Unexpected error in main loop; continuing")

    log.info("Exiting.")

if __name__ == "__main__":
    main()