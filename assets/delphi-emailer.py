#!/usr/bin/env python3
"""
Delphi Emailer – event-driven via Postgres LISTEN/NOTIFY
"""

import os
import time
import select
import signal
import logging
import pytz
import psycopg2
import smtplib
import html as html_lib

from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from email.header import Header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ───── CONFIG ────────────────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN         = os.getenv("PG_DSN", "").strip()
if not PG_DSN:
    print("FATAL: PG_DSN is not set or empty", file=sys.stderr)
    sys.exit(1)

SMTP_HOST      = os.environ["MAILCOW_SMTP_HOST"]
SMTP_PORT      = int(os.environ.get("MAILCOW_SMTP_PORT", "587"))
SMTP_USER      = os.environ["MAILCOW_SMTP_USER"]
SMTP_PASS      = os.environ["MAILCOW_SMTP_PASS"]
FROM_ADDR      = os.environ["MAILCOW_FROM"]
TO_ADDR        = os.environ["MAILCOW_TO"]

TIMEZONE       = pytz.timezone("Australia/Perth")
LISTEN_CHANNEL = "new_summarized"

# ───── RETRY CONFIG ─────────────────────────────────────────
SMTP_RETRIES       = 3
SMTP_RETRY_DELAY   = 5   # seconds between retries

# ───── LOGGING ───────────────────────────────────────────────
logging.basicConfig(
    filename="/var/log/stackstorm/delphi-emailer.log",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("delphi-emailer")
log.info("Startup: PG_DSN=%r", PG_DSN[:50] + "…")  # mask the tail


# ───── DATABASE HELPERS ─────────────────────────────────────
def connect_db():
    try:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
        log.info("Connected to Postgres")
        return conn
    except psycopg2.ProgrammingError as e:
        log.error("Invalid PG_DSN (%r): %s", PG_DSN, e)
        sys.exit(1)
    except Exception as e:
        log.exception("Unexpected error connecting to DB")
        sys.exit(1)

def fetch_alert(conn, alert_id):
    sql = """
      SELECT
        id,
        prompt_text         AS summary,
        response_text       AS response,
        response_received_at,
        alert_hash,
        agent_id,
        rule_level
      FROM alerts
      WHERE id = %s
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        return cur.fetchone()

def fetch_unsent_alerts(conn):
    sql = """
      SELECT
        id,
        prompt_text         AS summary,
        response_text       AS response,
        response_received_at,
        alert_hash,
        agent_id,
        rule_level
      FROM alerts
      WHERE state = 'summarized'
        AND alert_sent_at IS NULL
      ORDER BY response_received_at
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        return cur.fetchall()

def mark_sent(conn, alert_id):
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE alerts SET alert_sent_at = NOW(), state = 'sent' WHERE id = %s",
            (alert_id,)
        )


# ───── SMTP SEND WITH SIMPLE RETRY ───────────────────────────
def send_email(subject: str, plain: str, html_body: str) -> bool:
    """
    Try up to SMTP_RETRIES to connect and send.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"]    = FROM_ADDR
    msg["To"]      = TO_ADDR
    msg.attach(MIMEText(plain, "plain", _charset="utf-8"))
    msg.attach(MIMEText(html_body, "html",   _charset="utf-8"))

    for attempt in range(1, SMTP_RETRIES + 1):
        try:
            log.debug("SMTP attempt %d/%d to %s:%d", attempt, SMTP_RETRIES, SMTP_HOST, SMTP_PORT)
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            log.info("Email sent: %r", subject)
            return True

        except smtplib.SMTPAuthenticationError as e:
            log.error("SMTP auth error (check credentials): %s", e)
            break  # no point retrying bad creds

        except Exception as e:
            log.warning("SMTP send failed on attempt %d: %s", attempt, e)
            if attempt < SMTP_RETRIES:
                time.sleep(SMTP_RETRY_DELAY)
            else:
                log.error("All SMTP attempts failed for: %r", subject)
    return False


# ───── EMAIL BUILDER ────────────────────────────────────────
def build_email(row: dict):
    """
    row: summary, response, response_received_at,
         alert_hash, agent_id, rule_level
    """
    sent_at = row["response_received_at"] \
                 .astimezone(TIMEZONE) \
                 .strftime("%A, %d %B %Y %I:%M %p AWST")

    clean_sum = " ".join(row["summary"].split())[:50]
    short_hash = row["alert_hash"][:8]
    subject = f"[Delphi Notify] {row['agent_id']} L{row['rule_level']} A{short_hash}: {clean_sum}"

    safe_body = html_lib.escape(row["response"])
    plain     = f"{row['response']}\n\nSent at {sent_at}\n"
    html      = f"<html><body><p>{safe_body}</p><p><em>Sent at {sent_at}</em></p></body></html>"

    return subject, plain, html


# ───── MAIN LOOP & SIGNALS ─────────────────────────────────
shutdown = False
def on_signal(signum, frame):
    global shutdown
    shutdown = True
    log.info("Shutdown requested (signal %d)", signum)

signal.signal(signal.SIGINT,  on_signal)
signal.signal(signal.SIGTERM, on_signal)


def catch_up(conn):
    rows = fetch_unsent_alerts(conn)
    log.info("Backlog: %d unsent alerts", len(rows))
    for row in rows:
        try:
            subject, plain, html = build_email(row)
            if send_email(subject, plain, html):
                mark_sent(conn, row["id"])
        except Exception as e:
            log.exception("Backlog: failed alert %s", row["id"])


def main():
    conn = connect_db()
    cur  = conn.cursor()
    catch_up(conn)

    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    log.info("Listening on channel %r", LISTEN_CHANNEL)

    while not shutdown:
        try:
            if select.select([conn], [], [], 5)[0]:
                conn.poll()
                for n in conn.notifies:
                    alert_id = int(n.payload)
                    log.info("Notify: new summarized alert %d", alert_id)
                    row = fetch_alert(conn, alert_id)
                    if row:
                        try:
                            subject, plain, html = build_email(row)
                            if send_email(subject, plain, html):
                                mark_sent(conn, alert_id)
                        except Exception as e:
                            log.exception("Failed sending alert %d", alert_id)
                    else:
                        log.warning("Alert %d not found in DB", alert_id)
                conn.notifies.clear()

        except psycopg2.OperationalError as e:
            log.exception("DB lost, reconnect in 5s: %s", e)
            time.sleep(5)
            conn = connect_db()
            cur  = conn.cursor()
            catch_up(conn)
            cur.execute(f"LISTEN {LISTEN_CHANNEL};")

        except Exception as e:
            log.exception("Main loop error, continuing: %s", e)

    log.info("Shutting down service")


if __name__ == "__main__":
    main()