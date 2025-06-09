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
import backoff
from email.header import Header
import html as html_lib

from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ───── CONFIG ────────────────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN          = os.environ["PG_DSN"]
SMTP_HOST       = os.environ["MAILCOW_SMTP_HOST"]
SMTP_PORT       = int(os.environ.get("MAILCOW_SMTP_PORT", "587"))
SMTP_USER       = os.environ["MAILCOW_SMTP_USER"]
SMTP_PASS       = os.environ["MAILCOW_SMTP_PASS"]
FROM_ADDR       = os.environ["MAILCOW_FROM"]
TO_ADDR         = os.environ["MAILCOW_TO"]
TIMEZONE        = pytz.timezone("Australia/Perth")
LISTEN_CHANNEL  = "new_summarized"

# ───── LOGGING ───────────────────────────────────────────────
logging.basicConfig(
    filename="/var/log/stackstorm/delphi-emailer.log",
    level=logging.DEBUG,                     # ← switch to DEBUG
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("delphi-emailer")


# ───── DATABASE HELPERS ─────────────────────────────────────
def connect_db():
    conn = psycopg2.connect(PG_DSN)
    conn.set_session(autocommit=True)
    return conn

def fetch_alert(conn, alert_id):
    sql = f"""
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
    sql = f"""
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


# ───── SMTP CONNECTION + RETRY ──────────────────────────────
_smtp: smtplib.SMTP = None

def get_smtp():
    global _smtp
    if _smtp:
        try:
            _smtp.noop()
            return _smtp
        except:
            log.warning("SMTP connection dropped; reconnecting")
            _smtp = None

    log.debug("Opening new SMTP connection to %s:%d", SMTP_HOST, SMTP_PORT)
    smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
    smtp.starttls()
    smtp.login(SMTP_USER, SMTP_PASS)
    _smtp = smtp
    return smtp

@backoff.on_exception(
    backoff.expo,
    (smtplib.SMTPException, ConnectionResetError),
    max_time=60,
    jitter=backoff.full_jitter
)
def send_email(subject: str, plain: str, html_body: str) -> bool:
    """
    Sends one email, retrying with exponential backoff on transient SMTP errors.
    """
    log.debug("Preparing to send email: %r", subject)
    # build MIME message
    msg = MIMEMultipart("alternative")
    # explicitly encode the subject in UTF-8
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"]    = FROM_ADDR
    msg["To"]      = TO_ADDR
    msg.attach(MIMEText(plain, "plain", _charset="utf-8"))
    msg.attach(MIMEText(html_body, "html", _charset="utf-8"))

    smtp = get_smtp()
    log.debug("Sending message via SMTP")
    smtp.send_message(msg)
    log.info("Email sent: %r", subject)
    return True


# ───── EMAIL BUILDER ────────────────────────────────────────
def build_email(row: dict):
    """
    row: summary, response, response_received_at,
         alert_hash, agent_id, rule_level
    """
    log.debug("Building email for alert %s", row["id"])
    sent_at = row["response_received_at"].astimezone(TIMEZONE) \
                  .strftime("%A, %d %B %Y %I:%M %p AWST")

    clean_summary = " ".join(row["summary"].split())[:50]
    h8            = row["alert_hash"][:8]
    subject       = (
        f"[Delphi Notify] {row['agent_id']} "
        f"L{row['rule_level']} A{h8}: {clean_summary}"
    )

    safe_resp = html_lib.escape(row["response"])
    plain     = f"{row['response']}\n\nSent at {sent_at}\n"
    html      = (
        f"<html><body>"
        f"<p>{safe_resp}</p>"
        f"<p><em>Sent at {sent_at}</em></p>"
        f"</body></html>"
    )
    return subject, plain, html


# ───── MAIN LOOP ────────────────────────────────────────────
shutdown = False
def on_signal(signum, frame):
    global shutdown
    shutdown = True
    log.info("Shutdown signal received, exiting…")

signal.signal(signal.SIGINT,  on_signal)
signal.signal(signal.SIGTERM, on_signal)


def catch_up(conn):
    rows = fetch_unsent_alerts(conn)
    log.info("Backlog catch-up: %d unsent", len(rows))
    for row in rows:
        try:
            subject, plain, html = build_email(row)
            send_email(subject, plain, html)
            mark_sent(conn, row["id"])
        except Exception as e:
            log.exception("Backlog: failed alert %s: %s", row["id"], e)


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
                for notify in conn.notifies:
                    alert_id = int(notify.payload)
                    log.info("Notification received: %s", alert_id)
                    row = fetch_alert(conn, alert_id)
                    if row:
                        try:
                            subject, plain, html = build_email(row)
                            send_email(subject, plain, html)
                            mark_sent(conn, alert_id)
                        except Exception as e:
                            log.exception("Failed sending alert %s: %s", alert_id, e)
                    else:
                        log.warning("Alert %s not found", alert_id)
                conn.notifies.clear()
        except psycopg2.OperationalError as e:
            log.exception("DB connection lost, reconnecting in 5s: %s", e)
            time.sleep(5)
            conn = connect_db()
            cur  = conn.cursor()
            catch_up(conn)
            cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        except Exception as e:
            log.exception("Unexpected loop error: %s", e)

    log.info("Shutting down SMTP (if open)")
    if _smtp:
        try: _smtp.quit()
        except: pass

if __name__ == "__main__":
    main()