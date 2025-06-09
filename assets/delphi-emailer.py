#!/usr/bin/env python3
# /usr/local/bin/delphi-emailer.py
# 750 stanley:stanley 
"""
Delphi Emailer – event‐driven via Postgres LISTEN/NOTIFY
"""

import os, time, select, signal, logging, pytz, psycopg2, smtplib
import html as html_lib


from datetime import datetime
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.message import EmailMessage

# ───── CONFIG ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN     = os.environ["PG_DSN"]
SMTP_HOST  = os.environ["MAILCOW_SMTP_HOST"]
SMTP_PORT  = int(os.environ.get("MAILCOW_SMTP_PORT", "587"))
SMTP_USER  = os.environ["MAILCOW_SMTP_USER"]
SMTP_PASS  = os.environ["MAILCOW_SMTP_PASS"]
FROM_ADDR  = os.environ["MAILCOW_FROM"]
TO_ADDR    = os.environ["MAILCOW_TO"]
TIMEZONE   = pytz.timezone("Australia/Perth")
MAX_PER_MIN = 60  # maximum emails per rolling minute

# ───── LOGGING ─────
logging.basicConfig(
    filename="/var/log/stackstorm/delphi-emailer.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("delphi-emailer")


# ───── DATABASE HELPERS ─────
def connect_db():
    """Establish a fresh DB connection with autocommit."""
    conn = psycopg2.connect(PG_DSN)
    conn.set_session(autocommit=True)
    return conn

def fetch_alert(conn, alert_id):
    sql = """
      SELECT
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

def mark_sent(conn, alert_id):
    sql = "UPDATE alerts SET alert_sent_at = NOW(), state = 'sent' WHERE id = %s"
    with conn.cursor() as cur:
        cur.execute(sql, (alert_id,))

# ───── EMAIL BUILD / SEND ─────
def build_email(row):
    """
    row: dict with keys summary, response, response_received_at,
         alert_hash, agent_id, rule_level
    """
    summary     = row["summary"]
    response    = row["response"]
    timestamp   = row["response_received_at"]
    alert_hash  = row["alert_hash"]
    agent_id    = row["agent_id"]
    severity    = row["rule_level"]
    sent_at       = timestamp.astimezone(TIMEZONE).strftime("%A, %d %B %Y %I:%M %p AWST")
    clean_summary = " ".join(summary.split())[:50]
    h8            = alert_hash[:8]
    subject       = (
        f"[Delphi Notify] {agent_id}  L{severity}  A{h8}: {clean_summary}"
    )

    # sanitize response for HTML
    safe_resp = html_lib.escape(response)
    plain   = f"{response}\n\nSent at {sent_at}\n"
    html    = (
        f"<html><body>"
        f"<p>{safe_resp}</p>"
        f"<p><em>Sent at {sent_at}</em></p>"
        f"</body></html>"
    )
    return subject, plain, html

def send_email(subject, plain, html_body):

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = FROM_ADDR
    msg["To"]      = TO_ADDR
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        sent_timestamps.append(time.time())
        log.info(f"Email sent: {subject!r}")
        return True
    except Exception:
        log.exception("Failed to send email")
        return False

# ───── SHUTDOWN HANDLING ─────
shutdown = False
def on_signal(signum, frame):
    global shutdown
    shutdown = True
    log.info("Shutdown signal received, exiting…")

signal.signal(signal.SIGINT,  on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ───── CATCH-UP HELPERS ─────
def fetch_unsent_alerts(conn):
    sql = """
      SELECT id,
             prompt_text   AS summary,
             response_text AS response,
             response_received_at
        FROM alerts
       WHERE state = 'summarized'
         AND alert_sent_at IS NULL
       ORDER BY response_received_at
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        return cur.fetchall()

def catch_up(conn):
    rows = fetch_unsent_alerts(conn)
    log.info(f"Backlog catch-up: {len(rows)} unsent alerts")
    for row in rows:
        subj, plain, html = build_email(row)
        if send_email(subj, plain, html):
            mark_sent(conn, row["id"])
        else:
            log.warning(f"Failed to send backlog email for alert {row['id']}")

# ───── MAIN LOOP ─────
def main():
    conn = connect_db()
    cur  = conn.cursor()

    # 1) on startup do a backlog catch-up
    catch_up(conn)

    # 2) then switch to LISTEN mode
    cur.execute("LISTEN new_summarized;")
    log.info("Listening for new_summarized notifications…")

    while not shutdown:
        try:
            # block until a notification arrives or timeout to check for shutdown
            if select.select([conn], [], [], 5)[0]:
                conn.poll()
                for notify in conn.notifies:
                    alert_id = int(notify.payload)
                    log.info(f"Received new_summarized for alert {alert_id}")
                    row = fetch_alert(conn, alert_id)
                    if row:
                        subj, plain, html = build_email(row)
                        if send_email(subj, plain, html):
                            mark_sent(conn, alert_id)
                    else:
                        log.warning(f"Alert {alert_id} not found in DB")
                # clear out all notifications
                conn.notifies.clear()
        except psycopg2.OperationalError:
            log.exception("DB connection lost; reconnecting in 5s")
            time.sleep(5)
            conn = connect_db()
            cur  = conn.cursor()
            # after reconnect, re-subscribe and re-catch any missed alerts
            catch_up(conn)
            cur.execute("LISTEN new_summarized;")
        except Exception:
            log.exception("Unexpected error in main loop")
    log.info("Delphi Emailer shutting down")

if __name__ == "__main__":
    main()