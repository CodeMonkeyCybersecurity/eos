#!/usr/bin/env python3
# /usr/local/bin/delphi-emailer.py
# stanley:stanley 0750
"""
Delphi Emailer – event-driven via Postgres LISTEN/NOTIFY
"""
import os, sys, re, time, select, signal, logging, pytz, psycopg2, smtplib
import json # ADDED: Import json for handling agent_data_json
import html as html_lib
from datetime import datetime, timezone # ADDED: Explicitly import datetime and timezone
from logging.handlers import RotatingFileHandler
from string import Template
from typing import Tuple, Dict, List, Union # ADDED: Union for type hints
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
LISTEN_CHANNEL  = "new_response"
SMTP_RETRIES    = 3
SMTP_RETRY_DELAY= 5  # seconds

# ───── 2. LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configure a rotating file logger and return it."""
    logger = logging.getLogger("delphi-emailer")
    logger.setLevel(logging.DEBUG) # Changed to DEBUG to see detailed logs

    handler = RotatingFileHandler(
        "/var/log/stackstorm/delphi-emailer.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    # Add a stream handler for real-time console output during debugging
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

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
    """
    Fetches alerts that are 'summarized' but not yet sent,
    including the full agent API response for enrichment.
    """
    sql = """
      SELECT
        a.id,
        a.prompt_text         AS summary,
        a.response_text       AS response,
        a.response_received_at,
        a.alert_hash,
        a.agent_id,
        a.rule_level,
        ag.api_response AS agent_details_from_db -- ADDED: Retrieve full agent details
      FROM alerts a
      JOIN agents ag ON ag.id = a.agent_id
     WHERE a.state='summarized'
       AND a.alert_sent_at IS NULL
  ORDER BY a.response_received_at
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        return cur.fetchall()

def fetch_alert(conn, alert_id: int) -> Union[Dict, None]: # MODIFIED return type
    """
    Fetches a single alert by ID, including its associated agent details.
    """
    sql = """
        SELECT
            a.id,
            a.agent_id,
            a.prompt_text AS summary,
            a.response_text AS response,
            a.response_received_at,
            a.alert_hash,
            a.rule_level,
            ag.api_response AS agent_details_from_db -- ADDED: Retrieve full agent details
        FROM alerts a
        JOIN agents ag ON ag.id = a.agent_id
        WHERE a.id = %s
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        return cur.fetchone() # returns None if not found

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
    """
    Build the email subject line using agent name/ID, OS, and rule level.
    e.g., "[Delphi Notify] vm-server1 (Ubuntu 20.04) Level 7"
    """
    log.debug(f"Row received in format_subject: {row}") # DEBUG LOG
    
    agent_name = row.get('agent_id', 'Unknown Agent') # Fallback to agent ID
    os_info = "Unknown OS"
    
    agent_details = row.get('agent_details_from_db')
    log.debug(f"agent_details_from_db in format_subject: {agent_details}") # DEBUG LOG

    if agent_details and isinstance(agent_details, dict):
        if agent_details.get('name'):
            agent_name = agent_details['name']
            log.debug(f"Found agent name: {agent_name}") # DEBUG LOG
        else:
            log.debug("Agent name not found in agent_details, falling back to agent_id.") # DEBUG LOG

        os_data = agent_details.get('os')
        log.debug(f"OS data from agent_details: {os_data}") # DEBUG LOG
        
        if os_data and isinstance(os_data, dict):
            os_name = os_data.get('name', '').strip() # Ensure stripping
            os_version = os_data.get('version', '').strip() # Ensure stripping
            os_arch = os_data.get('arch', '').strip() # Get architecture too

            os_parts = [os_name]
            if os_version:
                os_parts.append(os_version)
            if os_arch:
                os_parts.append(f"({os_arch})")
            
            os_info = " ".join(filter(None, os_parts)).strip() # Join non-empty parts
            if not os_info:
                os_info = "Unknown OS" # Final fallback if all parts are empty
            log.debug(f"Formatted OS info: {os_info}") # DEBUG LOG
        else:
            log.debug("OS data not found or not a dictionary in agent_details, falling back to 'Unknown OS'.") # DEBUG LOG
    else:
        log.debug("agent_details_from_db is not a dictionary or is missing, using default agent_id and 'Unknown OS'.") # DEBUG LOG

    return f"[Delphi Notify] {agent_name} ({os_info}) Level {row['rule_level']}"


def split_sections(text: str) -> Dict[str,str]:
    """
    Parses the LLM’s single-string response into a dict:
      { "What happened": "...", "Further investigation": "...", "What to do": "...", "How to check": "..." }
    """
    # split on those exact headings (including the colon)
    parts = re.split(r'(What happened:|Further investigation:|What to do:|How to check:)', text)
    # parts will be: ["", "What happened:", " ...", "Further investigation:", "...", "How to check:", "...", ...]
    out = {}
    for i in range(1, len(parts), 2):
        key   = parts[i].rstrip(':')
        value = parts[i+1].strip()
        out[key] = value
    return out

def build_agent_details_html(agent_details: Dict) -> str:
    """
    Builds an HTML block for agent details from the api_response JSON.
    """
    if not agent_details:
        return "<p>No detailed agent information available.</p>"

    html_parts = []
    html_parts.append(f"<h2>Agent Details:</h2>")
    html_parts.append("<ul>")

    # Basic info directly from agent_details (which is api_response)
    if agent_details.get('name'):
        html_parts.append(f"<li><strong>Agent Name:</strong> {html_lib.escape(agent_details['name'])}</li>")
    if agent_details.get('id'):
        html_parts.append(f"<li><strong>Agent ID:</strong> {html_lib.escape(agent_details['id'])}</li>")
    if agent_details.get('ip'):
        html_parts.append(f"<li><strong>IP Address:</strong> {html_lib.escape(agent_details['ip'])}</li>")
    if agent_details.get('version'):
        html_parts.append(f"<li><strong>Wazuh Version:</strong> {html_lib.escape(agent_details['version'])}</li>")
    if agent_details.get('status'):
        html_parts.append(f"<li><strong>Status:</strong> {html_lib.escape(agent_details['status'])}</li>")

    # OS details (nested dictionary)
    os_info = agent_details.get('os')
    if os_info and isinstance(os_info, dict):
        os_display = f"{os_info.get('name', '')} {os_info.get('version', '')} ({os_info.get('arch', '')})".strip()
        if os_display:
            html_parts.append(f"<li><strong>Operating System:</strong> {html_lib.escape(os_display)}</li>")

    # Timestamps
    if agent_details.get('dateAdd'):
        try:
            registered_at = datetime.fromisoformat(agent_details['dateAdd'].replace('Z', '+00:00')).astimezone(TIMEZONE)
            html_parts.append(f"<li><strong>Registered:</strong> {registered_at.strftime('%Y-%m-%d %H:%M:%S %Z%z')}</li>")
        except ValueError:
            log.warning(f"Could not parse agent dateAdd: {agent_details['dateAdd']}")
    if agent_details.get('lastKeepAlive'):
        try:
            if agent_details['lastKeepAlive'].startswith("9999"): # Handle special "never expires" timestamp
                last_seen = "Never (future timestamp)"
            else:
                last_seen = datetime.fromisoformat(agent_details['lastKeepAlive'].replace('Z', '+00:00')).astimezone(TIMEZONE).strftime('%Y-%m-%d %H:%M:%S %Z%z')
            html_parts.append(f"<li><strong>Last Seen:</strong> {last_seen}</li>")
        except ValueError:
            log.warning(f"Could not parse agent lastKeepAlive: {agent_details['lastKeepAlive']}")
    if agent_details.get('disconnection_time'):
        try:
            disconnection_time = datetime.fromisoformat(agent_details['disconnection_time'].replace('Z', '+00:00')).astimezone(TIMEZONE)
            html_parts.append(f"<li><strong>Disconnected:</strong> {disconnection_time.strftime('%Y-%m-%d %H:%M:%S %Z%z')}</li>")
        except ValueError:
            log.warning(f"Could not parse agent disconnection_time: {agent_details['disconnection_time']}")

    # Other relevant fields
    if agent_details.get('manager'):
        html_parts.append(f"<li><strong>Manager:</strong> {html_lib.escape(agent_details['manager'])}</li>")
    if agent_details.get('group') and isinstance(agent_details['group'], list):
        groups_str = ", ".join([html_lib.escape(g) for g in agent_details['group']])
        html_parts.append(f"<li><strong>Groups:</strong> {groups_str}</li>")

    html_parts.append("</ul>")
    return "\n".join(html_parts)


def build_body_html(response: str, agent_details: Dict) -> str: # MODIFIED: Added agent_details
    """
    Renders LLM response sections and agent details as HTML.
    """
    secs = split_sections(response)
    html_blocks = []

    # Add LLM analysis sections
    for heading in ("What happened", "Further investigation", "What to do", "How to check"):
        content = secs.get(heading, "")
        # make each paragraph
        paras = "".join(f"<p>{html_lib.escape(p)}</p>"
                        for p in content.split("\n\n") if p)
        if paras: # Only add heading if there's content
            html_blocks.append(f"<h2>{heading}:</h2>{paras}")
    
    # Add Agent Details section
    agent_details_html = build_agent_details_html(agent_details)
    html_blocks.append(agent_details_html)

    return "\n".join(html_blocks)


def build_email(row: Dict) -> Tuple[str, str, str]:
    """
    Builds the complete email content (subject, plain text, HTML)
    using the alert data and enriched agent details.
    """
    sent_at = row["response_received_at"] \
                 .astimezone(TIMEZONE) \
                 .strftime("%A, %d %B %Y %I:%M %p AWST")

    subject   = format_subject(row) # Now uses agent_details implicitly through row
    
    # Pass agent_details_from_db to build_body_html
    body_html_content = build_body_html(row["response"], row.get('agent_details_from_db', {}))

    alert_id_short = row["alert_hash"][:8] # Shortened ID for email readability

    # The HTML template expects 'body', 'subject', 'sent_at', 'alert_id', 'support_email'
    html_body = email_tpl.safe_substitute(
        subject=html_lib.escape(subject), # Escape subject for HTML email
        sent_at=html_lib.escape(sent_at),
        alert_id=html_lib.escape(alert_id_short),
        body=body_html_content, # This is already HTML formatted
        support_email=html_lib.escape(SUPPORT_EMAIL)
    )

    # Building plain text version (simplified for brevity, but could be expanded)
    plain_text_parts = [
        f"Subject: {subject}",
        f"Alert ID: {alert_id_short}",
        f"Sent at: {sent_at}",
        "\n--- LLM Summary ---\n",
        row['response'], # Raw LLM response here
        "\n--- Agent Details ---\n"
    ]

    agent_details_from_db = row.get('agent_details_from_db', {})
    if agent_details_from_db:
        if agent_details_from_db.get('name'):
            plain_text_parts.append(f"Agent Name: {agent_details_from_db['name']}")
        if agent_details_from_db.get('id'):
            plain_text_parts.append(f"Agent ID: {agent_details_from_db['id']}")
        if agent_details_from_db.get('ip'):
            plain_text_parts.append(f"IP Address: {agent_details_from_db['ip']}")
        if agent_details_from_db.get('os') and isinstance(agent_details_from_db['os'], dict):
            os_display = f"{agent_details_from_db['os'].get('name', '')} {agent_details_from_db['os'].get('version', '')}".strip()
            if os_display:
                plain_text_parts.append(f"OS: {os_display}")
        if agent_details_from_db.get('status'):
            plain_text_parts.append(f"Status: {agent_details_from_db['status']}")
        if agent_details_from_db.get('group') and isinstance(agent_details_from_db['group'], list):
            groups_str = ", ".join([html_lib.escape(g) for g in agent_details_from_db['group']])
            plain_text_parts.append(f"Groups: {groups_str}")
        # Add more agent fields as needed for plain text
    else:
        plain_text_parts.append("No detailed agent information available.")
    
    plain_text = "\n".join(plain_text_parts)

    return subject, plain_text, html_body

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
            # Wait for notifications
            if not select.select([conn], [], [], 5)[0]:
                continue  # Timeout, loop again

            conn.poll()
            
            # Process each notification individually
            for notify in conn.notifies:
                try:
                    alert_id = int(notify.payload)
                    log.info("Got notify for alert %d", alert_id)
                    
                    row = fetch_alert(conn, alert_id)
                    if not row:
                        log.warning("Alert %d not found, skipping.", alert_id)
                        continue

                    # The `row` dictionary now contains `agent_details_from_db`
                    subj, plain, html = build_email(row)
                    if send_email(subj, plain, html):
                        mark_sent(conn, alert_id)
                        
                except Exception as e:
                    # Log the error for this specific alert but DON'T crash
                    log.exception("Failed to process alert from payload %r: %s", notify.payload, e)

            # Clear the notification list after processing all of them
            conn.notifies.clear()

        except psycopg2.OperationalError:
            log.exception("DB connection lost; reconnecting in 5s")
            time.sleep(5)
            # Re-establish connection and listener
            conn = connect_db()
            cur = conn.cursor()
            cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        except Exception:
            # A serious error outside of alert processing happened
            log.exception("Unexpected error in main loop; aborting")
            raise

    log.info("Exiting.")

if __name__ == "__main__":
    main()
