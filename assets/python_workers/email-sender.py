#!/usr/bin/env python3
# /usr/local/bin/email-sender.py
# stanley:stanley 0750
"""
Email Sender Worker - Sends formatted emails via SMTP
"""
import os
import sys
import time
import select
import signal
import logging
import json
import smtplib
import psycopg2
import psycopg2.extensions
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional, List
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*_a, **_kw): pass

try:
    from psycopg2.extras import RealDictCursor
except ImportError:
    logging.error("Required dependency 'psycopg2' not found.")
    sys.exit(1)

# ───── CONFIGURATION ─────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")

REQUIRED_ENV = ["PG_DSN", "SMTP_HOST", "SMTP_PORT", "FROM_EMAIL"]
_missing = [var for var in REQUIRED_ENV if not os.getenv(var)]
if _missing:
    print(f"FATAL: Missing environment variables: {', '.join(_missing)}", file=sys.stderr)
    sys.exit(1)

PG_DSN = os.getenv("PG_DSN", "").strip()
LISTEN_CHANNEL = "alert_formatted"     # Channel for alerts needing sending

# SMTP Configuration
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"
FROM_EMAIL = os.getenv("FROM_EMAIL")
DEFAULT_TO_EMAIL = os.getenv("DEFAULT_TO_EMAIL", "")

# Email configuration
MAX_RECIPIENTS = int(os.getenv("MAX_RECIPIENTS", "10"))
RETRY_ATTEMPTS = int(os.getenv("EMAIL_RETRY_ATTEMPTS", "3"))
RETRY_DELAY = int(os.getenv("EMAIL_RETRY_DELAY", "60"))

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    logger = logging.getLogger("email-sender")
    logger.setLevel(logging.INFO)
    
    handler = RotatingFileHandler(
        "/var/log/stackstorm/email-sender.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3
    )
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    
    if sys.stdout.isatty():
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(fmt)
        logger.addHandler(console)
    
    return logger

log = setup_logging()

# ───── EMAIL SENDER CLASS ─────────────────────────────────
class EmailSender:
    """Handles SMTP email delivery"""
    
    def __init__(self):
        self.smtp_host = SMTP_HOST
        self.smtp_port = SMTP_PORT
        self.smtp_user = SMTP_USER
        self.smtp_pass = SMTP_PASS
        self.smtp_tls = SMTP_TLS
        self.from_email = FROM_EMAIL
        self.max_recipients = MAX_RECIPIENTS
    
    def send_email(self, to_emails: List[str], subject: str, 
                   html_body: str, plain_body: str = None,
                   reply_to: str = None) -> bool:
        """
        Send email via SMTP
        
        Args:
            to_emails: List of recipient email addresses
            subject: Email subject
            html_body: HTML email body
            plain_body: Plain text email body (optional)
            reply_to: Reply-to address (optional)
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not to_emails:
            log.warning("No recipients specified")
            return False
        
        # Limit recipients to prevent abuse
        if len(to_emails) > self.max_recipients:
            log.warning("Too many recipients (%d), limiting to %d", 
                       len(to_emails), self.max_recipients)
            to_emails = to_emails[:self.max_recipients]
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_email
            msg['To'] = ', '.join(to_emails)
            
            if reply_to:
                msg['Reply-To'] = reply_to
            
            # Add plain text part
            if plain_body:
                text_part = MIMEText(plain_body, 'plain', 'utf-8')
                msg.attach(text_part)
            
            # Add HTML part
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)
            
            # Connect to SMTP server
            log.info("Connecting to SMTP server %s:%d", self.smtp_host, self.smtp_port)
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_tls:
                    server.starttls()
                
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                
                # Send email
                server.send_message(msg, to_addrs=to_emails)
                
            log.info("Email sent successfully to %d recipients", len(to_emails))
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            log.error("SMTP authentication failed: %s", e)
            return False
        except smtplib.SMTPRecipientsRefused as e:
            log.error("SMTP recipients refused: %s", e)
            return False
        except smtplib.SMTPException as e:
            log.error("SMTP error: %s", e)
            return False
        except Exception as e:
            log.exception("Unexpected error sending email: %s", e)
            return False
    
    def test_connection(self) -> bool:
        """Test SMTP connection"""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_tls:
                    server.starttls()
                
                if self.smtp_user and self.smtp_pass:
                    server.login(self.smtp_user, self.smtp_pass)
                
            log.info("SMTP connection test successful")
            return True
        except Exception as e:
            log.error("SMTP connection test failed: %s", e)
            return False


# ───── DATABASE FUNCTIONS ─────────────────────────────────
def connect_db() -> psycopg2.extensions.connection:
    """Connect to Postgres with auto-commit enabled"""
    try:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
        log.info("Connected to Postgres")
        return conn
    except Exception:
        log.exception("Could not connect to Postgres")
        sys.exit(1)


def fetch_alert_to_send(conn, alert_id: int) -> Optional[Dict]:
    """Fetch an alert that needs email sending"""
    sql = """
        SELECT
            a.id,
            a.formatted_data,
            a.formatted_at,
            a.rule_level,
            a.alert_hash,
            ag.api_response AS agent_details
        FROM alerts a
        JOIN agents ag ON ag.id = a.agent_id
        WHERE a.id = %s AND a.state = 'formatted'
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        row = cur.fetchone()
        
        if row and row.get('formatted_data'):
            if isinstance(row['formatted_data'], str):
                try:
                    row['formatted_data'] = json.loads(row['formatted_data'])
                except json.JSONDecodeError:
                    log.warning("Failed to parse formatted_data JSON for alert %d", alert_id)
                    row['formatted_data'] = {}
        
        return row


def get_email_recipients(conn, alert_data: Dict[str, Any]) -> List[str]:
    """Determine email recipients based on alert and configuration"""
    recipients = []
    
    # Add default recipient if configured
    if DEFAULT_TO_EMAIL:
        recipients.append(DEFAULT_TO_EMAIL)
    
    # You can add more sophisticated recipient logic here:
    # - Based on rule level
    # - Based on agent groups
    # - From a recipients table in the database
    # - From environment variables
    
    # Example: Add rule-level specific recipients
    rule_level = alert_data.get('rule_level', 0)
    if rule_level >= 10:  # Critical alerts
        critical_email = os.getenv("CRITICAL_ALERTS_EMAIL")
        if critical_email:
            recipients.append(critical_email)
    
    # Remove duplicates and validate
    recipients = list(set(recipients))
    valid_recipients = []
    
    for email in recipients:
        if email and '@' in email:
            valid_recipients.append(email)
        else:
            log.warning("Invalid email address: %s", email)
    
    return valid_recipients


def save_email_sent(conn, alert_id: int, recipients: List[str], 
                   success: bool, error_message: str = None):
    """Record email sending result"""
    try:
        with conn.cursor() as cur:
            # Update alert state
            if success:
                cur.execute("""
                    UPDATE alerts 
                    SET state = 'sent',
                        sent_at = NOW(),
                        email_recipients = %s
                    WHERE id = %s
                """, (json.dumps(recipients), alert_id))
                log.info("Alert %d marked as sent to %d recipients", alert_id, len(recipients))
            else:
                # Increment retry count or mark as failed
                cur.execute("""
                    UPDATE alerts 
                    SET email_error = %s,
                        email_retry_count = COALESCE(email_retry_count, 0) + 1
                    WHERE id = %s
                """, (error_message, alert_id))
                log.error("Alert %d email sending failed: %s", alert_id, error_message)
            
    except Exception as e:
        log.error("Failed to update alert %d send status: %s", alert_id, e)


def catch_up(conn, sender: EmailSender):
    """Process any backlog of unsent alerts"""
    sql = """
        SELECT id FROM alerts 
        WHERE state = 'formatted' 
        ORDER BY formatted_at
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        alert_ids = [row[0] for row in cur.fetchall()]
    
    if alert_ids:
        log.info("Processing backlog of %d alerts", len(alert_ids))
        for alert_id in alert_ids:
            try:
                process_email_alert(conn, sender, alert_id)
            except Exception as e:
                log.error("Failed to process backlog alert %d: %s", alert_id, e)


def process_email_alert(conn, sender: EmailSender, alert_id: int):
    """Process a single alert for email sending"""
    alert_data = fetch_alert_to_send(conn, alert_id)
    if not alert_data or not alert_data.get('formatted_data'):
        log.debug("Alert %d not in correct state or missing formatted data", alert_id)
        return
    
    formatted_data = alert_data['formatted_data']
    
    # Get recipients
    recipients = get_email_recipients(conn, alert_data)
    if not recipients:
        log.warning("No recipients found for alert %d", alert_id)
        save_email_sent(conn, alert_id, [], False, "No recipients configured")
        return
    
    # Extract email components
    subject = formatted_data.get('subject', 'Delphi Alert')
    html_body = formatted_data.get('html_body', '')
    plain_body = formatted_data.get('plain_body', '')
    
    # Send email with retries
    success = False
    error_message = None
    
    for attempt in range(RETRY_ATTEMPTS):
        try:
            success = sender.send_email(recipients, subject, html_body, plain_body)
            if success:
                break
            else:
                error_message = f"SMTP sending failed (attempt {attempt + 1})"
                
        except Exception as e:
            error_message = f"Email sending error (attempt {attempt + 1}): {str(e)}"
            log.warning(error_message)
        
        if attempt < RETRY_ATTEMPTS - 1:
            log.info("Retrying email send in %d seconds...", RETRY_DELAY)
            time.sleep(RETRY_DELAY)
    
    # Record result
    save_email_sent(conn, alert_id, recipients, success, error_message)


# ───── SIGNAL HANDLING ─────────────────────────────────
shutdown = False

def on_signal(signum, _frame):
    global shutdown
    shutdown = True
    log.info("Signal %d received; shutting down", signum)

signal.signal(signal.SIGINT, on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ───── MAIN LOOP ─────────────────────────────────────────
def main():
    """Main event loop"""
    log.info("Email Sender starting up...")
    log.info("SMTP: %s:%d (TLS: %s)", SMTP_HOST, SMTP_PORT, SMTP_TLS)
    log.info("From: %s", FROM_EMAIL)
    
    # Initialize email sender
    sender = EmailSender()
    
    # Test SMTP connection
    if not sender.test_connection():
        log.error("SMTP connection test failed - check configuration")
        sys.exit(1)
    
    # Connect to database
    conn = connect_db()
    
    # Ensure email tracking columns exist
    with conn.cursor() as cur:
        cur.execute("""
            DO $ 
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name='alerts' AND column_name='sent_at'
                ) THEN
                    ALTER TABLE alerts ADD COLUMN sent_at TIMESTAMP;
                    ALTER TABLE alerts ADD COLUMN email_recipients JSONB;
                    ALTER TABLE alerts ADD COLUMN email_error TEXT;
                    ALTER TABLE alerts ADD COLUMN email_retry_count INTEGER DEFAULT 0;
                END IF;
            END $;
        """)
    
    # Process backlog
    catch_up(conn, sender)
    
    # Listen for formatted alerts
    cur = conn.cursor()
    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    log.info("Listening for alerts to send")
    
    while not shutdown:
        try:
            if not select.select([conn], [], [], 5)[0]:
                continue
            
            conn.poll()
            
            for notify in conn.notifies:
                try:
                    alert_id = int(notify.payload)
                    log.info("Processing alert %d", alert_id)
                    
                    process_email_alert(conn, sender, alert_id)
                    
                except Exception as e:
                    log.exception("Failed to process alert %s: %s", notify.payload, e)
            
            conn.notifies.clear()
            
        except psycopg2.OperationalError:
            log.exception("DB connection lost; reconnecting in 5s")
            time.sleep(5)
            conn = connect_db()
            cur = conn.cursor()
            cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        except Exception:
            log.exception("Unexpected error in main loop")
            raise
    
    log.info("Shutting down gracefully")


if __name__ == "__main__":
    main()