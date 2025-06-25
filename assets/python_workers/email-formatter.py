#!/usr/bin/env python3
# /usr/local/bin/email-formatter.py
# stanley:stanley 0750
"""
Email Formatter Worker - Formats structured alert data into HTML/plain text emails
"""
import os
import sys
import time
import select
import signal
import logging
import json
import html as html_lib
import psycopg2 # Pylance: If this import cannot be resolved, ensure psycopg2-binary is installed
import psycopg2.extensions
from string import Template
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional, Tuple
from abc import ABC, abstractmethod

# Pylance: If 'load_dotenv' is an unknown import symbol, ensure python-dotenv is installed.
# The try-except handles runtime, but Pylance needs to see it defined statically.
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*_a, **_kw): pass

try:
    from psycopg2.extras import RealDictCursor
except ImportError:
    logging.error("Required dependency 'psycopg2' not found. Please install it using: pip install psycopg2-binary")
    sys.exit(1)

# Pylance: If 'pytz' could not be resolved, ensure pytz is installed.
try:
    import pytz
except ModuleNotFoundError:
    logging.warning("Pytz module not found. Timezone conversions might be limited. Please install it using: pip install pytz")
    pytz = None # Set pytz to None if not found, to handle gracefully

# ───── CONFIGURATION ─────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")

REQUIRED_ENV = ["PG_DSN"]
_missing = [var for var in REQUIRED_ENV if not os.getenv(var)]
if _missing:
    print(f"FATAL: Missing environment variables: {', '.join(_missing)}", file=sys.stderr)
    sys.exit(1)

PG_DSN = os.getenv("PG_DSN", "").strip()
LISTEN_CHANNEL = "alert_structured"    # Channel for alerts needing formatting
NOTIFY_CHANNEL = "alert_formatted"     # Channel to notify when done

# Template configuration
TEMPLATE_TYPE = os.getenv("DELPHI_EMAIL_TEMPLATE_TYPE", "file")
TEMPLATE_PATH = os.getenv("DELPHI_EMAIL_TEMPLATE_PATH", "/opt/stackstorm/packs/delphi/email.html")
TIMEZONE = os.getenv("DELPHI_TIMEZONE", "Australia/Perth")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "support@cybermonkey.net.au")

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    logger = logging.getLogger("email-formatter")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        "/var/log/stackstorm/email-formatter.log",
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

# ───── EMAIL TEMPLATE CLASSES ─────────────────────────────────────
class EmailTemplate(ABC):
    """Abstract base class for email templates"""

    @abstractmethod
    def format_html(self, data: Dict[str, Any]) -> str:
        """Format data as HTML"""
        pass

    @abstractmethod
    def format_plain(self, data: Dict[str, Any]) -> str:
        """Format data as plain text"""
        pass


class FileBasedTemplate(EmailTemplate):
    """Template that loads from an HTML file"""

    def __init__(self, template_path: str, fallback_html: Optional[str] = None):
        """Initialize with template file path"""
        self.template = self._load_template(template_path, fallback_html)

    def _load_template(self, path: str, fallback: Optional[str]) -> Template:
        """Load template from file with fallback"""
        try:
            with open(path, encoding="utf-8") as f:
                return Template(f.read())
        except (FileNotFoundError, PermissionError) as e:
            log.warning("Could not load template from %r: %s", path, e)
            if fallback:
                return Template(fallback)
            else:
                # Default minimal template
                return Template("""<!DOCTYPE html>
<html>
<head><title>$subject</title></head>
<body>
<h1>$subject</h1>
<div>$body</div>
<hr>
<p>Sent at: $sent_at | Alert ID: $alert_id</p>
</body>
</html>""")

    def format_html(self, data: Dict[str, Any]) -> str:
        """Format using the HTML template"""
        # Build the body content
        body_html = self._build_body_html(
            data.get('sections', {}),
            data.get('agent_info', {})
        )

        # Get metadata
        metadata = data.get('metadata', {})

        # Format timestamp
        timestamp = metadata.get('timestamp')
        if timestamp:
            try:
                # Use pytz only if it was successfully imported
                if pytz:
                    tz = pytz.timezone(TIMEZONE)
                    if isinstance(timestamp, str):
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    sent_at = timestamp.astimezone(tz).strftime("%A, %d %B %Y %I:%M %p AWST")
                else:
                    sent_at = str(timestamp) # Fallback if pytz not available
            except Exception: # Catch broader exceptions for timezone/datetime issues
                sent_at = str(timestamp)
        else:
            sent_at = "Unknown time"

        # Substitute into template
        return self.template.safe_substitute(
            subject=html_lib.escape(data.get('subject', 'Delphi Alert')),
            sent_at=html_lib.escape(sent_at),
            alert_id=html_lib.escape(str(metadata.get('alert_hash', 'Unknown'))), # Ensure alert_id is string
            body=body_html,
            support_email=html_lib.escape(SUPPORT_EMAIL)
        )

    def format_plain(self, data: Dict[str, Any]) -> str:
        """Format as plain text"""
        lines = []

        # Header
        lines.append(f"Subject: {data.get('subject', 'Delphi Alert')}")

        metadata = data.get('metadata', {})
        lines.append(f"Alert ID: {metadata.get('alert_hash', 'Unknown')}")

        # Timestamp
        timestamp = metadata.get('timestamp')
        if timestamp:
            lines.append(f"Sent at: {timestamp}")

        lines.append("\n--- Alert Details ---\n")

        # Sections
        sections = data.get('sections', {})
        for section, content in sections.items():
            lines.append(f"\n{section}:")
            lines.append(content)

        # Agent info
        lines.append("\n--- Agent Information ---")
        agent_info = data.get('agent_info', {})
        if agent_info:
            for key, value in agent_info.items():
                if value and key not in ['groups']:  # Skip complex fields
                    lines.append(f"{key.replace('_', ' ').title()}: {value}")

            if agent_info.get('groups'):
                lines.append(f"Groups: {', '.join(agent_info['groups'])}")
        else:
            lines.append("No agent information available")

        return "\n".join(lines)

    def _build_body_html(self, sections: Dict[str, str],
                        agent_info: Dict[str, Any]) -> str:
        """Build HTML body content"""
        html_parts = []

        # Add sections
        for heading, content in sections.items():
            if content:
                # Convert newlines to paragraphs
                # FIX: Used raw string literal r'\n\n' to avoid Pylance warning about escape sequences in f-string
                paragraphs = [
                    f"<p>{html_lib.escape(p)}</p>"
                    for p in content.split(r'\n\n') if p.strip()
                ]
                if paragraphs:
                    html_parts.append(f"<h2>{html_lib.escape(heading)}:</h2>")
                    html_parts.extend(paragraphs)

        # Add agent details
        if agent_info:
            html_parts.append(self._format_agent_details_html(agent_info))

        return "\n".join(html_parts)

    def _format_agent_details_html(self, agent_info: Dict[str, Any]) -> str:
        """Format agent details as HTML"""
        if not agent_info:
            return "<p>No agent information available.</p>"

        html_parts = ["<h2>Agent Details:</h2>", "<ul>"]

        # Simple fields
        field_mappings = [
            ('name', 'Agent Name'),
            ('id', 'Agent ID'),
            ('ip', 'IP Address'),
            ('version', 'Wazuh Version'),
            ('status', 'Status'),
            ('os', 'Operating System'),
            ('manager', 'Manager'),
        ]

        for field, label in field_mappings:
            if field in agent_info and agent_info[field]:
                value = html_lib.escape(str(agent_info[field]))
                html_parts.append(f"<li><strong>{label}:</strong> {value}</li>")

        # Groups
        if agent_info.get('groups'):
            groups_str = ", ".join([html_lib.escape(g) for g in agent_info['groups']])
            html_parts.append(f"<li><strong>Groups:</strong> {groups_str}</li>")

        # Timestamps
        for field, label in [
            ('registered_at', 'Registered'),
            ('last_seen', 'Last Seen'),
            ('disconnected_at', 'Disconnected')
        ]:
            if field in agent_info:
                value = agent_info[field]
                if isinstance(value, datetime):
                    try:
                        # Use pytz only if it was successfully imported
                        if pytz:
                            tz = pytz.timezone(TIMEZONE)
                            value = value.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S %Z')
                        else:
                            value = str(value) # Fallback if pytz not available
                    except Exception: # Catch broader exceptions for timezone/datetime issues
                        value = str(value)
                html_parts.append(f"<li><strong>{label}:</strong> {html_lib.escape(str(value))}</li>")

        html_parts.append("</ul>")
        return "\n".join(html_parts)


class ModernCardTemplate(EmailTemplate):
    """A more modern card-based email template"""

    def format_html(self, data: Dict[str, Any]) -> str:
        """Format using a modern card-based layout"""
        sections = data.get('sections', {})
        agent_info = data.get('agent_info', {})
        metadata = data.get('metadata', {})

        # Build cards for each section
        cards_html = []
        for heading, content in sections.items():
            if content:
                card = f"""
                <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="color: #2c3e50; margin-top: 0;">{html_lib.escape(heading)}</h3>
                    <div style="color: #555; line-height: 1.6;">
                        {html_lib.escape(content).replace(r'\n\n', '<br><br>')}
                    </div>
                </div>
                """
                cards_html.append(card)

        # Agent info card
        if agent_info:
            agent_card = f"""
            <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 16px;">
                <h3 style="color: #2c3e50; margin-top: 0;">System Information</h3>
                <table style="width: 100%; color: #555;">
                    <tr><td><strong>Agent:</strong></td><td>{html_lib.escape(str(agent_info.get('name', 'Unknown')))}</td></tr>
                    <tr><td><strong>OS:</strong></td><td>{html_lib.escape(str(agent_info.get('os', 'Unknown')))}</td></tr>
                    <tr><td><strong>IP:</strong></td><td>{html_lib.escape(str(agent_info.get('ip', 'N/A')))}</td></tr>
                    <tr><td><strong>Status:</strong></td><td>{html_lib.escape(str(agent_info.get('status', 'Unknown')))}</td></tr>
                </table>
            </div>
            """
            cards_html.append(agent_card)

        # Combine everything
        body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{html_lib.escape(data.get('subject', 'Alert'))}</title>
        </head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #e9ecef; padding: 20px; margin: 0;">
            <div style="max-width: 600px; margin: 0 auto;">
                <div style="background: #fff; border-radius: 8px; padding: 24px; margin-bottom: 20px; text-align: center;">
                    <h1 style="color: #2c3e50; margin: 0; font-size: 24px;">Security Alert</h1>
                    <p style="color: #7f8c8d; margin: 8px 0;">Alert ID: {html_lib.escape(str(metadata.get('alert_hash', 'Unknown')))}</p>
                </div>

                {''.join(cards_html)}

                <div style="text-align: center; color: #7f8c8d; font-size: 14px; margin-top: 32px;">
                    <p>This alert was generated by Delphi Security Monitoring</p>
                </div>
            </div>
        </body>
        </html>
        """

        return body

    def format_plain(self, data: Dict[str, Any]) -> str:
        """Simple plain text format"""
        # Instantiate FileBasedTemplate with an empty string as path/fallback for plain text
        # This prevents unnecessary file loading when only plain text is needed and no specific file template is required
        return FileBasedTemplate(template_path="", fallback_html="").format_plain(data)


# ───── EMAIL FORMATTER ─────────────────────────────────
class EmailFormatter:
    """Main formatter class that coordinates email formatting"""

    def __init__(self, template: Optional[EmailTemplate] = None):
        """Initialize with a template"""
        if template is None:
            # Try to load default template
            template_paths = [
                TEMPLATE_PATH,
                "/opt/stackstorm/packs/delphi/email.html",
                "/usr/local/share/eos/email.html",
            ]

            for path in template_paths:
                if os.path.exists(path):
                    template = FileBasedTemplate(path)
                    break
            else:
                # Use fallback with empty string for template_path (relies on internal fallback)
                template = FileBasedTemplate(template_path="")

        self.template = template

    def format_email(self, structured_data: Dict[str, Any]) -> Tuple[str, str, str]:
        """
        Format structured data into email components

        Returns:
            Tuple of (subject, plain_body, html_body)
        """
        subject = structured_data.get('subject', 'Delphi Alert')
        plain_body = self.template.format_plain(structured_data)
        html_body = self.template.format_html(structured_data)

        return subject, plain_body, html_body


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


def fetch_alert_to_format(conn, alert_id: int) -> Optional[Dict]:
    """Fetch an alert that needs formatting"""
    sql = """
        SELECT
            id,
            structured_data,
            structured_at
        FROM alerts
        WHERE state = 'STRUCTURED' -- FIX: Changed 'structured' to 'STRUCTURED' to match enum
        AND id = %s
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        row = cur.fetchone()

        if row and row.get('structured_data'):
            if isinstance(row['structured_data'], str):
                try:
                    row['structured_data'] = json.loads(row['structured_data'])
                except json.JSONDecodeError:
                    log.warning("Failed to parse structured_data JSON for alert %d", alert_id)
                    row['structured_data'] = {}

        return row


def save_formatted_data(conn, alert_id: int, formatted_data: Dict[str, Any]):
    """Save formatted data and update alert state"""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE alerts
                SET formatted_data = %s,
                    state = 'formatted', -- Assuming 'formatted' is a valid enum value
                    formatted_at = NOW()
                WHERE id = %s
            """, (json.dumps(formatted_data), alert_id))

            # Notify next worker (email sender)
            cur.execute(f"NOTIFY {NOTIFY_CHANNEL}, %s", (str(alert_id),))

        log.info("Saved formatted data for alert %d", alert_id)
    except Exception as e:
        log.error("Failed to save formatted data for alert %d: %s", alert_id, e)
        raise


def catch_up(conn, formatter: EmailFormatter):
    """Process any backlog of unformatted alerts"""
    sql = """
        SELECT id FROM alerts
        WHERE state = 'STRUCTURED' -- FIX: Changed 'structured' to 'STRUCTURED' to match enum
        ORDER BY structured_at
    """
    with conn.cursor() as cur:
        cur.execute(sql)
        alert_ids = [row[0] for row in cur.fetchall()]

    if alert_ids:
        log.info("Processing backlog of %d alerts", len(alert_ids))
        for alert_id in alert_ids:
            try:
                alert_data = fetch_alert_to_format(conn, alert_id)
                if alert_data and alert_data.get('structured_data'):
                    subject, plain_body, html_body = formatter.format_email(alert_data['structured_data'])

                    formatted_data = {
                        'subject': subject,
                        'html_body': html_body,
                        'plain_body': plain_body,
                        'template_used': TEMPLATE_TYPE,
                        'formatting_metadata': {
                            'template_path': TEMPLATE_PATH,
                            'formatted_at': datetime.now(timezone.utc).isoformat(),
                            'timezone': TIMEZONE
                        }
                    }

                    save_formatted_data(conn, alert_id, formatted_data)
            except Exception as e:
                log.error("Failed to process backlog alert %d: %s", alert_id, e)


# ───── SIGNAL HANDLING ─────────────────────────────────
shutdown = False

def on_signal(signum, _frame):
    global shutdown
    shutdown = True
    log.info("Signal %d received; shutting down", signum)

signal.signal(signal.SIGINT, on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ───── MAIN LOOP ─────────────────────────────────────────
def create_formatter():
    """Create formatter based on configuration"""
    if TEMPLATE_TYPE == 'file':
        template = FileBasedTemplate(TEMPLATE_PATH)
    elif TEMPLATE_TYPE == 'modern':
        template = ModernCardTemplate()
    else:
        log.warning("Unknown template type %s, using file", TEMPLATE_TYPE)
        template = FileBasedTemplate(TEMPLATE_PATH)

    return EmailFormatter(template)


def main():
    """Main event loop"""
    log.info("Email Formatter starting up...")
    log.info("Using template type: %s", TEMPLATE_TYPE)
    log.info("Template path: %s", TEMPLATE_PATH)

    # Initialize formatter
    formatter = create_formatter()

    # Connect to database
    conn = connect_db()

    # Ensure formatted_data column exists
    with conn.cursor() as cur:
        # FIX: Changed DO $ to DO $$ and END $; to END $$; for correct PostgreSQL dollar-quoting syntax
        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name='alerts' AND column_name='formatted_data'
                ) THEN
                    ALTER TABLE alerts ADD COLUMN formatted_data JSONB;
                    ALTER TABLE alerts ADD COLUMN formatted_at TIMESTAMP;
                END IF;
            END $$;
        """)

    # Process backlog
    catch_up(conn, formatter)

    # Listen for structured alerts
    cur = conn.cursor()
    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    log.info("Listening for alerts to format")

    while not shutdown:
        try:
            if not select.select([conn], [], [], 5)[0]:
                continue

            conn.poll()

            for notify in conn.notifies:
                try:
                    alert_id = int(notify.payload)
                    log.info("Processing alert %d", alert_id)

                    alert_data = fetch_alert_to_format(conn, alert_id)
                    if not alert_data or not alert_data.get('structured_data'):
                        log.debug("Alert %d not in correct state or missing structured data", alert_id)
                        continue

                    subject, plain_body, html_body = formatter.format_email(alert_data['structured_data'])

                    formatted_data = {
                        'subject': subject,
                        'html_body': html_body,
                        'plain_body': plain_body,
                        'template_used': TEMPLATE_TYPE,
                        'formatting_metadata': {
                            'template_path': TEMPLATE_PATH,
                            'formatted_at': datetime.now(timezone.utc).isoformat(),
                            'timezone': TIMEZONE
                        }
                    }

                    save_formatted_data(conn, alert_id, formatted_data)

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
