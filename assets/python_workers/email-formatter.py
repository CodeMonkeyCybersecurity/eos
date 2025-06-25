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

# --- Import sdnotify for Systemd Watchdog Integration ---
try:
    import sdnotify # ADDED: Import sdnotify
except ImportError:
    # Fallback for systems without sdnotify
    sdnotify = None
    print("WARNING: sdnotify module not found. Systemd watchdog integration will be disabled.")

# ───── CONFIGURATION ─────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")

REQUIRED_ENV = ["PG_DSN"]
_missing = [var for var in REQUIRED_ENV if not os.getenv(var)]
if _missing:
    print(f"FATAL: Missing environment variables: {', '.join(_missing)}", file=sys.stderr)
    if sdnotify:
        notifier.notify(f"STATUS=FATAL: Missing environment variables: {', '.join(_missing)}. Exiting.") # ADDED: sdnotify on missing env vars
        notifier.notify("STOPPING=1")
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

# --- Initialize Systemd Notifier ---
if sdnotify:
    notifier = sdnotify.SystemdNotifier() # ADDED: Initialize sdnotify notifier
else:
    class DummyNotifier: # Dummy class if sdnotify isn't available
        def notify(self, message):
            pass
    notifier = DummyNotifier()


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
                log.warning("Using default minimal HTML template as no file was found and no fallback was provided.")
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
                        # Ensure string timestamp is parsed as UTC if it lacks timezone info
                        if timestamp.endswith('Z'):
                            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        elif '+' not in timestamp and '-' not in timestamp[-6:]: # Simple check for offset presence
                             timestamp = datetime.fromisoformat(timestamp).replace(tzinfo=timezone.utc) # Assume UTC if no tzinfo
                        else:
                            timestamp = datetime.fromisoformat(timestamp)
                    sent_at = timestamp.astimezone(tz).strftime("%A, %d %B %Y %I:%M %p AWST")
                else:
                    sent_at = str(timestamp) # Fallback if pytz not available
            except Exception as e: # Catch broader exceptions for timezone/datetime issues
                log.error(f"Error formatting timestamp '{timestamp}': {e}", exc_info=True)
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
            # Attempt to convert timestamp for plain text too, similar to HTML
            if pytz and isinstance(timestamp, (str, datetime)):
                try:
                    tz = pytz.timezone(TIMEZONE)
                    if isinstance(timestamp, str):
                        if timestamp.endswith('Z'):
                            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        elif '+' not in timestamp and '-' not in timestamp[-6:]:
                             timestamp = datetime.fromisoformat(timestamp).replace(tzinfo=timezone.utc)
                        else:
                            timestamp = datetime.fromisoformat(timestamp)
                    formatted_ts = timestamp.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z")
                    lines.append(f"Sent at: {formatted_ts}")
                except Exception as e:
                    log.error(f"Error formatting timestamp for plain text '{timestamp}': {e}", exc_info=True)
                    lines.append(f"Sent at: {str(timestamp)}")
            else:
                lines.append(f"Sent at: {str(timestamp)}")

        lines.append("\n--- Alert Details ---\n")

        # Sections
        sections = data.get('sections', {})
        for section, content in sections.items():
            if content:
                lines.append(f"\n{section}:")
                lines.append(content) # No HTML escaping/conversion needed for plain text

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
                    for p in content.split('\n\n') if p.strip() # Correct split for newlines
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
            ('version', 'Wazuh Version'), # Changed from 'version' to 'wazuh_version' if that's the key
            ('status', 'Status'),
            ('os', 'Operating System'),
            ('manager', 'Manager'),
        ]

        # Use actual keys from agent_info if they exist, otherwise map from field_mappings
        # Assuming agent_info keys like 'agent_version', 'status_text', 'manager_name' from previous schemas
        agent_info_normalized = {
            'name': agent_info.get('name'),
            'id': agent_info.get('id'),
            'ip': agent_info.get('ip'),
            'version': agent_info.get('agent_version') or agent_info.get('version'), # Use agent_version if present
            'status': agent_info.get('status_text') or agent_info.get('status'), # Use status_text if present
            'os': agent_info.get('os'),
            'manager': agent_info.get('manager_name') or agent_info.get('manager'), # Use manager_name if present
        }


        for field, label in field_mappings:
            value = agent_info_normalized.get(field)
            if value:
                value_str = html_lib.escape(str(value))
                html_parts.append(f"<li><strong>{label}:</strong> {value_str}</li>")


        # Groups
        if agent_info.get('groups'): # Assuming 'groups' is a list of strings
            groups_str = ", ".join([html_lib.escape(g) for g in agent_info['groups']])
            html_parts.append(f"<li><strong>Groups:</strong> {groups_str}</li>")

        # Timestamps
        for field, label in [
            ('registered', 'Registered'), # Adjusted from 'registered_at' to 'registered'
            ('last_seen', 'Last Seen'),
            ('disconnection_time', 'Disconnected') # Adjusted from 'disconnected_at' to 'disconnection_time'
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
                    except Exception as e: # Catch broader exceptions for timezone/datetime issues
                        log.error(f"Error formatting agent timestamp '{value}' for field '{field}': {e}", exc_info=True)
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

        # Format timestamp for header
        header_timestamp = metadata.get('timestamp')
        if header_timestamp:
            try:
                if pytz:
                    tz = pytz.timezone(TIMEZONE)
                    if isinstance(header_timestamp, str):
                        if header_timestamp.endswith('Z'):
                            header_timestamp = datetime.fromisoformat(header_timestamp.replace('Z', '+00:00'))
                        elif '+' not in header_timestamp and '-' not in header_timestamp[-6:]:
                             header_timestamp = datetime.fromisoformat(header_timestamp).replace(tzinfo=timezone.utc)
                        else:
                            header_timestamp = datetime.fromisoformat(header_timestamp)
                    header_timestamp_str = header_timestamp.astimezone(tz).strftime("%A, %d %B %Y %I:%M %p AWST")
                else:
                    header_timestamp_str = str(header_timestamp)
            except Exception as e:
                log.error(f"Error formatting header timestamp '{header_timestamp}': {e}", exc_info=True)
                header_timestamp_str = str(header_timestamp)
        else:
            header_timestamp_str = "Unknown time"


        # Build cards for each section
        cards_html = []
        for heading, content in sections.items():
            if content:
                # Replace newlines with <br><br> for HTML rendering in cards
                formatted_content = html_lib.escape(content).replace('\n\n', '<br><br>')
                card = f"""
                <div style="background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="color: #2c3e50; margin-top: 0;">{html_lib.escape(heading)}</h3>
                    <div style="color: #555; line-height: 1.6;">
                        {formatted_content}
                    </div>
                </div>
                """
                cards_html.append(card)

        # Agent info card
        if agent_info:
            agent_details_list = []
            # Use the same normalization and formatting logic as in FileBasedTemplate for consistency
            field_mappings = [
                ('name', 'Agent'), ('id', 'ID'), ('ip', 'IP'),
                ('agent_version', 'Wazuh Version'), ('status_text', 'Status'),
                ('os', 'OS'), ('manager_name', 'Manager'),
            ]
            for field, label in field_mappings:
                value = agent_info.get(field)
                if value:
                    agent_details_list.append(f"<tr><td><strong>{label}:</strong></td><td>{html_lib.escape(str(value))}</td></tr>")

            if agent_info.get('groups'):
                groups_str = ", ".join([html_lib.escape(g) for g in agent_info['groups']])
                agent_details_list.append(f"<tr><td><strong>Groups:</strong></td><td>{groups_str}</td></tr>")

            for field, label in [
                ('registered', 'Registered'), ('last_seen', 'Last Seen'), ('disconnection_time', 'Disconnected')
            ]:
                if field in agent_info:
                    value = agent_info[field]
                    if isinstance(value, datetime):
                        try:
                            if pytz:
                                tz = pytz.timezone(TIMEZONE)
                                value = value.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S %Z')
                            else:
                                value = str(value)
                        except Exception as e:
                            log.error(f"Error formatting agent timestamp for modern card '{value}' for field '{field}': {e}", exc_info=True)
                            value = str(value)
                    agent_details_list.append(f"<tr><td><strong>{label}:</strong></td><td>{html_lib.escape(str(value))}</td></tr>")


            agent_card = f"""
            <div style="background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                <h3 style="color: #2c3e50; margin-top: 0;">System Information</h3>
                <table style="width: 100%; color: #555; border-collapse: collapse;">
                    {''.join(agent_details_list)}
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
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{html_lib.escape(data.get('subject', 'Security Alert'))}</title>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #e9ecef; padding: 20px; margin: 0; }}
                .container {{ max-width: 600px; margin: 0 auto; }}
                .header {{ background: #fff; border-radius: 8px; padding: 24px; margin-bottom: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .header h1 {{ color: #2c3e50; margin: 0; font-size: 24px; }}
                .header p {{ color: #7f8c8d; margin: 8px 0; font-size: 14px; }}
                .card {{ background: #fff; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .card h3 {{ color: #2c3e50; margin-top: 0; }}
                .card div {{ color: #555; line-height: 1.6; }}
                .agent-card {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .agent-card table {{ width: 100%; color: #555; border-collapse: collapse; }}
                .agent-card td {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
                .agent-card tr:last-child td {{ border-bottom: none; }}
                .footer {{ text-align: center; color: #7f8c8d; font-size: 14px; margin-top: 32px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Alert</h1>
                    <p style="font-size: 16px; font-weight: bold;">{html_lib.escape(data.get('subject', 'General Alert'))}</p>
                    <p>Alert ID: {html_lib.escape(str(metadata.get('alert_hash', 'Unknown')))}</p>
                    <p>Generated at: {header_timestamp_str}</p>
                </div>

                {''.join(cards_html)}

                <div class="footer">
                    <p>This alert was generated by Delphi Security Monitoring</p>
                    <p>For support, contact: <a href="mailto:{html_lib.escape(SUPPORT_EMAIL)}" style="color: #007bff; text-decoration: none;">{html_lib.escape(SUPPORT_EMAIL)}</a></p>
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

            found_template_path = None
            for path in template_paths:
                if os.path.exists(path):
                    found_template_path = path
                    break
            
            if found_template_path:
                template = FileBasedTemplate(found_template_path)
                log.info(f"Using template from path: {found_template_path}")
            else:
                # Use fallback with empty string for template_path (relies on internal fallback)
                template = FileBasedTemplate(template_path="")
                log.warning("No specific email template file found, using default minimal template.")

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
        notifier.notify("STATUS=FATAL: Could not connect to PostgreSQL. Exiting.") # ADDED: sdnotify on DB connection failure
        notifier.notify("STOPPING=1")
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
        notifier.notify(f"STATUS=DB update failed for alert {alert_id}. See logs.") # ADDED: sdnotify on DB update failure
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
            # Ping watchdog during backlog processing if it takes a long time
            notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping during backlog processing
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
                else:
                    log.debug("Alert %d not in correct state or missing structured data during backlog processing, skipping.", alert_id)
            except Exception as e:
                log.error("Failed to process backlog alert %d: %s", alert_id, e)
                notifier.notify(f"STATUS=Error processing backlog alert {alert_id}. See logs.") # ADDED: sdnotify on backlog error


# ───── SIGNAL HANDLING ─────────────────────────────────
shutdown = False

def on_signal(signum, _frame):
    global shutdown
    shutdown = True
    log.info("Signal %d received; shutting down", signum)
    notifier.notify("STOPPING=1") # ADDED: sdnotify on signal received

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
    notifier.notify("READY=1") # ADDED: Signal Systemd that the service is ready
    notifier.notify(f"STATUS=Starting up. Template type: {TEMPLATE_TYPE}. Path: {TEMPLATE_PATH}")

    # Initialize formatter
    formatter = create_formatter()

    # Connect to database
    conn = connect_db() # This function already calls sys.exit(1) on failure.

    # Ensure formatted_data column exists
    try:
        with conn.cursor() as cur:
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='alerts' AND column_name='formatted_data'
                    ) THEN
                        ALTER TABLE alerts ADD COLUMN formatted_data JSONB;
                        ALTER TABLE alerts ADD COLUMN formatted_at TIMESTAMP WITH TIME ZONE; -- Ensure TIMESTAMPTZ
                    END IF;
                END $$;
            """)
        conn.commit() # Ensure changes are committed if autocommit is not strictly on here
        notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog after schema check/update
    except Exception as e:
        log.critical(f"Failed to ensure DB columns exist: {e}", exc_info=True)
        notifier.notify("STATUS=FATAL: Failed to ensure DB columns. Exiting.") # ADDED: sdnotify on schema check failure
        notifier.notify("STOPPING=1")
        sys.exit(1)


    # Process backlog
    log.info("Processing backlog...")
    catch_up(conn, formatter)
    notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog after backlog processing

    # Listen for structured alerts
    cur = conn.cursor()
    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    log.info("Listening for alerts to format")
    notifier.notify(f"STATUS=Listening on {LISTEN_CHANNEL} for alerts to format...") # ADDED: Update status

    while not shutdown:
        try:
            # Ping watchdog before polling for events. This keeps systemd happy during idle times.
            notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping at the start of each poll cycle

            if not select.select([conn], [], [], 5)[0]: # Wait up to 5 seconds for events
                continue # If no events, loop back and ping watchdog again

            conn.poll()

            for notify in conn.notifies:
                notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping before processing each notification
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
                    notifier.notify(f"STATUS=Error processing alert {alert_id}. See logs.") # ADDED: sdnotify on processing error

            conn.notifies.clear()

        except psycopg2.OperationalError:
            log.exception("DB connection lost; reconnecting in 5s")
            notifier.notify("STATUS=DB connection lost. Attempting to reconnect...") # ADDED: sdnotify on DB connection loss
            time.sleep(5) # Keep this sleep for reconnection back-off
            try:
                conn = connect_db() # This function will call sys.exit if reconnect fails
                cur = conn.cursor()
                cur.execute(f"LISTEN {LISTEN_CHANNEL};")
                log.info("Reconnected to Postgres and re-listening.")
                notifier.notify("STATUS=Reconnected to DB. Listening for alerts to format...") # ADDED: sdnotify on successful reconnect
            except Exception: # Catch the sys.exit from connect_db
                log.critical("Failed to reconnect to database. Exiting.")
                notifier.notify("STOPPING=1")
                sys.exit(1)
        except Exception:
            log.exception("Unexpected error in main loop")
            notifier.notify("STATUS=Unexpected error in main loop. Exiting.") # ADDED: sdnotify on unexpected errors
            notifier.notify("STOPPING=1")
            raise # Re-raise the exception after notifying systemd for debugging/crash reporting

    log.info("Shutting down gracefully")
    notifier.notify("STATUS=Shutting down gracefully.") # ADDED: Final status update
    notifier.notify("STOPPING=1") # ADDED: Signal Systemd that the service is stopping


if __name__ == "__main__":
    main()
