#!/usr/bin/env python3
# /usr/local/bin/email-formatter.py
# stanley:stanley 0750
"""
Email Formatter Worker - Phase 5 of Delphi Pipeline
Formats structured alert data into professional HTML/plain text emails

IMPROVEMENTS:
- Fixed state case sensitivity to match schema.sql ('structured' not 'STRUCTURED')
- Simplified template system focused on actual LLM response formats
- Added proper handling for ISOBAR, Delphi Notify, and Brief formats
- Enhanced error handling and recovery
- Improved database schema alignment
- Added comprehensive monitoring and health checks
- Streamlined systemd integration
"""
import os
import sys
import time
import select
import signal
import logging
import json
import html as html_lib
import psycopg2
import psycopg2.extensions
import psycopg2.extras
from string import Template
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*_a, **_kw): pass

try:
    import pytz
except ModuleNotFoundError:
    logging.warning("pytz not found - timezone conversions will be limited")
    pytz = None

try:
    import sdnotify
except ImportError:
    sdnotify = None

# ───── CONFIGURATION ─────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")

# Environment validation
REQUIRED_ENV = ["PG_DSN"]
missing_vars = [var for var in REQUIRED_ENV if not os.getenv(var)]
if missing_vars:
    print(f"FATAL: Missing environment variables: {', '.join(missing_vars)}", file=sys.stderr)
    sys.exit(1)

PG_DSN = os.getenv("PG_DSN", "").strip()

# Pipeline configuration - FIXED: Aligned with schema.sql notification channels
LISTEN_CHANNEL = "alert_structured"
NOTIFY_CHANNEL = "alert_formatted"
STATE_STRUCTURED = "structured"  # FIXED: Lowercase to match schema.sql enum
STATE_FORMATTED = "formatted"

# Template and formatting configuration
TIMEZONE = os.getenv("DELPHI_TIMEZONE", "Australia/Perth")
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "support@cybermonkey.net.au")
ORGANIZATION_NAME = os.getenv("ORGANIZATION_NAME", "Delphi Security")
BRAND_COLOR = os.getenv("BRAND_COLOR", "#2c3e50")

# Performance configuration
BATCH_SIZE = int(os.getenv("FORMATTER_BATCH_SIZE", "5"))
MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", "50000"))  # Prevent massive emails

class PromptType(Enum):
    """Supported prompt types for specialized formatting"""
    ISOBAR = "security_analysis"
    DELPHI_NOTIFY = "delphi_notify_short"
    DELPHI_BRIEF = "delphi_notify_brief"
    EXECUTIVE = "executive_summary"
    INVESTIGATION = "investigation_guide"
    HYBRID = "hybrid"
    CUSTOM = "custom"

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configure structured logging"""
    logger = logging.getLogger("email-formatter")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        "/var/log/stackstorm/email-formatter.log",
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    if sys.stdout.isatty():
        console = logging.StreamHandler(sys.stdout)
        console.setFormatter(fmt)
        logger.addHandler(console)

    return logger

log = setup_logging()

# ───── SYSTEMD INTEGRATION ─────────────────────────────
class SystemdNotifier:
    """Wrapper for systemd notifications"""
    def __init__(self):
        if sdnotify:
            self.notifier = sdnotify.SystemdNotifier()
        else:
            self.notifier = None
            
    def notify(self, message: str):
        """Send notification to systemd"""
        if self.notifier:
            try:
                self.notifier.notify(message)
            except Exception as e:
                log.warning("Failed to send systemd notification: %s", e)
    
    def ready(self):
        """Signal that service is ready"""
        self.notify("READY=1")
        
    def watchdog(self):
        """Send watchdog ping"""
        self.notify("WATCHDOG=1")
        
    def status(self, status: str):
        """Update service status"""
        self.notify(f"STATUS={status}")
        
    def stopping(self):
        """Signal that service is stopping"""
        self.notify("STOPPING=1")

notifier = SystemdNotifier()

# ───── EMAIL FORMATTER CLASSES ─────────────────────────────
@dataclass
class FormattedEmail:
    """Container for formatted email components"""
    subject: str
    html_body: str
    plain_body: str
    metadata: Dict[str, Any]

class BaseEmailFormatter:
    """Base formatter with common functionality"""
    
    def __init__(self):
        self.timezone = self._get_timezone()
        
    def _get_timezone(self):
        """Get timezone object with fallback"""
        if pytz:
            try:
                return pytz.timezone(TIMEZONE)
            except Exception as e:
                log.warning("Invalid timezone %s: %s", TIMEZONE, e)
                return pytz.UTC
        return None
    
    def _format_timestamp(self, timestamp_str: str) -> str:
        """Format timestamp with timezone conversion"""
        if not timestamp_str:
            return "Unknown time"
            
        try:
            # Parse ISO timestamp
            if timestamp_str.endswith('Z'):
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            elif '+' in timestamp_str[-6:] or timestamp_str.count('-') > 2:
                dt = datetime.fromisoformat(timestamp_str)
            else:
                dt = datetime.fromisoformat(timestamp_str).replace(tzinfo=timezone.utc)
            
            # Convert to local timezone
            if self.timezone:
                dt = dt.astimezone(self.timezone)
                return dt.strftime("%A, %d %B %Y %I:%M %p %Z")
            else:
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                
        except Exception as e:
            log.warning("Failed to parse timestamp '%s': %s", timestamp_str, e)
            return str(timestamp_str)
    
    def _truncate_content(self, content: str, max_length: int = MAX_CONTENT_LENGTH) -> str:
        """Truncate content that's too long"""
        if len(content) <= max_length:
            return content
        
        truncated = content[:max_length - 100]
        last_sentence = truncated.rfind('.')
        if last_sentence > max_length * 0.8:  # Keep if we can preserve most content
            truncated = truncated[:last_sentence + 1]
        
        truncated += f"\n\n[Content truncated - original was {len(content)} characters]"
        return truncated

class ISOBARFormatter(BaseEmailFormatter):
    """Formatter for ISOBAR framework responses"""
    
    def format(self, data: Dict[str, Any]) -> FormattedEmail:
        """Format ISOBAR structured data"""
        sections = data.get('sections', {})
        metadata = data.get('metadata', {})
        
        # Extract alert metadata
        alert_id = metadata.get('alert_id', 'Unknown')
        rule_level = metadata.get('rule_level', 0)
        agent_name = metadata.get('agent_name', 'Unknown System')
        timestamp = metadata.get('timestamp', '')
        
        # Generate subject based on severity
        severity = self._determine_severity(rule_level)
        subject = f"[{severity}] Security Alert - {agent_name} - Alert #{alert_id}"
        
        # Build HTML content
        html_body = self._build_isobar_html(sections, metadata, subject)
        
        # Build plain text content
        plain_body = self._build_isobar_plain(sections, metadata, subject)
        
        return FormattedEmail(
            subject=subject,
            html_body=html_body,
            plain_body=plain_body,
            metadata={
                'prompt_type': 'ISOBAR',
                'severity': severity,
                'formatted_at': datetime.now(timezone.utc).isoformat()
            }
        )
    
    def _determine_severity(self, rule_level: int) -> str:
        """Map rule level to severity"""
        if rule_level >= 12:
            return "CRITICAL"
        elif rule_level >= 9:
            return "HIGH"
        elif rule_level >= 6:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _build_isobar_html(self, sections: Dict[str, str], metadata: Dict[str, Any], subject: str) -> str:
        """Build HTML for ISOBAR format"""
        timestamp_str = self._format_timestamp(metadata.get('timestamp', ''))
        
        # Header section
        header = f"""
        <div style="background: linear-gradient(135deg, {BRAND_COLOR} 0%, #34495e 100%); color: white; padding: 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 24px; font-weight: 600;">Security Alert - ISOBAR Analysis</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9; font-size: 16px;">{html_lib.escape(subject)}</p>
            <p style="margin: 4px 0 0 0; opacity: 0.8; font-size: 14px;">Generated: {timestamp_str}</p>
        </div>
        """
        
        # Section mapping for ISOBAR
        isobar_sections = [
            ('identify', 'I - IDENTIFY', '#e74c3c'),
            ('situation', 'S - SITUATION', '#f39c12'),
            ('observations', 'O - OBSERVATIONS', '#3498db'),
            ('background', 'B - BACKGROUND', '#9b59b6'),
            ('assessment', 'A - ASSESSMENT & ACTIONS', '#e67e22'),
            ('recommendations', 'R - RECOMMENDATIONS & RESPONSE', '#27ae60')
        ]
        
        cards = []
        for section_key, section_title, color in isobar_sections:
            content = sections.get(section_key, sections.get(section_title.lower(), ''))
            if content:
                content = self._truncate_content(content)
                formatted_content = html_lib.escape(content).replace('\n\n', '<br><br>').replace('\n', '<br>')
                
                card = f"""
                <div style="background: white; border-left: 4px solid {color}; border-radius: 0 8px 8px 0; padding: 20px; margin: 16px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h2 style="color: {color}; margin: 0 0 12px 0; font-size: 18px; font-weight: 600;">{section_title}</h2>
                    <div style="color: #555; line-height: 1.6; font-size: 14px;">
                        {formatted_content}
                    </div>
                </div>
                """
                cards.append(card)
        
        # Footer
        footer = f"""
        <div style="background: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; text-align: center; border-top: 1px solid #e9ecef;">
            <p style="margin: 0; color: #6c757d; font-size: 14px;">
                Generated by {ORGANIZATION_NAME} | For support: <a href="mailto:{SUPPORT_EMAIL}" style="color: {BRAND_COLOR};">{SUPPORT_EMAIL}</a>
            </p>
        </div>
        """
        
        return f"""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>{html_lib.escape(subject)}</title></head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px;">
            <div style="max-width: 800px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                {header}
                <div style="padding: 0 24px 24px 24px;">
                    {''.join(cards)}
                </div>
                {footer}
            </div>
        </body></html>
        """
    
    def _build_isobar_plain(self, sections: Dict[str, str], metadata: Dict[str, Any], subject: str) -> str:
        """Build plain text for ISOBAR format"""
        lines = [
            f"SECURITY ALERT - ISOBAR ANALYSIS",
            f"=" * 50,
            f"Subject: {subject}",
            f"Generated: {self._format_timestamp(metadata.get('timestamp', ''))}",
            f"Alert ID: {metadata.get('alert_id', 'Unknown')}",
            f"System: {metadata.get('agent_name', 'Unknown')}",
            "",
        ]
        
        isobar_sections = [
            ('identify', 'I - IDENTIFY'),
            ('situation', 'S - SITUATION'),
            ('observations', 'O - OBSERVATIONS'),
            ('background', 'B - BACKGROUND'),
            ('assessment', 'A - ASSESSMENT & ACTIONS'),
            ('recommendations', 'R - RECOMMENDATIONS & RESPONSE')
        ]
        
        for section_key, section_title in isobar_sections:
            content = sections.get(section_key, sections.get(section_title.lower(), ''))
            if content:
                content = self._truncate_content(content)
                lines.extend([
                    f"{section_title}",
                    "-" * len(section_title),
                    content,
                    ""
                ])
        
        lines.extend([
            f"Generated by {ORGANIZATION_NAME}",
            f"Support: {SUPPORT_EMAIL}"
        ])
        
        return "\n".join(lines)

class DelphiNotifyFormatter(BaseEmailFormatter):
    """Formatter for Delphi Notify responses (user-friendly)"""
    
    def format(self, data: Dict[str, Any]) -> FormattedEmail:
        """Format Delphi Notify structured data"""
        sections = data.get('sections', {})
        metadata = data.get('metadata', {})
        
        # Extract key information
        agent_name = metadata.get('agent_name', 'Your Computer')
        alert_id = metadata.get('alert_id', 'Unknown')
        
        # Create user-friendly subject
        summary = sections.get('summary', '')
        if 'LOW RISK' in summary.upper():
            risk_level = "Low Risk"
        elif 'MEDIUM RISK' in summary.upper():
            risk_level = "Medium Risk"
        elif 'HIGH RISK' in summary.upper():
            risk_level = "High Risk"
        else:
            risk_level = "Security Notice"
        
        subject = f"{risk_level} - Security Alert for {agent_name}"
        
        # Build content
        html_body = self._build_delphi_html(sections, metadata, subject)
        plain_body = self._build_delphi_plain(sections, metadata, subject)
        
        return FormattedEmail(
            subject=subject,
            html_body=html_body,
            plain_body=plain_body,
            metadata={
                'prompt_type': 'DELPHI_NOTIFY',
                'risk_level': risk_level,
                'formatted_at': datetime.now(timezone.utc).isoformat()
            }
        )
    
    def _build_delphi_html(self, sections: Dict[str, str], metadata: Dict[str, Any], subject: str) -> str:
        """Build HTML for Delphi Notify format"""
        timestamp_str = self._format_timestamp(metadata.get('timestamp', ''))
        
        # Friendly header
        header = f"""
        <div style="background: linear-gradient(135deg, #3498db 0%, #2980b9 100%); color: white; padding: 24px; border-radius: 8px 8px 0 0;">
            <h1 style="margin: 0; font-size: 22px; font-weight: 600;">🛡️ Security Alert</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9; font-size: 16px;">{html_lib.escape(subject)}</p>
            <p style="margin: 4px 0 0 0; opacity: 0.8; font-size: 14px;">{timestamp_str}</p>
        </div>
        """
        
        # Delphi section mapping
        delphi_sections = [
            ('summary', 'Summary', '#3498db', '📋'),
            ('what_happened', 'What Happened', '#e74c3c', '🔍'),
            ('further_investigation', 'Further Investigation', '#f39c12', '🔎'),
            ('what_to_do', 'What To Do', '#27ae60', '✅'),
            ('how_to_check', 'How To Check', '#9b59b6', '👀'),
            ('how_to_prevent', 'How To Prevent This In Future', '#34495e', '🛡️'),
            ('what_to_ask_next', 'What To Ask Next', '#16a085', '❓')
        ]
        
        cards = []
        for section_key, section_title, color, icon in delphi_sections:
            content = sections.get(section_key, '')
            if content:
                content = self._truncate_content(content)
                formatted_content = html_lib.escape(content).replace('\n\n', '<br><br>').replace('\n', '<br>')
                
                card = f"""
                <div style="background: white; border-radius: 8px; padding: 20px; margin: 16px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-left: 4px solid {color};">
                    <h2 style="color: {color}; margin: 0 0 12px 0; font-size: 16px; font-weight: 600;">
                        {icon} {section_title}
                    </h2>
                    <div style="color: #555; line-height: 1.6; font-size: 14px;">
                        {formatted_content}
                    </div>
                </div>
                """
                cards.append(card)
        
        # Friendly footer
        footer = f"""
        <div style="background: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; text-align: center;">
            <p style="margin: 0 0 8px 0; color: #6c757d; font-size: 14px;">
                This alert was created to help keep you safe online.
            </p>
            <p style="margin: 0; color: #6c757d; font-size: 14px;">
                Questions? Contact us: <a href="mailto:{SUPPORT_EMAIL}" style="color: #3498db;">{SUPPORT_EMAIL}</a>
            </p>
        </div>
        """
        
        return f"""
        <!DOCTYPE html>
        <html><head><meta charset="utf-8"><title>{html_lib.escape(subject)}</title></head>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; margin: 0; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                {header}
                <div style="padding: 0 24px 24px 24px;">
                    {''.join(cards)}
                </div>
                {footer}
            </div>
        </body></html>
        """
    
    def _build_delphi_plain(self, sections: Dict[str, str], metadata: Dict[str, Any], subject: str) -> str:
        """Build plain text for Delphi Notify format"""
        lines = [
            f"SECURITY ALERT",
            f"=" * 30,
            f"{subject}",
            f"Generated: {self._format_timestamp(metadata.get('timestamp', ''))}",
            "",
        ]
        
        delphi_sections = [
            ('summary', 'SUMMARY'),
            ('what_happened', 'WHAT HAPPENED'),
            ('further_investigation', 'FURTHER INVESTIGATION'),
            ('what_to_do', 'WHAT TO DO'),
            ('how_to_check', 'HOW TO CHECK'),
            ('how_to_prevent', 'HOW TO PREVENT THIS IN FUTURE'),
            ('what_to_ask_next', 'WHAT TO ASK NEXT')
        ]
        
        for section_key, section_title in delphi_sections:
            content = sections.get(section_key, '')
            if content:
                content = self._truncate_content(content)
                lines.extend([
                    f"{section_title}:",
                    content,
                    ""
                ])
        
        lines.extend([
            "This alert was created to help keep you safe online.",
            f"Questions? Contact: {SUPPORT_EMAIL}"
        ])
        
        return "\n".join(lines)

class EmailFormatterFactory:
    """Factory for creating appropriate formatters based on prompt type"""
    
    @staticmethod
    def create_formatter(prompt_type: str) -> BaseEmailFormatter:
        """Create formatter based on prompt type"""
        if prompt_type in ['security_analysis', 'isobar']:
            return ISOBARFormatter()
        elif prompt_type in ['delphi_notify_short', 'delphi_notify_brief', 'delphi_brief']:
            return DelphiNotifyFormatter()
        elif prompt_type in ['executive_summary', 'investigation_guide']:
            return ISOBARFormatter()  # These use similar structured format
        else:
            log.warning("Unknown prompt type '%s', using Delphi Notify formatter", prompt_type)
            return DelphiNotifyFormatter()

# ───── DATABASE OPERATIONS ─────────────────────────────────
class DatabaseManager:
    """Manage database operations with proper error handling"""
    
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.conn = None
        
    def connect(self) -> psycopg2.extensions.connection:
        """Connect to database with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.conn = psycopg2.connect(self.dsn)
                self.conn.autocommit = True
                log.info("Connected to PostgreSQL")
                return self.conn
            except psycopg2.OperationalError as e:
                if attempt < max_retries - 1:
                    wait_time = 5 * (attempt + 1)
                    log.warning("Database connection failed, retrying in %ds: %s", wait_time, e)
                    time.sleep(wait_time)
                else:
                    log.critical("Failed to connect to database after %d attempts", max_retries)
                    raise
                    
    def ensure_connection(self):
        """Ensure database connection is alive"""
        try:
            if self.conn and not self.conn.closed:
                self.conn.cursor().execute("SELECT 1")
            else:
                self.connect()
        except Exception:
            log.warning("Database connection lost, reconnecting...")
            self.connect()
            
    def fetch_alerts_to_format(self, batch_size: int) -> List[Dict[str, Any]]:
        """Fetch batch of alerts ready for formatting"""
        self.ensure_connection()
        
        # FIXED: Query aligned with schema.sql structure and correct state value
        sql = """
            SELECT
                a.id,
                a.alert_hash,
                a.rule_id,
                a.rule_level,
                a.rule_desc,
                a.structured_data,
                a.structured_at,
                a.prompt_type,
                a.ingest_timestamp,
                ag.name as agent_name,
                ag.ip as agent_ip,
                ag.os as agent_os
            FROM alerts a
            JOIN agents ag ON ag.id = a.agent_id
            WHERE a.state = %s
              AND a.structured_data IS NOT NULL
              AND a.archived_at IS NULL
            ORDER BY a.rule_level DESC, a.structured_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_STRUCTURED, batch_size))
                alerts = cur.fetchall()
                
                # Parse JSON fields safely
                for alert in alerts:
                    if isinstance(alert.get('structured_data'), str):
                        try:
                            alert['structured_data'] = json.loads(alert['structured_data'])
                        except json.JSONDecodeError as e:
                            log.warning("Invalid JSON in structured_data for alert %s: %s", 
                                       alert['id'], e)
                            alert['structured_data'] = {}
                            
                return [dict(alert) for alert in alerts]
                
        except Exception as e:
            log.error("Failed to fetch alerts: %s", e)
            return []
            
    def save_formatted_data(self, alert_id: int, formatted_email: FormattedEmail):
        """Save formatted data and update alert state"""
        self.ensure_connection()
        
        formatted_data = {
            'subject': formatted_email.subject,
            'html_body': formatted_email.html_body,
            'plain_body': formatted_email.plain_body,
            'metadata': formatted_email.metadata
        }
        
        sql = """
            UPDATE alerts
            SET formatted_data = %s::jsonb,
                state = %s,
                formatted_at = NOW()
            WHERE id = %s
        """
        
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (json.dumps(formatted_data), STATE_FORMATTED, alert_id))
                
                # Notify next worker (email sender)
                cur.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, str(alert_id)))
                
            log.info("Formatted alert %s and notified %s", alert_id, NOTIFY_CHANNEL)
            
        except Exception as e:
            log.error("Failed to save formatted data for alert %s: %s", alert_id, e)
            raise
            
    def get_formatting_stats(self) -> Dict[str, Any]:
        """Get formatting statistics for monitoring"""
        self.ensure_connection()
        
        sql = """
            SELECT 
                COUNT(*) FILTER (WHERE state = %s) as pending_formatting,
                COUNT(*) FILTER (WHERE state = %s AND formatted_at > NOW() - INTERVAL '1 hour') as formatted_last_hour,
                COUNT(*) FILTER (WHERE state = %s AND formatted_at > NOW() - INTERVAL '24 hours') as formatted_last_day
            FROM alerts
            WHERE archived_at IS NULL
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_STRUCTURED, STATE_FORMATTED, STATE_FORMATTED))
                result = cur.fetchone()
                return dict(result) if result else {}
        except Exception as e:
            log.warning("Failed to get formatting stats: %s", e)
            return {}

# ───── MAIN SERVICE LOGIC ─────────────────────────────────
class EmailFormatterService:
    """Main service orchestrator"""
    
    def __init__(self):
        self.shutdown = False
        self.db = DatabaseManager(PG_DSN)
        self.stats = {
            'formatted': 0,
            'failed': 0,
            'errors': 0
        }
        self.stats_report_interval = 300  # 5 minutes
        self.last_stats_report = time.time()
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        log.info("Received signal %d, initiating shutdown", signum)
        self.shutdown = True
        notifier.status("Shutting down gracefully")
        notifier.stopping()
        
    def run(self):
        """Main service loop"""
        log.info("Email Formatter Service starting...")
        notifier.ready()
        notifier.status("Starting email formatter service")
        
        # Connect to database
        try:
            self.db.connect()
        except Exception as e:
            log.critical("Database connection failed: %s", e)
            notifier.status("Database connection failed")
            sys.exit(1)
            
        # Process any backlog
        self._process_backlog()
        
        # Main event loop
        self._run_event_loop()
        
    def _process_backlog(self):
        """Process any queued alerts on startup"""
        log.info("Processing backlog...")
        backlog_count = 0
        
        while not self.shutdown:
            alerts = self.db.fetch_alerts_to_format(BATCH_SIZE)
            if not alerts:
                break
                
            for alert in alerts:
                if self.shutdown:
                    break
                self._process_alert(alert)
                backlog_count += 1
                notifier.watchdog()
                
        if backlog_count > 0:
            log.info("Processed %d alerts from backlog", backlog_count)
            
    def _run_event_loop(self):
        """Main event loop with PostgreSQL LISTEN/NOTIFY"""
        listen_conn = self.db.connect()
        cursor = listen_conn.cursor()
        cursor.execute(f"LISTEN {LISTEN_CHANNEL};")
        
        log.info("Listening for notifications on channel: %s", LISTEN_CHANNEL)
        notifier.status(f"Listening on {LISTEN_CHANNEL}")
        
        while not self.shutdown:
            notifier.watchdog()
            
            # Report statistics periodically
            if time.time() - self.last_stats_report > self.stats_report_interval:
                self._report_statistics()
                
            # Wait for notifications
            if select.select([listen_conn], [], [], 5.0)[0]:
                listen_conn.poll()
                
                # Process all pending notifications
                while listen_conn.notifies:
                    notify = listen_conn.notifies.pop(0)
                    try:
                        self._process_notification_batch()
                    except Exception as e:
                        log.exception("Error processing notification: %s", e)
                        self.stats['errors'] += 1
                        
    def _process_notification_batch(self):
        """Process a batch of alerts when notified"""
        alerts = self.db.fetch_alerts_to_format(BATCH_SIZE)
        
        for alert in alerts:
            if self.shutdown:
                break
            self._process_alert(alert)
            notifier.watchdog()
            
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a single alert"""
        alert_id = alert['id']
        prompt_type = alert.get('prompt_type', 'unknown')
        
        log.info("Formatting alert %s (prompt_type: %s)", alert_id, prompt_type)
        
        try:
            # Get structured data
            structured_data = alert.get('structured_data', {})
            if not structured_data:
                log.warning("Alert %s has no structured data", alert_id)
                self.stats['failed'] += 1
                return
            
            # Add metadata
            structured_data['metadata'] = {
                'alert_id': alert_id,
                'alert_hash': alert.get('alert_hash'),
                'rule_id': alert.get('rule_id'),
                'rule_level': alert.get('rule_level'),
                'rule_desc': alert.get('rule_desc'),
                'agent_name': alert.get('agent_name'),
                'agent_ip': alert.get('agent_ip'),
                'agent_os': alert.get('agent_os'),
                'timestamp': alert.get('structured_at'),
                'prompt_type': prompt_type
            }
            
            # Create appropriate formatter
            formatter = EmailFormatterFactory.create_formatter(prompt_type)
            
            # Format the email
            formatted_email = formatter.format(structured_data)
            
            # Save to database
            self.db.save_formatted_data(alert_id, formatted_email)
            
            self.stats['formatted'] += 1
            log.info("Successfully formatted alert %s", alert_id)
            
        except Exception as e:
            log.error("Failed to format alert %s: %s", alert_id, e)
            self.stats['failed'] += 1
            
    def _report_statistics(self):
        """Report service statistics"""
        db_stats = self.db.get_formatting_stats()
        
        log.info("Formatting statistics: formatted=%d, failed=%d, errors=%d",
                self.stats['formatted'], self.stats['failed'], self.stats['errors'])
        
        pending = db_stats.get('pending_formatting', 0)
        notifier.status(f"Formatted: {self.stats['formatted']}, Pending: {pending}")
        
        self.last_stats_report = time.time()

# ───── ENTRY POINT ─────────────────────────────────────
def main():
    """Service entry point"""
    try:
        service = EmailFormatterService()
        service.run()
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as e:
        log.critical("Fatal error: %s", e, exc_info=True)
        notifier.status(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        log.info("Email Formatter Service stopped")
        notifier.stopping()

if __name__ == "__main__":
    main()