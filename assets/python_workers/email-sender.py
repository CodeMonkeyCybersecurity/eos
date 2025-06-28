#!/usr/bin/env python3
# /usr/local/bin/email-sender.py
# stanley:stanley 0750
"""
Email Sender Worker - Final stage of the Delphi pipeline
Sends formatted security alerts via SMTP with intelligent routing
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
from typing import Dict, Any, Optional, List, Tuple
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from dataclasses import dataclass
from enum import Enum

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*_a, **_kw): pass

try:
    import sdnotify
except ImportError:
    sdnotify = None

# ───── CONFIGURATION CLASSES ─────────────────────────────
# Using dataclasses for better configuration management
@dataclass
class SMTPConfig:
    """SMTP configuration with validation"""
    host: str
    port: int
    user: str
    password: str
    use_tls: bool
    from_email: str
    from_name: str = "Delphi Security Alerts"
    
    def validate(self) -> List[str]:
        """Validate SMTP configuration"""
        errors = []
        if not self.host:
            errors.append("SMTP host is required")
        if not 0 < self.port < 65536:
            errors.append("Invalid SMTP port")
        if not self.from_email or '@' not in self.from_email:
            errors.append("Invalid from email address")
        return errors

class AlertPriority(Enum):
    """Alert priority levels for routing decisions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def from_rule_level(cls, level: int) -> 'AlertPriority':
        """Convert Wazuh rule level to priority"""
        if level >= 12:
            return cls.CRITICAL
        elif level >= 9:
            return cls.HIGH
        elif level >= 6:
            return cls.MEDIUM
        else:
            return cls.LOW

# ───── ENVIRONMENT SETUP ─────────────────────────────────
# Load environment variables with clear naming
load_dotenv("/opt/stackstorm/packs/delphi/.env")

# Database configuration
PG_DSN = os.getenv("PG_DSN", "").strip()
if not PG_DSN:
    print("FATAL: PG_DSN environment variable is required", file=sys.stderr)
    sys.exit(1)

# SMTP configuration with consistent naming
smtp_config = SMTPConfig(
    host=os.getenv("SMTP_HOST", "localhost"),
    port=int(os.getenv("SMTP_PORT", "587")),
    user=os.getenv("SMTP_USER", ""),
    password=os.getenv("SMTP_PASSWORD", ""),
    use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
    from_email=os.getenv("SMTP_FROM", "alerts@example.com"),
    from_name=os.getenv("SMTP_FROM_NAME", "Delphi Security Alerts")
)

# Validate configuration
config_errors = smtp_config.validate()
if config_errors:
    print(f"FATAL: Configuration errors: {'; '.join(config_errors)}", file=sys.stderr)
    sys.exit(1)

# Pipeline configuration
LISTEN_CHANNEL = "alert_formatted"
STATE_FORMATTED = "formatted"  # This should match your actual state enum
STATE_SENT = "sent"

# Email routing configuration
DEFAULT_RECIPIENTS = os.getenv("DEFAULT_RECIPIENTS", "").split(",")
CRITICAL_RECIPIENTS = os.getenv("CRITICAL_RECIPIENTS", "").split(",")
BUSINESS_HOURS_START = int(os.getenv("BUSINESS_HOURS_START", "9"))
BUSINESS_HOURS_END = int(os.getenv("BUSINESS_HOURS_END", "17"))

# Performance configuration
BATCH_SIZE = int(os.getenv("EMAIL_BATCH_SIZE", "10"))
MAX_RECIPIENTS = int(os.getenv("MAX_RECIPIENTS", "20"))
RETRY_ATTEMPTS = int(os.getenv("EMAIL_RETRY_ATTEMPTS", "3"))
RETRY_DELAY = int(os.getenv("EMAIL_RETRY_DELAY", "60"))

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configure structured logging with proper rotation"""
    logger = logging.getLogger("email-sender")
    logger.setLevel(logging.INFO)

    # File handler with rotation
    handler = RotatingFileHandler(
        "/var/log/stackstorm/email-sender.log",
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    
    # Structured logging format
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(funcName)s:%(lineno)d - %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    # Console handler for development
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

# ───── EMAIL SENDER CLASS ─────────────────────────────────
class IntelligentEmailSender:
    """Enhanced email sender with routing logic and monitoring"""
    
    def __init__(self, config: SMTPConfig):
        self.config = config
        self.stats = {
            "sent": 0,
            "failed": 0,
            "retried": 0
        }
        
    def determine_recipients(self, alert_data: Dict[str, Any]) -> List[str]:
        """
        Intelligently determine recipients based on alert characteristics
        
        This is where you implement your routing logic:
        - Rule severity mapping
        - Time-based routing
        - Team assignments
        - Escalation paths
        """
        recipients = set()
        
        # Always include default recipients
        recipients.update(r.strip() for r in DEFAULT_RECIPIENTS if r.strip())
        
        # Add critical recipients for high-severity alerts
        priority = AlertPriority.from_rule_level(alert_data.get('rule_level', 0))
        if priority in [AlertPriority.HIGH, AlertPriority.CRITICAL]:
            recipients.update(r.strip() for r in CRITICAL_RECIPIENTS if r.strip())
        
        # Time-based routing example
        current_hour = datetime.now().hour
        if not (BUSINESS_HOURS_START <= current_hour < BUSINESS_HOURS_END):
            # Outside business hours - you might want different recipients
            on_call_email = os.getenv("ON_CALL_EMAIL")
            if on_call_email:
                recipients.add(on_call_email)
        
        # Agent-based routing example
        agent_name = alert_data.get('agent_name', '')
        if 'production' in agent_name.lower():
            prod_team_email = os.getenv("PRODUCTION_TEAM_EMAIL")
            if prod_team_email:
                recipients.add(prod_team_email)
        
        # Validate and limit recipients
        valid_recipients = [r for r in recipients if self._is_valid_email(r)]
        if len(valid_recipients) > MAX_RECIPIENTS:
            log.warning("Limiting recipients from %d to %d", 
                       len(valid_recipients), MAX_RECIPIENTS)
            valid_recipients = valid_recipients[:MAX_RECIPIENTS]
            
        return valid_recipients
    
    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation"""
        return bool(email and '@' in email and '.' in email.split('@')[1])
    
    def send_email(self, alert_data: Dict[str, Any], 
                   recipients: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Send email with proper error handling and monitoring
        
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        if not recipients:
            return False, "No valid recipients"
            
        formatted_data = alert_data.get('formatted_data', {})
        subject = formatted_data.get('subject', 'Delphi Security Alert')
        html_body = formatted_data.get('html_body', '')
        plain_body = formatted_data.get('plain_body', '')
        
        # Create message with proper headers
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = formataddr((self.config.from_name, self.config.from_email))
        msg['To'] = ', '.join(recipients)
        msg['X-Alert-ID'] = str(alert_data.get('id', 'unknown'))
        msg['X-Alert-Priority'] = AlertPriority.from_rule_level(
            alert_data.get('rule_level', 0)
        ).value
        
        # Add message ID for tracking
        msg['Message-ID'] = f"<alert-{alert_data.get('id')}@{self.config.host}>"
        
        # Attach parts
        if plain_body:
            msg.attach(MIMEText(plain_body, 'plain', 'utf-8'))
        if html_body:
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
            
        # Send with connection pooling and retry logic
        for attempt in range(RETRY_ATTEMPTS):
            try:
                self._send_via_smtp(msg, recipients)
                self.stats['sent'] += 1
                log.info("Email sent successfully for alert %s to %d recipients",
                        alert_data.get('id'), len(recipients))
                return True, None
                
            except smtplib.SMTPAuthenticationError as e:
                error = f"SMTP authentication failed: {e}"
                log.error(error)
                return False, error  # Don't retry auth failures
                
            except smtplib.SMTPRecipientsRefused as e:
                error = f"Recipients refused: {e}"
                log.error(error)
                return False, error  # Don't retry recipient issues
                
            except Exception as e:
                error = f"Send attempt {attempt + 1} failed: {e}"
                log.warning(error)
                self.stats['retried'] += 1
                
                if attempt < RETRY_ATTEMPTS - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))  # Exponential backoff
                else:
                    self.stats['failed'] += 1
                    return False, error
                    
        return False, "Max retry attempts exceeded"
    
    def _send_via_smtp(self, msg: MIMEMultipart, recipients: List[str]):
        """Send message via SMTP with proper connection handling"""
        with smtplib.SMTP(self.config.host, self.config.port) as server:
            server.set_debuglevel(0)  # Set to 1 for SMTP debugging
            
            if self.config.use_tls:
                server.starttls()
                
            if self.config.user and self.config.password:
                server.login(self.config.user, self.config.password)
                
            server.send_message(msg, to_addrs=recipients)
    
    def get_stats(self) -> Dict[str, int]:
        """Get sending statistics"""
        return self.stats.copy()

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
                    log.warning("Database connection failed, retrying in %ds: %s", 
                               wait_time, e)
                    time.sleep(wait_time)
                else:
                    log.critical("Failed to connect to database after %d attempts", 
                                max_retries)
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
            
    def fetch_alerts_to_send(self, batch_size: int) -> List[Dict[str, Any]]:
        """Fetch batch of alerts ready for sending"""
        self.ensure_connection()
        
        # Note: You'll need to adjust this query based on your actual state names
        sql = """
            SELECT
                a.id,
                a.alert_hash,
                a.rule_level,
                a.formatted_data,
                a.formatted_at,
                a.email_retry_count,
                ag.name as agent_name,
                ag.ip as agent_ip
            FROM alerts a
            JOIN agents ag ON ag.id = a.agent_id
            WHERE a.state = %s
              AND (a.email_retry_count IS NULL OR a.email_retry_count < %s)
            ORDER BY a.rule_level DESC, a.formatted_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_FORMATTED, RETRY_ATTEMPTS, batch_size))
                alerts = cur.fetchall()
                
                # Parse JSON fields
                for alert in alerts:
                    if isinstance(alert.get('formatted_data'), str):
                        try:
                            alert['formatted_data'] = json.loads(alert['formatted_data'])
                        except json.JSONDecodeError:
                            log.warning("Invalid JSON in formatted_data for alert %s", 
                                       alert['id'])
                            alert['formatted_data'] = {}
                            
                return alerts
                
        except Exception as e:
            log.error("Failed to fetch alerts: %s", e)
            return []
            
    def mark_alert_sent(self, alert_id: int, recipients: List[str]):
        """Mark alert as successfully sent"""
        self.ensure_connection()
        
        sql = """
            UPDATE alerts
            SET state = %s,
                alert_sent_at = NOW(),
                email_recipients = %s::jsonb
            WHERE id = %s
        """
        
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (STATE_SENT, json.dumps(recipients), alert_id))
            log.debug("Alert %s marked as sent", alert_id)
        except Exception as e:
            log.error("Failed to mark alert %s as sent: %s", alert_id, e)
            
    def mark_alert_failed(self, alert_id: int, error_message: str):
        """Record email sending failure"""
        self.ensure_connection()
        
        sql = """
            UPDATE alerts
            SET email_error = %s,
                email_retry_count = COALESCE(email_retry_count, 0) + 1
            WHERE id = %s
        """
        
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (error_message[:500], alert_id))  # Limit error length
            log.debug("Alert %s marked as failed: %s", alert_id, error_message)
        except Exception as e:
            log.error("Failed to record error for alert %s: %s", alert_id, e)

# ───── MAIN SERVICE LOGIC ─────────────────────────────────
class EmailSenderService:
    """Main service orchestrator"""
    
    def __init__(self):
        self.shutdown = False
        self.db = DatabaseManager(PG_DSN)
        self.sender = IntelligentEmailSender(smtp_config)
        self.stats_report_interval = 300  # Report stats every 5 minutes
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
        """Main service loop with batch processing"""
        log.info("Email Sender Service starting...")
        notifier.ready()
        notifier.status(f"Connected to {smtp_config.host}:{smtp_config.port}")
        
        # Test SMTP connection
        try:
            self.sender._send_via_smtp(
                self._create_test_message(),
                [smtp_config.from_email]
            )
            log.info("SMTP test successful")
        except Exception as e:
            log.critical("SMTP test failed: %s", e)
            notifier.status("SMTP test failed - check configuration")
            sys.exit(1)
            
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
        
    def _create_test_message(self) -> MIMEMultipart:
        """Create a test message for SMTP validation"""
        msg = MIMEMultipart()
        msg['Subject'] = "Delphi Email Sender - Test Message"
        msg['From'] = formataddr((smtp_config.from_name, smtp_config.from_email))
        msg['To'] = smtp_config.from_email
        msg.attach(MIMEText("This is a test message from Delphi Email Sender", 'plain'))
        return msg
        
    def _process_backlog(self):
        """Process any queued alerts on startup"""
        log.info("Checking for backlog...")
        backlog_count = 0
        
        while not self.shutdown:
            alerts = self.db.fetch_alerts_to_send(BATCH_SIZE)
            if not alerts:
                break
                
            for alert in alerts:
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
                
            # Wait for notifications with timeout
            if select.select([listen_conn], [], [], 5.0)[0]:
                listen_conn.poll()
                
                # Process all pending notifications
                while listen_conn.notifies:
                    notify = listen_conn.notifies.pop(0)
                    try:
                        # Process batch instead of single alert
                        self._process_notification_batch()
                    except Exception as e:
                        log.exception("Error processing notification: %s", e)
                        
    def _process_notification_batch(self):
        """Process a batch of alerts when notified"""
        alerts = self.db.fetch_alerts_to_send(BATCH_SIZE)
        
        for alert in alerts:
            if self.shutdown:
                break
            self._process_alert(alert)
            notifier.watchdog()
            
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a single alert"""
        alert_id = alert['id']
        log.info("Processing alert %s (level %d)", alert_id, alert['rule_level'])
        
        # Determine recipients
        recipients = self.sender.determine_recipients(alert)
        if not recipients:
            log.warning("No recipients for alert %s", alert_id)
            self.db.mark_alert_failed(alert_id, "No recipients configured")
            return
            
        # Send email
        success, error = self.sender.send_email(alert, recipients)
        
        if success:
            self.db.mark_alert_sent(alert_id, recipients)
        else:
            self.db.mark_alert_failed(alert_id, error or "Unknown error")
            
    def _report_statistics(self):
        """Report service statistics"""
        stats = self.sender.get_stats()
        log.info("Email statistics: sent=%d, failed=%d, retried=%d",
                stats['sent'], stats['failed'], stats['retried'])
        notifier.status(f"Sent: {stats['sent']}, Failed: {stats['failed']}")
        self.last_stats_report = time.time()

# ───── ENTRY POINT ─────────────────────────────────────
def main():
    """Service entry point"""
    try:
        service = EmailSenderService()
        service.run()
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as e:
        log.critical("Fatal error: %s", e, exc_info=True)
        notifier.status(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        log.info("Email Sender Service stopped")
        notifier.stopping()

if __name__ == "__main__":
    main()