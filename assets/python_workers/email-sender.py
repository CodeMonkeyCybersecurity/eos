#!/usr/bin/env python3
# /usr/local/bin/email-sender.py
# stanley:stanley 0750
"""
Email Sender Worker - Final stage of the Wazuh pipeline
Sends formatted security alerts via SMTP with intelligent routing

IMPROVEMENTS:
- Fixed state transition logic for failed alerts
- Aligned environment variables with .env template
- Added missing imports and proper error handling
- Implemented circuit breaker pattern for SMTP failures
- Enhanced batch processing and connection management
- Added comprehensive monitoring and health checks
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
import psycopg2.extras  # FIXED: Added missing import
from datetime import datetime, timezone, timedelta
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
@dataclass
class SMTPConfig:
    """SMTP configuration with validation"""
    host: str
    port: int
    user: str
    password: str
    use_tls: bool
    from_email: str
    from_name: str = "Wazuh Security Alerts"
    
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

class CircuitBreaker:
    """Circuit breaker pattern for SMTP failures"""
    def __init__(self, failure_threshold: int = 5, timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure = None
        self.state = "closed"  # closed, open, half-open
        
    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection"""
        if self.state == "open":
            if self.last_failure and (time.time() - self.last_failure) > self.timeout:
                self.state = "half-open"
                log.info("Circuit breaker transitioning to half-open")
            else:
                raise Exception("Circuit breaker is open - SMTP temporarily disabled")
                
        try:
            result = func(*args, **kwargs)
            if self.state == "half-open":
                self.reset()
            return result
        except Exception as e:
            self.record_failure()
            raise e
            
    def record_failure(self):
        """Record a failure and potentially open the circuit"""
        self.failure_count += 1
        self.last_failure = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            log.error("Circuit breaker opened after %d failures", self.failure_count)
            
    def reset(self):
        """Reset the circuit breaker to closed state"""
        self.failure_count = 0
        self.last_failure = None
        self.state = "closed"
        log.info("Circuit breaker reset to closed state")

# ───── ENVIRONMENT SETUP ─────────────────────────────────
# Load environment variables with clear naming
load_dotenv("/opt/stackstorm/packs/wazuh/.env")

# Database configuration
PG_DSN = os.getenv("PG_DSN", "").strip()
if not PG_DSN:
    print("FATAL: PG_DSN environment variable is required", file=sys.stderr)
    sys.exit(1)

# FIXED: SMTP configuration aligned with .env template
smtp_config = SMTPConfig(
    host=os.getenv("MAILCOW_SMTP_HOST", "localhost"),
    port=int(os.getenv("MAILCOW_SMTP_PORT", "587")),
    user=os.getenv("MAILCOW_SMTP_USER", ""),
    password=os.getenv("MAILCOW_SMTP_PASS", ""),
    use_tls=os.getenv("MAILCOW_USE_TLS", "true").lower() == "true",
    from_email=os.getenv("MAILCOW_FROM", "alerts@example.com"),
    from_name=os.getenv("MAILCOW_FROM_NAME", "Wazuh Security Alerts")
)

# Validate configuration
config_errors = smtp_config.validate()
if config_errors:
    print(f"FATAL: Configuration errors: {'; '.join(config_errors)}", file=sys.stderr)
    sys.exit(1)

# Pipeline configuration - matches schema.sql notification channels
LISTEN_CHANNEL = "alert_formatted"
STATE_FORMATTED = "formatted"
STATE_SENT = "sent"
STATE_FAILED = "failed"  # ADDED: Explicit failed state

# Email routing configuration
DEFAULT_RECIPIENTS = [r.strip() for r in os.getenv("MAILCOW_TO", "").split(",") if r.strip()]
CRITICAL_RECIPIENTS = [r.strip() for r in os.getenv("CRITICAL_RECIPIENTS", "").split(",") if r.strip()]
SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "")
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
        self.circuit_breaker = CircuitBreaker()
        self.stats = {
            "sent": 0,
            "failed": 0,
            "retried": 0,
            "circuit_breaker_opens": 0
        }
        
    def determine_recipients(self, alert_data: Dict[str, Any]) -> List[str]:
        """
        Intelligently determine recipients based on alert characteristics
        
        This implements your routing logic based on:
        - Rule severity mapping
        - Time-based routing  
        - Agent characteristics
        - Escalation paths
        """
        recipients = set()
        
        # Always include default recipients
        recipients.update(DEFAULT_RECIPIENTS)
        
        # Add critical recipients for high-severity alerts
        priority = AlertPriority.from_rule_level(alert_data.get('rule_level', 0))
        if priority in [AlertPriority.HIGH, AlertPriority.CRITICAL]:
            recipients.update(CRITICAL_RECIPIENTS)
        
        # Time-based routing - different teams for different hours
        current_hour = datetime.now().hour
        if not (BUSINESS_HOURS_START <= current_hour < BUSINESS_HOURS_END):
            # Outside business hours - add on-call if configured
            on_call_email = os.getenv("ON_CALL_EMAIL")
            if on_call_email:
                recipients.add(on_call_email)
        
        # Agent-based routing - production systems get special attention
        agent_name = alert_data.get('agent_name', '').lower()
        if any(keyword in agent_name for keyword in ['production', 'prod', 'critical']):
            prod_team_email = os.getenv("PRODUCTION_TEAM_EMAIL")
            if prod_team_email:
                recipients.add(prod_team_email)
        
        # Rule-based routing - certain rules go to specialized teams
        rule_id = alert_data.get('rule_id', 0)
        if rule_id in range(87000, 88000):  # Example: malware detection rules
            malware_team = os.getenv("MALWARE_TEAM_EMAIL")
            if malware_team:
                recipients.add(malware_team)
        
        # Validate and limit recipients
        valid_recipients = [r for r in recipients if self._is_valid_email(r)]
        if len(valid_recipients) > MAX_RECIPIENTS:
            log.warning("Limiting recipients from %d to %d", 
                       len(valid_recipients), MAX_RECIPIENTS)
            valid_recipients = valid_recipients[:MAX_RECIPIENTS]
        
        # Always include support email for critical alerts
        if priority == AlertPriority.CRITICAL and SUPPORT_EMAIL:
            if self._is_valid_email(SUPPORT_EMAIL) and SUPPORT_EMAIL not in valid_recipients:
                valid_recipients.append(SUPPORT_EMAIL)
            
        return valid_recipients
    
    def _is_valid_email(self, email: str) -> bool:
        """Enhanced email validation"""
        if not email or not isinstance(email, str):
            return False
        if '@' not in email:
            return False
        local, domain = email.split('@', 1)
        if not local or not domain or '.' not in domain:
            return False
        return True
    
    def send_email(self, alert_data: Dict[str, Any], 
                   recipients: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Send email with circuit breaker protection and proper error handling
        
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        if not recipients:
            return False, "No valid recipients"
            
        formatted_data = alert_data.get('formatted_data', {})
        if not formatted_data:
            return False, "No formatted data available"
            
        subject = formatted_data.get('subject', f"Wazuh Security Alert - Rule {alert_data.get('rule_id', 'Unknown')}")
        html_body = formatted_data.get('html_body', '')
        plain_body = formatted_data.get('plain_body', '')
        
        if not html_body and not plain_body:
            return False, "No email content available"
        
        # Create message with comprehensive headers
        msg = self._create_message(alert_data, recipients, subject, html_body, plain_body)
        
        # Send with circuit breaker protection
        try:
            self.circuit_breaker.call(self._send_via_smtp, msg, recipients)
            self.stats['sent'] += 1
            log.info("Email sent successfully for alert %s to %d recipients",
                    alert_data.get('id'), len(recipients))
            return True, None
            
        except Exception as e:
            error_msg = str(e)
            if "Circuit breaker is open" in error_msg:
                self.stats['circuit_breaker_opens'] += 1
                return False, "SMTP service temporarily unavailable"
            else:
                self.stats['failed'] += 1
                return False, error_msg
    
    def _create_message(self, alert_data: Dict[str, Any], recipients: List[str], 
                       subject: str, html_body: str, plain_body: str) -> MIMEMultipart:
        """Create properly formatted email message"""
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = formataddr((self.config.from_name, self.config.from_email))
        msg['To'] = ', '.join(recipients)
        
        # Headers for tracking and filtering
        msg['X-Alert-ID'] = str(alert_data.get('id', 'unknown'))
        msg['X-Alert-Priority'] = AlertPriority.from_rule_level(
            alert_data.get('rule_level', 0)
        ).value
        msg['X-Alert-Rule-ID'] = str(alert_data.get('rule_id', 'unknown'))
        msg['X-Agent-Name'] = alert_data.get('agent_name', 'unknown')
        
        # Message ID for tracking
        timestamp = int(time.time())
        msg['Message-ID'] = f"<alert-{alert_data.get('id', 'unknown')}-{timestamp}@wazuh.security>"
        
        # Add reply-to if support email is configured
        if SUPPORT_EMAIL:
            msg['Reply-To'] = SUPPORT_EMAIL
        
        # Attach content parts
        if plain_body:
            msg.attach(MIMEText(plain_body, 'plain', 'utf-8'))
        if html_body:
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
            
        return msg
    
    def _send_via_smtp(self, msg: MIMEMultipart, recipients: List[str]):
        """Send message via SMTP with proper connection handling"""
        with smtplib.SMTP(self.config.host, self.config.port, timeout=30) as server:
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
        
        # Query aligned with schema.sql structure
        sql = """
            SELECT
                a.id,
                a.alert_hash,
                a.rule_id,
                a.rule_level,
                a.rule_desc,
                a.formatted_data,
                a.formatted_at,
                a.email_retry_count,
                a.ingest_timestamp,
                ag.name as agent_name,
                ag.ip as agent_ip,
                ag.os as agent_os
            FROM alerts a
            JOIN agents ag ON ag.id = a.agent_id
            WHERE a.state = %s
              AND (a.email_retry_count IS NULL OR a.email_retry_count < %s)
              AND a.archived_at IS NULL
            ORDER BY a.rule_level DESC, a.formatted_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_FORMATTED, RETRY_ATTEMPTS, batch_size))
                alerts = cur.fetchall()
                
                # Parse JSON fields safely
                for alert in alerts:
                    if isinstance(alert.get('formatted_data'), str):
                        try:
                            alert['formatted_data'] = json.loads(alert['formatted_data'])
                        except json.JSONDecodeError:
                            log.warning("Invalid JSON in formatted_data for alert %s", 
                                       alert['id'])
                            alert['formatted_data'] = {}
                            
                return [dict(alert) for alert in alerts]
                
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
            log.debug("Alert %s marked as sent to %d recipients", alert_id, len(recipients))
        except Exception as e:
            log.error("Failed to mark alert %s as sent: %s", alert_id, e)
            
    def mark_alert_failed(self, alert_id: int, error_message: str, is_final: bool = False):
        """FIXED: Record email sending failure with proper state management"""
        self.ensure_connection()
        
        # First update: increment retry count and record error
        sql_update_error = """
            UPDATE alerts
            SET email_error = %s,
                email_retry_count = COALESCE(email_retry_count, 0) + 1
            WHERE id = %s
            RETURNING email_retry_count
        """
        
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql_update_error, (error_message[:500], alert_id))
                result = cur.fetchone()
                retry_count = result[0] if result else 0
                
                # If we've exhausted retries OR this is marked as final, transition to failed
                if retry_count >= RETRY_ATTEMPTS or is_final:
                    sql_fail = """
                        UPDATE alerts
                        SET state = %s
                        WHERE id = %s
                    """
                    cur.execute(sql_fail, (STATE_FAILED, alert_id))
                    log.error("Alert %s transitioned to failed state after %d attempts: %s", 
                             alert_id, retry_count, error_message)
                else:
                    log.warning("Alert %s failed (attempt %d/%d): %s", 
                               alert_id, retry_count, RETRY_ATTEMPTS, error_message)
                    
        except Exception as e:
            log.error("Failed to record error for alert %s: %s", alert_id, e)
    
    def get_pipeline_health(self) -> Dict[str, Any]:
        """Get current pipeline health metrics"""
        self.ensure_connection()
        
        sql = "SELECT * FROM pipeline_health WHERE state = %s"
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_FORMATTED,))
                result = cur.fetchone()
                return dict(result) if result else {}
        except Exception as e:
            log.warning("Failed to get pipeline health: %s", e)
            return {}

# ───── MAIN SERVICE LOGIC ─────────────────────────────────
class EmailSenderService:
    """Main service orchestrator with enhanced monitoring"""
    
    def __init__(self):
        self.shutdown = False
        self.db = DatabaseManager(PG_DSN)
        self.sender = IntelligentEmailSender(smtp_config)
        self.stats_report_interval = 300  # Report stats every 5 minutes
        self.last_stats_report = time.time()
        self.health_check_interval = 60  # Check health every minute
        self.last_health_check = time.time()
        
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
        """Main service loop with comprehensive startup checks"""
        log.info("Email Sender Service starting...")
        log.info("Configuration: Host=%s, Port=%d, TLS=%s", 
                smtp_config.host, smtp_config.port, smtp_config.use_tls)
        
        notifier.ready()
        notifier.status(f"Connected to {smtp_config.host}:{smtp_config.port}")
        
        # Test database connection
        try:
            self.db.connect()
            log.info("Database connection successful")
        except Exception as e:
            log.critical("Database connection failed: %s", e)
            notifier.status("Database connection failed")
            sys.exit(1)
        
        # Test SMTP connection (but don't send actual email)
        try:
            with smtplib.SMTP(smtp_config.host, smtp_config.port, timeout=10) as server:
                if smtp_config.use_tls:
                    server.starttls()
                if smtp_config.user and smtp_config.password:
                    server.login(smtp_config.user, smtp_config.password)
            log.info("SMTP connection test successful")
        except Exception as e:
            log.critical("SMTP connection test failed: %s", e)
            notifier.status("SMTP test failed - check configuration")
            sys.exit(1)
            
        # Process any backlog
        self._process_backlog()
        
        # Main event loop
        self._run_event_loop()
        
    def _process_backlog(self):
        """Process any queued alerts on startup"""
        log.info("Checking for backlog...")
        backlog_count = 0
        
        while not self.shutdown:
            alerts = self.db.fetch_alerts_to_send(BATCH_SIZE)
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
            
            # Periodic health and stats reporting
            current_time = time.time()
            if current_time - self.last_stats_report > self.stats_report_interval:
                self._report_statistics()
                
            if current_time - self.last_health_check > self.health_check_interval:
                self._check_health()
                
            # Wait for notifications with timeout
            if select.select([listen_conn], [], [], 5.0)[0]:
                listen_conn.poll()
                
                # Process all pending notifications
                while listen_conn.notifies:
                    notify = listen_conn.notifies.pop(0)
                    try:
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
        """Process a single alert with comprehensive error handling"""
        alert_id = alert['id']
        log.info("Processing alert %s (rule %d, level %d)", 
                alert_id, alert.get('rule_id', 0), alert['rule_level'])
        
        # Determine recipients using intelligent routing
        recipients = self.sender.determine_recipients(alert)
        if not recipients:
            log.warning("No recipients determined for alert %s", alert_id)
            self.db.mark_alert_failed(alert_id, "No recipients configured", is_final=True)
            return
            
        # Send email with proper error classification
        success, error = self.sender.send_email(alert, recipients)
        
        if success:
            self.db.mark_alert_sent(alert_id, recipients)
            log.info("Alert %s sent successfully to %d recipients", alert_id, len(recipients))
        else:
            # Classify error types for appropriate handling
            is_final = self._is_final_error(error)
            self.db.mark_alert_failed(alert_id, error or "Unknown error", is_final)
            
    def _is_final_error(self, error: str) -> bool:
        """Determine if an error should cause immediate failure (no retries)"""
        if not error:
            return False
            
        final_error_patterns = [
            "authentication failed",
            "recipients refused",
            "No recipients configured",
            "No formatted data available",
            "No email content available",
            "temporarily unavailable"  # Circuit breaker
        ]
        
        return any(pattern in error.lower() for pattern in final_error_patterns)
            
    def _check_health(self):
        """Perform health checks and report status"""
        try:
            health = self.db.get_pipeline_health()
            if health:
                count = health.get('count', 0)
                health_status = health.get('health_status', 'Unknown')
                notifier.status(f"Health: {health_status}, Pending: {count}")
                
                if health_status == 'ATTENTION NEEDED':
                    log.warning("Pipeline health needs attention: %d alerts pending", count)
                    
            self.last_health_check = time.time()
        except Exception as e:
            log.warning("Health check failed: %s", e)
            
    def _report_statistics(self):
        """Report comprehensive service statistics"""
        stats = self.sender.get_stats()
        circuit_breaker_state = self.sender.circuit_breaker.state
        
        log.info("Email statistics: sent=%d, failed=%d, retried=%d, cb_opens=%d, cb_state=%s",
                stats['sent'], stats['failed'], stats['retried'], 
                stats['circuit_breaker_opens'], circuit_breaker_state)
        
        notifier.status(f"Sent: {stats['sent']}, Failed: {stats['failed']}, CB: {circuit_breaker_state}")
        self.last_stats_report = time.time()

# ───── ENTRY POINT ─────────────────────────────────────
def main():
    """Service entry point with comprehensive error handling"""
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