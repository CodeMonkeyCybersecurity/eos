#!/usr/bin/env python3
# /usr/local/bin/email-structurer.py
# stanley:stanley 0750
"""
Email Structurer Worker - Phase 4 of Delphi Pipeline
Parses LLM responses into structured sections for email formatting

IMPROVEMENTS:
- Fixed state/channel alignment to match schema.sql ('analyzed' not 'summarized') 
- Simplified parser system focused on actual prompt formats
- Enhanced error handling with intelligent fallbacks
- Improved database schema alignment
- Streamlined circuit breaker implementation
- Better performance through targeted parsing
"""
import os
import sys
import re
import time
import select
import signal
import logging
import json
import psycopg2
import psycopg2.extensions
import psycopg2.extras
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Any, Optional, Tuple
from abc import ABC, abstractmethod
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
LISTEN_CHANNEL = "alert_analyzed"      # FIXED: Match schema.sql trigger
NOTIFY_CHANNEL = "alert_structured"   # Notify formatter when complete
STATE_ANALYZED = "analyzed"           # FIXED: Match schema.sql enum value
STATE_STRUCTURED = "structured"

# Performance configuration
BATCH_SIZE = int(os.getenv("STRUCTURER_BATCH_SIZE", "10"))
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("PARSER_FAILURE_THRESHOLD", "5"))
CIRCUIT_BREAKER_TIMEOUT = int(os.getenv("PARSER_FAILURE_TIMEOUT", "300"))

class PromptType(Enum):
    """Known prompt types from your LLM worker"""
    ISOBAR = "security_analysis"
    DELPHI_NOTIFY = "delphi_notify_short" 
    DELPHI_BRIEF = "delphi_notify_brief"
    EXECUTIVE = "executive_summary"
    INVESTIGATION = "investigation_guide"
    HYBRID = "hybrid"
    CUSTOM = "custom"

@dataclass
class ParseResult:
    """Container for parsing results"""
    success: bool
    sections: Dict[str, str]
    subject: str
    metadata: Dict[str, Any]
    error: Optional[str] = None
    parse_time_ms: float = 0.0

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configure structured logging"""
    logger = logging.getLogger("email-structurer")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        "/var/log/stackstorm/email-structurer.log",
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

# ───── PARSER BASE CLASS ─────────────────────────────────
class BaseParser(ABC):
    """Abstract base class for response parsers"""
    
    @abstractmethod
    def parse(self, response_text: str, alert_context: Dict[str, Any]) -> ParseResult:
        """Parse LLM response into structured format"""
        pass
        
    @abstractmethod
    def get_expected_sections(self) -> List[str]:
        """Get list of expected section names"""
        pass
        
    def generate_subject(self, sections: Dict[str, str], alert_context: Dict[str, Any]) -> str:
        """Generate email subject from parsed sections"""
        agent_name = alert_context.get('agent_name', 'Unknown System')
        rule_level = alert_context.get('rule_level', 0)
        
        # Default subject generation
        if rule_level >= 12:
            severity = "CRITICAL"
        elif rule_level >= 9:
            severity = "HIGH"
        elif rule_level >= 6:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return f"[{severity}] Security Alert - {agent_name}"

# ───── ISOBAR FRAMEWORK PARSER ─────────────────────────────
class ISOBARParser(BaseParser):
    """Parser for ISOBAR framework responses (security_analysis prompt)"""
    
    def get_expected_sections(self) -> List[str]:
        return [
            "identify", "situation", "observations", 
            "background", "assessment", "recommendations"
        ]
    
    def parse(self, response_text: str, alert_context: Dict[str, Any]) -> ParseResult:
        """Parse ISOBAR framework response"""
        start_time = time.perf_counter()
        
        try:
            sections = self._extract_isobar_sections(response_text)
            subject = self._generate_isobar_subject(sections, alert_context)
            
            metadata = {
                "format_type": "ISOBAR",
                "confidence_ratings": self._extract_confidence_ratings(response_text),
                "references": self._extract_references(response_text)
            }
            
            parse_time_ms = (time.perf_counter() - start_time) * 1000
            
            return ParseResult(
                success=len(sections) >= 3,  # Minimum viable ISOBAR report
                sections=sections,
                subject=subject,
                metadata=metadata,
                parse_time_ms=parse_time_ms
            )
            
        except Exception as e:
            parse_time_ms = (time.perf_counter() - start_time) * 1000
            return ParseResult(
                success=False,
                sections={},
                subject="Failed to Parse ISOBAR Response",
                metadata={"format_type": "ISOBAR"},
                error=str(e),
                parse_time_ms=parse_time_ms
            )
    
    def _extract_isobar_sections(self, text: str) -> Dict[str, str]:
        """Extract ISOBAR sections using pattern matching"""
        sections = {}
        
        # ISOBAR section patterns - flexible but specific
        patterns = {
            "identify": r"(?:^|\n)\*?\*?I\s*[-–—]\s*IDENTIFY\*?\*?(?:\s*\*?\*?Section Confidence[^\n]*)?[:\n](.*?)(?=(?:\n\*?\*?[SOBARD]\s*[-–—]|\Z))",
            "situation": r"(?:^|\n)\*?\*?S\s*[-–—]\s*SITUATION\*?\*?(?:\s*\*?\*?Section Confidence[^\n]*)?[:\n](.*?)(?=(?:\n\*?\*?[IOBARD]\s*[-–—]|\Z))",
            "observations": r"(?:^|\n)\*?\*?O\s*[-–—]\s*OBSERVATIONS\*?\*?(?:\s*\*?\*?Section Confidence[^\n]*)?[:\n](.*?)(?=(?:\n\*?\*?[ISOBABD]\s*[-–—]|\Z))",
            "background": r"(?:^|\n)\*?\*?B\s*[-–—]\s*BACKGROUND\*?\*?(?:\s*\*?\*?Section Confidence[^\n]*)?[:\n](.*?)(?=(?:\n\*?\*?[ISOAARD]\s*[-–—]|\Z))",
            "assessment": r"(?:^|\n)\*?\*?A\s*[-–—]\s*ASSESSMENT[^:\n]*\*?\*?(?:\s*\*?\*?Section Confidence[^\n]*)?[:\n](.*?)(?=(?:\n\*?\*?[ISOBBRD]\s*[-–—]|\Z))",
            "recommendations": r"(?:^|\n)\*?\*?R\s*[-–—]\s*RECOMMENDATIONS[^:\n]*\*?\*?(?:\s*\*?\*?Section Confidence[^\n]*)?[:\n](.*?)(?=(?:\n\*?\*?[ISOBAD]\s*[-–—]|\Z))"
        }
        
        for section_name, pattern in patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                content = match.group(1).strip()
                # Clean up the content
                content = re.sub(r'\n+', '\n', content)  # Collapse multiple newlines
                content = content.strip()
                if content:
                    sections[section_name] = content
        
        return sections
    
    def _generate_isobar_subject(self, sections: Dict[str, str], alert_context: Dict[str, Any]) -> str:
        """Generate subject for ISOBAR reports"""
        agent_name = alert_context.get('agent_name', 'Unknown System')
        rule_level = alert_context.get('rule_level', 0)
        
        # Try to extract severity from IDENTIFY section
        identify_section = sections.get('identify', '')
        severity_match = re.search(r'Severity Level:\s*([A-Z]+)', identify_section, re.IGNORECASE)
        
        if severity_match:
            severity = severity_match.group(1).upper()
        else:
            # Fallback to rule level mapping
            if rule_level >= 12:
                severity = "CRITICAL"
            elif rule_level >= 9:
                severity = "HIGH"  
            elif rule_level >= 6:
                severity = "MEDIUM"
            else:
                severity = "LOW"
                
        return f"[{severity}] Security Incident Analysis - {agent_name}"
    
    def _extract_confidence_ratings(self, text: str) -> Dict[str, str]:
        """Extract confidence ratings from ISOBAR sections"""
        confidence_pattern = r"Section Confidence:\s*\[?(\d+%?)\]?"
        matches = re.findall(confidence_pattern, text, re.IGNORECASE)
        
        # Map confidence ratings to sections (rough approximation)
        ratings = {}
        section_names = self.get_expected_sections()
        for i, match in enumerate(matches[:len(section_names)]):
            if i < len(section_names):
                ratings[section_names[i]] = match
                
        return ratings
    
    def _extract_references(self, text: str) -> List[str]:
        """Extract reference citations from ISOBAR text"""
        reference_patterns = [
            r"Reference:\s*([^\n]+)",
            r"References?:\s*([^\n]+)",
            r"\*Reference[s]?:\s*([^\n]+)"
        ]
        
        references = []
        for pattern in reference_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            references.extend(matches)
            
        return [ref.strip() for ref in references if ref.strip()]

# ───── DELPHI NOTIFY PARSER ─────────────────────────────
class DelphiNotifyParser(BaseParser):
    """Parser for Delphi Notify responses (user-friendly format)"""
    
    def get_expected_sections(self) -> List[str]:
        return [
            "summary", "what_happened", "further_investigation", 
            "what_to_do", "how_to_check", "how_to_prevent", "what_to_ask_next"
        ]
    
    def parse(self, response_text: str, alert_context: Dict[str, Any]) -> ParseResult:
        """Parse Delphi Notify response format"""
        start_time = time.perf_counter()
        
        try:
            sections = self._extract_delphi_sections(response_text)
            subject = self._generate_delphi_subject(sections, alert_context)
            
            metadata = {
                "format_type": "DELPHI_NOTIFY",
                "risk_level": self._extract_risk_level(sections.get('summary', '')),
                "confidence_indicators": self._extract_confidence_indicators(response_text)
            }
            
            parse_time_ms = (time.perf_counter() - start_time) * 1000
            
            return ParseResult(
                success=len(sections) >= 2 and 'summary' in sections,
                sections=sections,
                subject=subject,
                metadata=metadata,
                parse_time_ms=parse_time_ms
            )
            
        except Exception as e:
            parse_time_ms = (time.perf_counter() - start_time) * 1000
            return ParseResult(
                success=False,
                sections={},
                subject="Failed to Parse Delphi Notify Response",
                metadata={"format_type": "DELPHI_NOTIFY"},
                error=str(e),
                parse_time_ms=parse_time_ms
            )
    
    def _extract_delphi_sections(self, text: str) -> Dict[str, str]:
        """Extract Delphi Notify sections"""
        sections = {}
        
        # Section patterns for Delphi format
        section_patterns = {
            "summary": r"(?:^|\n)Summary:\s*(.*?)(?=(?:\n(?:What happened|Further investigation|What to do|How to check|How to prevent|What to ask):|$))",
            "what_happened": r"(?:^|\n)What happened(?:\s*\([^)]*\))?:\s*(.*?)(?=(?:\n(?:Summary|Further investigation|What to do|How to check|How to prevent|What to ask):|$))",
            "further_investigation": r"(?:^|\n)Further investigation(?:\s*\([^)]*\))?:\s*(.*?)(?=(?:\n(?:Summary|What happened|What to do|How to check|How to prevent|What to ask):|$))",
            "what_to_do": r"(?:^|\n)What to do(?:\s*\([^)]*\))?:\s*(.*?)(?=(?:\n(?:Summary|What happened|Further investigation|How to check|How to prevent|What to ask):|$))",
            "how_to_check": r"(?:^|\n)How to check(?:\s*\([^)]*\))?:\s*(.*?)(?=(?:\n(?:Summary|What happened|Further investigation|What to do|How to prevent|What to ask):|$))",
            "how_to_prevent": r"(?:^|\n)How to prevent this in future(?:\s*\([^)]*\))?:\s*(.*?)(?=(?:\n(?:Summary|What happened|Further investigation|What to do|How to check|What to ask):|$))",
            "what_to_ask_next": r"(?:^|\n)What to ask next:\s*(.*?)(?=(?:\n(?:Summary|What happened|Further investigation|What to do|How to check|How to prevent):|$))"
        }
        
        for section_name, pattern in section_patterns.items():
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                content = match.group(1).strip()
                if content:
                    sections[section_name] = content
        
        return sections
    
    def _extract_risk_level(self, summary: str) -> str:
        """Extract risk level from summary"""
        risk_pattern = r"\[(LOW|MEDIUM|HIGH)\s+RISK[^\]]*\]"
        match = re.search(risk_pattern, summary, re.IGNORECASE)
        return match.group(1).upper() if match else "UNKNOWN"
    
    def _extract_confidence_indicators(self, text: str) -> Dict[str, str]:
        """Extract confidence indicators from Delphi text"""
        # Pattern for confidence expressions like "fairly sure - 80%"
        confidence_pattern = r"(?:very likely|probably|might be|unsure|fairly confident|very sure|best guess)(?:\s*[-–—]\s*\d+%?)?"
        matches = re.findall(confidence_pattern, text, re.IGNORECASE)
        
        return {"confidence_expressions": matches}
    
    def _generate_delphi_subject(self, sections: Dict[str, str], alert_context: Dict[str, Any]) -> str:
        """Generate user-friendly subject for Delphi Notify"""
        agent_name = alert_context.get('agent_name', 'Your Computer')
        
        # Extract risk level from summary
        summary = sections.get('summary', '')
        risk_level = self._extract_risk_level(summary)
        
        if risk_level == "HIGH":
            return f"🚨 High Risk Security Alert - {agent_name}"
        elif risk_level == "MEDIUM":
            return f"⚠️  Medium Risk Security Alert - {agent_name}"
        elif risk_level == "LOW":
            return f"ℹ️  Low Risk Security Notice - {agent_name}"
        else:
            return f"🛡️ Security Alert - {agent_name}"

# ───── PARSER FACTORY ─────────────────────────────────
class ParserFactory:
    """Factory for creating appropriate parsers based on prompt type"""
    
    @staticmethod
    def create_parser(prompt_type: str) -> BaseParser:
        """Create parser based on prompt type"""
        if prompt_type in ['security_analysis', 'isobar']:
            return ISOBARParser()
        elif prompt_type in ['delphi_notify_short', 'delphi_notify_brief', 'delphi_brief']:
            return DelphiNotifyParser()
        elif prompt_type in ['executive_summary', 'investigation_guide']:
            return ISOBARParser()  # These use similar structured format
        else:
            log.warning("Unknown prompt type '%s', using Delphi Notify parser", prompt_type)
            return DelphiNotifyParser()  # Safe default for user-facing content

# ───── CIRCUIT BREAKER ─────────────────────────────────
class SimpleCircuitBreaker:
    """Simplified circuit breaker for parser failures"""
    
    def __init__(self, failure_threshold: int = 5, timeout_seconds: int = 300):
        self.failure_threshold = failure_threshold
        self.timeout = timedelta(seconds=timeout_seconds)
        self.failures: Dict[str, List[datetime]] = defaultdict(list)
        self.state: Dict[str, str] = defaultdict(lambda: "CLOSED")
        self.last_failure: Dict[str, datetime] = {}
        
    def record_failure(self, parser_type: str):
        """Record a parser failure"""
        now = datetime.now(timezone.utc)
        self.failures[parser_type].append(now)
        self.last_failure[parser_type] = now
        
        # Keep only recent failures
        self.failures[parser_type] = [
            f for f in self.failures[parser_type] 
            if f > now - timedelta(hours=1)
        ]
        
        # Check if we should trip the breaker
        if len(self.failures[parser_type]) >= self.failure_threshold:
            self.state[parser_type] = "OPEN"
            log.error("Circuit breaker OPEN for parser type: %s", parser_type)
            
    def record_success(self, parser_type: str):
        """Record a parser success"""
        if self.state[parser_type] != "CLOSED":
            log.info("Circuit breaker CLOSED for parser type: %s", parser_type)
        self.failures[parser_type].clear()
        self.state[parser_type] = "CLOSED"
        
    def allow_request(self, parser_type: str) -> bool:
        """Check if requests are allowed for this parser type"""
        if self.state[parser_type] == "CLOSED":
            return True
            
        # Check if timeout has passed
        if parser_type in self.last_failure:
            time_since_failure = datetime.now(timezone.utc) - self.last_failure[parser_type]
            if time_since_failure > self.timeout:
                log.info("Circuit breaker timeout expired for parser type: %s", parser_type)
                self.state[parser_type] = "CLOSED"
                return True
                
        return False
        
    def get_status(self) -> Dict[str, Dict[str, Any]]:
        """Get current circuit breaker status"""
        status = {}
        for parser_type in set(self.failures.keys()) | set(self.state.keys()):
            now = datetime.now(timezone.utc)
            recent_failures = len([
                f for f in self.failures[parser_type] 
                if f > now - timedelta(hours=1)
            ])
            
            status[parser_type] = {
                "state": self.state[parser_type],
                "recent_failures": recent_failures,
                "last_failure": self.last_failure.get(parser_type)
            }
            
        return status

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
            
    def fetch_alerts_to_structure(self, batch_size: int) -> List[Dict[str, Any]]:
        """Fetch batch of alerts ready for structuring"""
        self.ensure_connection()
        
        # FIXED: Query aligned with schema.sql structure and correct state value
        sql = """
            SELECT
                a.id,
                a.alert_hash,
                a.rule_id,
                a.rule_level,
                a.rule_desc,
                a.response_text,
                a.prompt_type,
                a.response_received_at,
                a.ingest_timestamp,
                ag.name as agent_name,
                ag.ip as agent_ip,
                ag.os as agent_os
            FROM alerts a
            JOIN agents ag ON ag.id = a.agent_id
            WHERE a.state = %s
              AND a.response_text IS NOT NULL
              AND a.archived_at IS NULL
            ORDER BY a.rule_level DESC, a.response_received_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_ANALYZED, batch_size))
                alerts = cur.fetchall()
                return [dict(alert) for alert in alerts]
                
        except Exception as e:
            log.error("Failed to fetch alerts: %s", e)
            return []
            
    def save_structured_data(self, alert_id: int, parse_result: ParseResult):
        """Save structured data and update alert state"""
        self.ensure_connection()
        
        # Build the structured data format expected by email formatter
        structured_data = {
            "subject": parse_result.subject,
            "sections": parse_result.sections,
            "metadata": {
                **parse_result.metadata,
                "parse_success": parse_result.success,
                "parse_time_ms": parse_result.parse_time_ms,
                "parse_error": parse_result.error,
                "structured_at": datetime.now(timezone.utc).isoformat()
            }
        }
        
        sql = """
            UPDATE alerts
            SET structured_data = %s::jsonb,
                parser_success = %s,
                parser_error = %s,
                parser_duration_ms = %s,
                structured_at = NOW(),
                state = %s
            WHERE id = %s
        """
        
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (
                    json.dumps(structured_data),
                    parse_result.success,
                    parse_result.error,
                    parse_result.parse_time_ms,
                    STATE_STRUCTURED,
                    alert_id
                ))
                
                # Notify next worker (email formatter)
                cur.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, str(alert_id)))
                
            log.info("Structured alert %s and notified %s", alert_id, NOTIFY_CHANNEL)
            
        except Exception as e:
            log.error("Failed to save structured data for alert %s: %s", alert_id, e)
            raise
            
    def save_parser_metrics(self, alert_id: int, prompt_type: str, parser_used: str, 
                           success: bool, parse_time_ms: float, error_message: Optional[str] = None):
        """Record parser metrics for monitoring"""
        self.ensure_connection()
        
        sql = """
            INSERT INTO parser_metrics 
            (alert_id, prompt_type, parser_used, success, parse_time_ms, error_message)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (
                    alert_id, prompt_type, parser_used, 
                    success, parse_time_ms, error_message
                ))
        except Exception as e:
            log.warning("Failed to save parser metrics for alert %s: %s", alert_id, e)
            
    def get_parser_stats(self) -> Dict[str, Any]:
        """Get parser performance statistics"""
        self.ensure_connection()
        
        sql = """
            SELECT 
                prompt_type,
                parser_used,
                COUNT(*) as total_attempts,
                COUNT(*) FILTER (WHERE success) as successes,
                AVG(parse_time_ms) FILTER (WHERE success) as avg_parse_time_ms
            FROM parser_metrics
            WHERE created_at > NOW() - INTERVAL '24 hours'
            GROUP BY prompt_type, parser_used
            ORDER BY total_attempts DESC
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql)
                return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            log.warning("Failed to get parser stats: %s", e)
            return []

# ───── MAIN SERVICE LOGIC ─────────────────────────────────
class EmailStructurerService:
    """Main service orchestrator"""
    
    def __init__(self):
        self.shutdown = False
        self.db = DatabaseManager(PG_DSN)
        self.circuit_breaker = SimpleCircuitBreaker(
            failure_threshold=CIRCUIT_BREAKER_THRESHOLD,
            timeout_seconds=CIRCUIT_BREAKER_TIMEOUT
        )
        self.stats = {
            'structured': 0,
            'failed': 0,
            'circuit_breaker_blocks': 0
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
        log.info("Email Structurer Service starting...")
        notifier.ready()
        notifier.status("Starting email structurer service")
        
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
            alerts = self.db.fetch_alerts_to_structure(BATCH_SIZE)
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
                        
    def _process_notification_batch(self):
        """Process a batch of alerts when notified"""
        alerts = self.db.fetch_alerts_to_structure(BATCH_SIZE)
        
        for alert in alerts:
            if self.shutdown:
                break
            self._process_alert(alert)
            notifier.watchdog()
            
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a single alert"""
        alert_id = alert['id']
        prompt_type = alert.get('prompt_type', 'unknown')
        response_text = alert.get('response_text', '')
        
        log.info("Structuring alert %s (prompt_type: %s)", alert_id, prompt_type)
        
        # Check circuit breaker
        if not self.circuit_breaker.allow_request(prompt_type):
            log.warning("Circuit breaker blocking parser for type: %s", prompt_type)
            self.stats['circuit_breaker_blocks'] += 1
            
            # Create fallback structure
            parse_result = ParseResult(
                success=False,
                sections={"Raw Response": response_text},
                subject=f"Parser Temporarily Disabled - Alert {alert_id}",
                metadata={"format_type": "FALLBACK"},
                error=f"Circuit breaker open for {prompt_type}"
            )
        else:
            # Create appropriate parser and process
            parser = ParserFactory.create_parser(prompt_type)
            parse_result = parser.parse(response_text, alert)
            
            # Record result with circuit breaker
            if parse_result.success:
                self.circuit_breaker.record_success(prompt_type)
                self.stats['structured'] += 1
            else:
                self.circuit_breaker.record_failure(prompt_type)
                self.stats['failed'] += 1
        
        try:
            # Save to database
            self.db.save_structured_data(alert_id, parse_result)
            
            # Record metrics
            self.db.save_parser_metrics(
                alert_id, prompt_type, parse_result.metadata.get('format_type', 'unknown'),
                parse_result.success, parse_result.parse_time_ms, parse_result.error
            )
            
            log.info("Successfully processed alert %s", alert_id)
            
        except Exception as e:
            log.error("Failed to save structured data for alert %s: %s", alert_id, e)
            
    def _report_statistics(self):
        """Report service statistics"""
        parser_stats = self.db.get_parser_stats()
        cb_status = self.circuit_breaker.get_status()
        
        log.info("Structurer statistics: structured=%d, failed=%d, cb_blocks=%d",
                self.stats['structured'], self.stats['failed'], self.stats['circuit_breaker_blocks'])
        
        # Log parser performance
        for stat in parser_stats[:5]:  # Top 5 parsers
            success_rate = (stat['successes'] / stat['total_attempts'] * 100) if stat['total_attempts'] > 0 else 0
            log.info("Parser %s/%s: %d/%d (%.1f%%) avg: %.1fms",
                    stat['prompt_type'], stat['parser_used'],
                    stat['successes'], stat['total_attempts'], success_rate,
                    stat['avg_parse_time_ms'] or 0)
        
        notifier.status(f"Structured: {self.stats['structured']}, CB blocks: {self.stats['circuit_breaker_blocks']}")
        self.last_stats_report = time.time()

# ───── ENTRY POINT ─────────────────────────────────────
def main():
    """Service entry point"""
    try:
        service = EmailStructurerService()
        service.run()
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as e:
        log.critical("Fatal error: %s", e, exc_info=True)
        notifier.status(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        log.info("Email Structurer Service stopped")
        notifier.stopping()

if __name__ == "__main__":
    main()