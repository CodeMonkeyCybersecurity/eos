#!/usr/bin/env python3
# /usr/local/bin/email-structurer.py
# stanley:stanley 0750
"""
Email Structurer Worker V2 - Prompt-aware structuring with multiple parsers
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
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Any, Optional, Type
from abc import ABC, abstractmethod

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

REQUIRED_ENV = ["PG_DSN"]
_missing = [var for var in REQUIRED_ENV if not os.getenv(var)]
if _missing:
    print(f"FATAL: Missing environment variables: {', '.join(_missing)}", file=sys.stderr)
    sys.exit(1)

PG_DSN = os.getenv("PG_DSN", "").strip()
LISTEN_CHANNEL = "alert_to_structure"
NOTIFY_CHANNEL = "alert_structured"

# Circuit breaker configuration
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv("PARSER_FAILURE_THRESHOLD", "5"))
CIRCUIT_BREAKER_TIMEOUT = int(os.getenv("PARSER_FAILURE_TIMEOUT", "300"))  # 5 minutes

# A/B testing configuration
AB_TEST_PERCENTAGE = int(os.getenv("PARSER_AB_TEST_PERCENTAGE", "0"))  # 0 = disabled

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    logger = logging.getLogger("email-structurer")
    logger.setLevel(logging.INFO)
    
    handler = RotatingFileHandler(
        "/var/log/stackstorm/email-structurer.log",
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

# ───── PARSER BASE CLASS ─────────────────────────────────
class ResponseParser(ABC):
    """Base parser interface - all parsers must implement these methods"""
    
    @abstractmethod
    def parse(self, response_text: str) -> Dict[str, str]:
        pass
    
    @abstractmethod
    def get_expected_sections(self) -> List[str]:
        pass
    
    def validate_output(self, sections: Dict[str, str]) -> bool:
        """Validate that required sections are present"""
        # Override in subclasses for specific validation
        return len(sections) > 0


# ───── DELPHI NOTIFY SHORT PARSER ─────────────────────────────
class DelphiNotifyShortParser(ResponseParser):
    """
    Parser specifically for the delphi-notify-short.txt prompt format.
    
    Handles the structured format with sections like:
    Summary: [RISK LEVEL] description...
    What happened: explanation...
    Further investigation: steps...
    What to do: MOST IMPORTANT: action...
    How to check: GOOD SIGNS/BAD SIGNS...
    How to prevent this in future: prevention...
    What to ask next: question...
    """
    
    def get_expected_sections(self) -> List[str]:
        return [
            "Summary",
            "What happened", 
            "Further investigation",
            "What to do",
            "How to check",
            "How to prevent this in future",
            "What to ask next"
        ]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {}
        
        # Clean the response - remove extra whitespace but preserve structure
        response_text = re.sub(r'\s+', ' ', response_text.strip())
        
        # Pattern to match section headers (flexible with punctuation)
        section_pattern = r'(' + '|'.join([
            re.escape(section) for section in self.get_expected_sections()
        ]) + r')[:.]?\s*'
        
        # Split by section headers
        parts = re.split(section_pattern, response_text, flags=re.IGNORECASE)
        
        # Process the splits
        for i in range(1, len(parts), 2):
            if i + 1 < len(parts):
                header = parts[i].strip()
                content = parts[i + 1].strip()
                
                # Clean up trailing separators
                content = re.sub(r'^[:.]\s*', '', content)
                content = content.rstrip('.,')
                
                # Map to exact expected section names
                for expected in self.get_expected_sections():
                    if header.lower() == expected.lower():
                        sections[expected] = content
                        break
        
        # If no structured sections found, try to extract key information
        if not sections:
            sections = self._fallback_parse(response_text)
        
        return sections
    
    def _fallback_parse(self, response_text: str) -> Dict[str, str]:
        """Fallback parsing for unstructured responses"""
        sections = {}
        
        # Look for risk level indicators
        risk_match = re.search(r'\[(LOW|MEDIUM|HIGH)\s+RISK[^\]]*\]', response_text, re.IGNORECASE)
        if risk_match:
            # Extract summary from beginning
            summary_end = min(response_text.find('.') + 1, 200)
            sections["Summary"] = response_text[:summary_end].strip()
        
        # Look for "MOST IMPORTANT" actions
        action_match = re.search(r'MOST IMPORTANT:([^.]+\.)', response_text, re.IGNORECASE)
        if action_match:
            sections["What to do"] = f"MOST IMPORTANT: {action_match.group(1).strip()}"
        
        # If still no content, use the whole response as summary
        if not sections:
            sections["Summary"] = response_text[:300] + "..." if len(response_text) > 300 else response_text
        
        return sections
    
    def validate_output(self, sections: Dict[str, str]) -> bool:
        """Validate Delphi Notify Short format requirements"""
        # Must have at least Summary and one action section
        return ("Summary" in sections and 
                any(key in sections for key in ["What to do", "What happened"]) and
                len(sections) >= 2)


# ───── STANDARD DELPHI PARSER ─────────────────────────────
class StandardDelphiParser(ResponseParser):
    """Original Delphi format parser (legacy compatibility)"""
    
    def get_expected_sections(self) -> List[str]:
        return [
            "Summary",
            "What happened",
            "Further investigation",
            "What to do",
            "How to check",
            "How to prevent this in future",
            "What to ask next"
        ]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        pattern = r'(' + '|'.join(f"{section}:" for section in self.get_expected_sections()) + ')'
        parts = re.split(pattern, response_text)
        
        sections = {}
        for i in range(1, len(parts), 2):
            if i + 1 < len(parts):
                key = parts[i].rstrip(':')
                value = parts[i + 1].strip()
                sections[key] = value
        
        return sections
    
    def validate_output(self, sections: Dict[str, str]) -> bool:
        # Must have at least Summary and What happened
        return "Summary" in sections and "What happened" in sections


# ───── SECURITY INCIDENT PARSER ─────────────────────────────
class SecurityIncidentParser(ResponseParser):
    """Parser for security-focused analysis prompts"""
    
    def get_expected_sections(self) -> List[str]:
        return [
            "Threat Level",
            "Attack Type", 
            "Compromised Assets",
            "Immediate Response Required",
            "Investigation Steps",
            "Prevention Measures"
        ]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {}
        
        # Handle both "Section:" and "Section -" formats
        pattern = r'(?:^|\n)(' + '|'.join(
            f"(?:{section}[:\-])" for section in self.get_expected_sections()
        ) + ')'
        
        parts = re.split(pattern, response_text, flags=re.MULTILINE | re.IGNORECASE)
        
        for i in range(1, len(parts), 2):
            if i + 1 < len(parts):
                header = parts[i].strip().rstrip(':-').strip()
                content = parts[i + 1].strip()
                
                # Match to expected sections (case-insensitive)
                for expected in self.get_expected_sections():
                    if header.lower() == expected.lower():
                        sections[expected] = content
                        break
        
        return sections
    
    def validate_output(self, sections: Dict[str, str]) -> bool:
        # Must have Threat Level and Attack Type
        return "Threat Level" in sections and "Attack Type" in sections


# ───── NUMBERED LIST PARSER ─────────────────────────────
class NumberedListParser(ResponseParser):
    """Parser for numbered list format responses"""
    
    def get_expected_sections(self) -> List[str]:
        return [
            "What is happening",
            "Why this is important",
            "What to do next",
            "How to verify the fix"
        ]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {}
        
        # Match numbered items: "1. ", "1) ", "1: "
        pattern = r'\n?\d+[\.\):\s]+([^\n]+)'
        matches = re.finditer(pattern, response_text)
        
        # Extract content between numbered items
        positions = []
        for match in matches:
            positions.append((match.start(), match.group(1).strip()))
        
        # Get content for each numbered item
        for i, (start, header) in enumerate(positions):
            if i + 1 < len(positions):
                end = positions[i + 1][0]
            else:
                end = len(response_text)
            
            full_content = response_text[start:end].strip()
            content_match = re.match(r'\d+[\.\):\s]+[^\n]+\n?(.*)', full_content, re.DOTALL)
            if content_match:
                content = content_match.group(1).strip()
            else:
                content = full_content
            
            # Try to match header to expected sections
            header_lower = header.lower()
            matched = False
            for expected in self.get_expected_sections():
                if expected.lower() in header_lower or header_lower in expected.lower():
                    sections[expected] = content
                    matched = True
                    break
            
            if not matched:
                sections[header] = content
        
        return sections
    
    def validate_output(self, sections: Dict[str, str]) -> bool:
        # Must have at least "What is happening"
        return "What is happening" in sections or any("what" in k.lower() for k in sections.keys())


# ───── JSON RESPONSE PARSER ─────────────────────────────
class JSONResponseParser(ResponseParser):
    """Parser for JSON-formatted LLM responses"""
    
    def get_expected_sections(self) -> List[str]:
        return ["severity", "summary", "technical_details", "recommendations", "related_systems"]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {}
        
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{[^{}]*\{?[^{}]*\}?[^{}]*\}', response_text, re.DOTALL)
            
            if json_match:
                json_str = json_match.group(0)
                data = json.loads(json_str)
                
                # Convert all values to strings
                for key, value in data.items():
                    if isinstance(value, list):
                        sections[key] = "\n• " + "\n• ".join(str(item) for item in value)
                    elif isinstance(value, dict):
                        sections[key] = "\n".join(f"{k}: {v}" for k, v in value.items())
                    else:
                        sections[key] = str(value)
            else:
                sections["summary"] = response_text
                
        except json.JSONDecodeError:
            # Fallback parsing
            for line in response_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().strip('"\'')
                    value = value.strip().strip('",\'')
                    if key.lower() in [s.lower() for s in self.get_expected_sections()]:
                        sections[key] = value
            
            if not sections:
                sections["content"] = response_text
        
        return sections


# ───── CONVERSATIONAL PARSER ─────────────────────────────
class ConversationalParser(ResponseParser):
    """Parser for natural language responses"""
    
    def get_expected_sections(self) -> List[str]:
        return ["What's Wrong", "Why It Matters", "What To Do", "Additional Info"]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {
            "What's Wrong": "",
            "Why It Matters": "",
            "What To Do": "",
            "Additional Info": ""
        }
        
        # Keywords that indicate each section
        indicators = {
            "What's Wrong": [
                "what's happening", "the problem is", "detected", "found",
                "alert shows", "issue is", "what's wrong", "the situation"
            ],
            "Why It Matters": [
                "this matters because", "important because", "risk is",
                "could lead to", "impact", "why you should care", "this means"
            ],
            "What To Do": [
                "you should", "recommend", "to fix", "action items",
                "next steps", "to resolve", "what to do"
            ]
        }
        
        # Split into sentences
        sentences = re.split(r'(?<=[.!?])\s+', response_text)
        
        current_section = "What's Wrong"  # Default section
        
        for sentence in sentences:
            sentence_lower = sentence.lower()
            
            # Check if this sentence starts a new section
            for section, keywords in indicators.items():
                if any(keyword in sentence_lower for keyword in keywords):
                    current_section = section
                    break
            
            # Add sentence to current section
            if sections[current_section]:
                sections[current_section] += " " + sentence
            else:
                sections[current_section] = sentence
        
        # Clean up sections
        for key in sections:
            sections[key] = sections[key].strip()
        
        # If everything ended up in one section, split by paragraphs
        if sum(1 for v in sections.values() if v) == 1:
            paragraphs = response_text.split('\n\n')
            if len(paragraphs) >= 3:
                sections["What's Wrong"] = paragraphs[0]
                sections["Why It Matters"] = paragraphs[1]
                sections["What To Do"] = '\n\n'.join(paragraphs[2:])
        
        # Remove empty sections
        return {k: v for k, v in sections.items() if v}


# ───── HYBRID FALLBACK PARSER ─────────────────────────────
class HybridParser(ResponseParser):
    """Fallback parser that tries multiple strategies"""
    
    def get_expected_sections(self) -> List[str]:
        return ["Summary", "Details", "Actions", "Notes"]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {}
        
        # Try various header patterns
        header_patterns = [
            r'^(\w[\w\s]+):\s*',  # "Section:"
            r'^(?:#+\s+)?(\w[\w\s]+)$',  # "## Section"
            r'^\[(\w[\w\s]+)\]',  # "[Section]"
            r'^(?:\d+\.?\s+)?(\w[\w\s]+):',  # "1. Section:"
        ]
        
        for pattern in header_patterns:
            matches = list(re.finditer(pattern, response_text, re.MULTILINE))
            if len(matches) >= 2:
                for i, match in enumerate(matches):
                    header = match.group(1).strip()
                    start = match.end()
                    end = matches[i + 1].start() if i + 1 < len(matches) else len(response_text)
                    content = response_text[start:end].strip()
                    
                    header_lower = header.lower()
                    if 'summ' in header_lower:
                        sections["Summary"] = content
                    elif 'detail' in header_lower or 'analy' in header_lower:
                        sections["Details"] = content
                    elif 'action' in header_lower or 'step' in header_lower:
                        sections["Actions"] = content
                    else:
                        sections["Notes"] = sections.get("Notes", "") + "\n" + content
                
                if sections:
                    break
        
        # If no structured content, use paragraphs
        if not sections:
            paragraphs = [p.strip() for p in response_text.split('\n\n') if p.strip()]
            if paragraphs:
                sections["Summary"] = paragraphs[0]
                if len(paragraphs) > 1:
                    sections["Details"] = '\n\n'.join(paragraphs[1:])
        
        # Last resort
        if not sections:
            sections["Details"] = response_text
        
        return sections


# ───── PARSER REGISTRY ─────────────────────────────────
class ParserRegistry:
    """Central registry for all parsers"""
    
    _parsers = {
        'delphi_notify_short': DelphiNotifyShortParser,
        'standard': StandardDelphiParser,
        'standard_delphi': StandardDelphiParser,
        'security_analysis': SecurityIncidentParser,
        'security_incident': SecurityIncidentParser,
        'numbered_investigation': NumberedListParser,
        'numbered_list': NumberedListParser,
        'json_response': JSONResponseParser,
        'json': JSONResponseParser,
        'conversational': ConversationalParser,
        'executive_summary': ConversationalParser,
        'hybrid': HybridParser,
        'fallback': HybridParser,
    }
    
    @classmethod
    def register(cls, prompt_type: str, parser_class: Type[ResponseParser]):
        """Register a parser for a prompt type"""
        cls._parsers[prompt_type] = parser_class
        log.info(f"Registered parser {parser_class.__name__} for prompt type: {prompt_type}")
    
    @classmethod
    def get_parser(cls, prompt_type: str) -> ResponseParser:
        """Get parser instance for prompt type"""
        parser_class = cls._parsers.get(prompt_type)
        if not parser_class:
            log.warning(f"No parser registered for prompt_type: {prompt_type}, using HybridParser")
            return HybridParser()
        return parser_class()
    
    @classmethod
    def list_parsers(cls) -> List[str]:
        """List all registered prompt types"""
        return list(cls._parsers.keys())


# ───── CIRCUIT BREAKER ─────────────────────────────────
class ParserCircuitBreaker:
    """Circuit breaker to prevent cascading parser failures"""
    
    def __init__(self, failure_threshold: int = 5, timeout: int = 300):
        self.failures = defaultdict(int)
        self.last_failure = defaultdict(float)
        self.threshold = failure_threshold
        self.timeout = timeout
    
    def record_success(self, prompt_type: str):
        """Reset failure count on success"""
        self.failures[prompt_type] = 0
    
    def record_failure(self, prompt_type: str):
        """Record a parser failure"""
        self.failures[prompt_type] += 1
        self.last_failure[prompt_type] = time.time()
        log.warning(f"Parser failure for {prompt_type}: {self.failures[prompt_type]} failures")
    
    def is_open(self, prompt_type: str) -> bool:
        """Check if circuit is open (failing)"""
        if self.failures[prompt_type] >= self.threshold:
            if time.time() - self.last_failure[prompt_type] < self.timeout:
                return True
            else:
                # Reset after timeout
                log.info(f"Circuit breaker reset for {prompt_type} after timeout")
                self.failures[prompt_type] = 0
        return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status for monitoring"""
        return {
            prompt_type: {
                'failures': count,
                'is_open': self.is_open(prompt_type),
                'last_failure': self.last_failure.get(prompt_type, 0)
            }
            for prompt_type, count in self.failures.items()
        }


# ───── ALERT STRUCTURER ─────────────────────────────────
class AlertStructurer:
    """Handles the structuring of alert data"""
    
    def __init__(self, circuit_breaker: ParserCircuitBreaker):
        self.circuit_breaker = circuit_breaker
    
    def structure_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Structure alert data with appropriate parser"""
        prompt_type = alert_data.get('prompt_type', 'delphi_notify_short')  # Default to new format
        alert_id = alert_data.get('id')
        
        # Check circuit breaker
        if self.circuit_breaker.is_open(prompt_type):
            log.warning(f"Circuit breaker open for {prompt_type}, using fallback parser")
            parser = HybridParser()
        else:
            # Get appropriate parser (with A/B testing if enabled)
            parser = self._get_parser_with_ab_test(prompt_type, alert_id)
        
        log.info(f"Processing alert {alert_id} with {parser.__class__.__name__} for prompt_type: {prompt_type}")
        
        # Parse with timing
        start_time = time.time()
        try:
            response_text = alert_data.get('response', '')
            sections = parser.parse(response_text)
            
            # Validate output
            if not parser.validate_output(sections):
                raise ValueError(f"Parser output validation failed for {prompt_type}")
            
            parse_time = time.time() - start_time
            self.circuit_breaker.record_success(prompt_type)
            
            # Log metrics
            log.info(f"Successfully parsed alert {alert_id} in {parse_time:.2f}s")
            
        except Exception as e:
            parse_time = time.time() - start_time
            self.circuit_breaker.record_failure(prompt_type)
            log.error(f"Parser failed for alert {alert_id}: {e}")
            
            # Fallback to hybrid parser
            log.info(f"Attempting fallback parsing for alert {alert_id}")
            parser = HybridParser()
            sections = parser.parse(alert_data.get('response', ''))
        
        # Extract agent information
        agent_info = self._extract_agent_info(alert_data)
        
        # Build subject line
        subject = self._build_subject(alert_data, agent_info)
        
        # Collect metadata
        metadata = {
            'alert_id': alert_id,
            'alert_hash': alert_data.get('alert_hash', '')[:8],
            'rule_level': alert_data.get('rule_level'),
            'timestamp': alert_data.get('response_received_at'),
            'agent_id': alert_data.get('agent_id'),
            'prompt_type': prompt_type,
            'parser_used': parser.__class__.__name__,
            'parse_time_ms': round(parse_time * 1000, 2)
        }
        
        return {
            'subject': subject,
            'sections': sections,
            'agent_info': agent_info,
            'metadata': metadata,
            'raw_response': alert_data.get('response', '')
        }
    
    def _get_parser_with_ab_test(self, prompt_type: str, alert_id: int) -> ResponseParser:
        """Get parser with optional A/B testing"""
        if AB_TEST_PERCENTAGE > 0 and prompt_type == 'security_analysis':
            # Example A/B test for security parser
            if (alert_id % 100) < AB_TEST_PERCENTAGE:
                log.info(f"A/B test: Using experimental parser for alert {alert_id}")
                # Return experimental parser (in this case, just using standard)
                return StandardDelphiParser()
        
        return ParserRegistry.get_parser(prompt_type)
    
    def _extract_agent_info(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and structure agent information"""
        agent_details = alert_data.get('agent_details_from_db', {})
        
        if not isinstance(agent_details, dict):
            return {}
        
        info = {
            'name': agent_details.get('name', alert_data.get('agent_id', 'Unknown')),
            'id': agent_details.get('id'),
            'ip': agent_details.get('ip'),
            'version': agent_details.get('version'),
            'status': agent_details.get('status'),
            'manager': agent_details.get('manager'),
            'groups': agent_details.get('group', [])
        }
        
        # OS information
        os_data = agent_details.get('os', {})
        if isinstance(os_data, dict):
            os_parts = [
                os_data.get('name', ''),
                os_data.get('version', ''),
            ]
            if os_data.get('arch'):
                os_parts.append(f"({os_data['arch']})")
            
            os_display = ' '.join(filter(None, os_parts)).strip()
            info['os'] = os_display if os_display else 'Unknown OS'
        else:
            info['os'] = 'Unknown OS'
        
        # Timestamps
        for field, label in [
            ('dateAdd', 'registered_at'),
            ('lastKeepAlive', 'last_seen'),
            ('disconnection_time', 'disconnected_at')
        ]:
            if field in agent_details:
                try:
                    if agent_details[field].startswith("9999"):
                        info[label] = "Never (future timestamp)"
                    else:
                        dt = datetime.fromisoformat(
                            agent_details[field].replace('Z', '+00:00')
                        )
                        info[label] = dt
                except ValueError:
                    log.warning(f"Could not parse timestamp {field}: {agent_details[field]}")
        
        return info
    
    def _build_subject(self, alert_data: Dict[str, Any], 
                      agent_info: Dict[str, Any]) -> str:
        """Build email subject line"""
        agent_name = agent_info.get('name', 'Unknown Agent')
        os_info = agent_info.get('os', 'Unknown OS')
        rule_level = alert_data.get('rule_level', 'Unknown')
        
        return f"[Delphi Notify] {agent_name} ({os_info}) Level {rule_level}"


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


def ensure_columns_exist(conn):
    """Ensure necessary columns exist"""
    with conn.cursor() as cur:
        cur.execute("""
            DO $ 
            BEGIN
                -- Add prompt_type column if it doesn't exist
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns 
                    WHERE table_name='alerts' AND column_name='prompt_type'
                ) THEN
                    ALTER TABLE alerts ADD COLUMN prompt_type VARCHAR(50);
                    ALTER TABLE alerts ADD COLUMN prompt_template TEXT;
                END IF;
                
                -- Add parser metrics table
                CREATE TABLE IF NOT EXISTS parser_metrics (
                    id SERIAL PRIMARY KEY,
                    alert_id INTEGER REFERENCES alerts(id),
                    prompt_type VARCHAR(50),
                    parser_used VARCHAR(100),
                    success BOOLEAN,
                    parse_time_ms FLOAT,
                    error TEXT,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                
                -- Create index for metrics
                CREATE INDEX IF NOT EXISTS idx_parser_metrics_prompt_type 
                ON parser_metrics(prompt_type, created_at);
            END $;
        """)


def fetch_alert_to_structure(conn, alert_id: int) -> Optional[Dict]:
    """Fetch an alert that needs structuring"""
    sql = """
        SELECT
            a.id,
            a.agent_id,
            a.prompt_type,
            a.prompt_text AS summary,
            a.response_text AS response,
            a.response_received_at,
            a.alert_hash,
            a.rule_level,
            ag.api_response AS agent_details_from_db
        FROM alerts a
        JOIN agents ag ON ag.id = a.agent_id
        WHERE a.id = %s AND a.state = 'summarized'
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        row = cur.fetchone()
        
        if row and row.get('agent_details_from_db') and isinstance(row['agent_details_from_db'], str):
            try:
                row['agent_details_from_db'] = json.loads(row['agent_details_from_db'])
            except json.JSONDecodeError:
                log.warning(f"Failed to parse agent_details JSON for alert {alert_id}")
                row['agent_details_from_db'] = {}
        
        return row


def save_structured_data(conn, alert_id: int, structured_data: Dict[str, Any]):
    """Save structured data and update alert state"""
    try:
        with conn.cursor() as cur:
            # Save structured data
            cur.execute("""
                UPDATE alerts 
                SET structured_data = %s,
                    state = 'structured',
                    structured_at = NOW()
                WHERE id = %s
            """, (json.dumps(structured_data), alert_id))
            
            # Save parser metrics
            metadata = structured_data.get('metadata', {})
            cur.execute("""
                INSERT INTO parser_metrics 
                (alert_id, prompt_type, parser_used, success, parse_time_ms)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                alert_id,
                metadata.get('prompt_type'),
                metadata.get('parser_used'),
                True,
                metadata.get('parse_time_ms', 0)
            ))
            
            # Notify next worker
            cur.execute(f"NOTIFY {NOTIFY_CHANNEL}, %s", (str(alert_id),))
            
        log.info(f"Saved structured data for alert {alert_id}")
    except Exception as e:
        log.error(f"Failed to save structured data for alert {alert_id}: {e}")
        raise


def save_parser_failure(conn, alert_id: int, prompt_type: str, 
                       parser_used: str, error: str):
    """Record parser failure in metrics"""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO parser_metrics 
                (alert_id, prompt_type, parser_used, success, error)
                VALUES (%s, %s, %s, %s, %s)
            """, (alert_id, prompt_type, parser_used, False, error))
    except Exception as e:
        log.error(f"Failed to save parser failure metrics: {e}")


def get_circuit_breaker_status(conn) -> Dict[str, Any]:
    """Get circuit breaker status from database"""
    sql = """
        SELECT 
            prompt_type,
            COUNT(*) FILTER (WHERE NOT success) as failures,
            MAX(created_at) FILTER (WHERE NOT success) as last_failure
        FROM parser_metrics
        WHERE created_at > NOW() - INTERVAL '1 hour'
        GROUP BY prompt_type
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        return {row['prompt_type']: row for row in cur.fetchall()}


# ───── MONITORING FUNCTIONS ─────────────────────────────
def log_parser_statistics(conn):
    """Log parser performance statistics"""
    sql = """
        SELECT 
            prompt_type,
            parser_used,
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE success) as successful,
            AVG(parse_time_ms) FILTER (WHERE success) as avg_parse_time_ms,
            MAX(created_at) as last_used
        FROM parser_metrics
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY prompt_type, parser_used
        ORDER BY prompt_type, total DESC
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        stats = cur.fetchall()
        
        log.info("=== Parser Statistics (Last 24h) ===")
        for stat in stats:
            success_rate = (stat['successful'] / stat['total'] * 100) if stat['total'] > 0 else 0
            log.info(
                f"{stat['prompt_type']}/{stat['parser_used']}: "
                f"{stat['successful']}/{stat['total']} ({success_rate:.1f}%), "
                f"avg: {stat['avg_parse_time_ms']:.1f}ms"
            )


# ───── SIGNAL HANDLING ─────────────────────────────────
shutdown = False

def on_signal(signum, _frame):
    global shutdown
    shutdown = True
    log.info(f"Signal {signum} received; shutting down")

signal.signal(signal.SIGINT, on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ───── MAIN LOOP ─────────────────────────────────────────
def main():
    """Main event loop"""
    # Connect to database
    conn = connect_db()
    ensure_columns_exist(conn)
    
    # Initialize components
    circuit_breaker = ParserCircuitBreaker(
        failure_threshold=CIRCUIT_BREAKER_THRESHOLD,
        timeout=CIRCUIT_BREAKER_TIMEOUT
    )
    structurer = AlertStructurer(circuit_breaker)
    
    # Log available parsers
    log.info(f"Available parsers for prompt types: {ParserRegistry.list_parsers()}")
    log.info(f"Circuit breaker config: threshold={CIRCUIT_BREAKER_THRESHOLD}, timeout={CIRCUIT_BREAKER_TIMEOUT}s")
    log.info(f"A/B testing: {AB_TEST_PERCENTAGE}% for security_analysis prompts")
    
    # Process any backlog
    catch_up(conn, structurer)
    
    # Listen for new alerts
    cur = conn.cursor()
    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    cur.execute("LISTEN new_response;")  # Also listen to original channel
    log.info("Listening for alerts to structure")
    
    # Statistics logging
    last_stats_log = time.time()
    stats_interval = 3600  # Log stats every hour
    
    while not shutdown:
        try:
            # Log statistics periodically
            if time.time() - last_stats_log > stats_interval:
                log_parser_statistics(conn)
                log.info(f"Circuit breaker status: {circuit_breaker.get_status()}")
                last_stats_log = time.time()
            
            if not select.select([conn], [], [], 5)[0]:
                continue
            
            conn.poll()
            
            for notify in conn.notifies:
                try:
                    alert_id = int(notify.payload)
                    log.info(f"Processing alert {alert_id}")
                    
                    alert_data = fetch_alert_to_structure(conn, alert_id)
                    if not alert_data:
                        log.debug(f"Alert {alert_id} not in correct state or not found")
                        continue
                    
                    # Structure the alert
                    structured_data = structurer.structure_alert(alert_data)
                    save_structured_data(conn, alert_id, structured_data)
                    
                except Exception as e:
                    log.exception(f"Failed to process alert {notify.payload}: {e}")
                    # Try to save failure metrics
                    try:
                        alert_id = int(notify.payload)
                        save_parser_failure(
                            conn, alert_id, 
                            alert_data.get('prompt_type', 'unknown') if 'alert_data' in locals() else 'unknown',
                            'unknown', str(e)
                        )
                    except:
                        pass
            
            conn.notifies.clear()
            
        except psycopg2.OperationalError:
            log.exception("DB connection lost; reconnecting in 5s")
            time.sleep(5)
            conn = connect_db()
            cur = conn.cursor()
            cur.execute(f"LISTEN {LISTEN_CHANNEL};")
            cur.execute("LISTEN new_response;")
        except Exception:
            log.exception("Unexpected error in main loop")
            raise
    
    log.info("Shutting down gracefully")


def catch_up(conn, structurer: AlertStructurer):
    """Process any backlog of unstructured alerts"""
    sql = """
        SELECT id FROM alerts 
        WHERE state = 'summarized' 
        ORDER BY response_received_at
        LIMIT 100  -- Process in batches to avoid memory issues
    """
    
    processed = 0
    while True:
        with conn.cursor() as cur:
            cur.execute(sql)
            alert_ids = [row[0] for row in cur.fetchall()]
        
        if not alert_ids:
            break
            
        log.info(f"Processing batch of {len(alert_ids)} backlog alerts")
        
        for alert_id in alert_ids:
            try:
                alert_data = fetch_alert_to_structure(conn, alert_id)
                if alert_data:
                    structured_data = structurer.structure_alert(alert_data)
                    save_structured_data(conn, alert_id, structured_data)
                    processed += 1
            except Exception as e:
                log.error(f"Failed to process backlog alert {alert_id}: {e}")
    
    if processed > 0:
        log.info(f"Processed {processed} backlog alerts")


if __name__ == "__main__":
    main()