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
import psycopg2 # Pylance: If this import cannot be resolved, ensure psycopg2-binary is installed
import psycopg2.extensions
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Any, Optional, Type
from abc import ABC, abstractmethod

# Pylance: If 'load_dotenv' is an unknown import symbol, ensure python-dotenv is installed.
# The try-except handles runtime, but Pylance needs to see it defined statically.
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    # Define a dummy load_dotenv if the module is not found, for static analysis
    def load_dotenv(*_a, **_kw): pass

try:
    import psycopg2
    import psycopg2.extensions
    from psycopg2.extras import RealDictCursor
except ImportError:
    logging.error("Required dependency 'psycopg2' not found. Please install it using: pip install psycopg2-binary")
    sys.exit(1) # This exit will not be caught by sdnotify if it's not imported yet


# --- Import sdnotify for Systemd Watchdog Integration ---
try:
    import sdnotify # ADDED: Import sdnotify
except ImportError:
    # Fallback for systems without sdnotify
    sdnotify = None
    print("WARNING: sdnotify module not found. Systemd watchdog integration will be disabled.", file=sys.stderr)


# ───── CONFIGURATION ─────────────────────────────────────
load_dotenv("/opt/stackstorm/packs/delphi/.env")

REQUIRED_ENV = ["PG_DSN"]
_missing = [var for var in REQUIRED_ENV if not os.getenv(var)]
if _missing:
    print(f"FATAL: Missing environment variables: {', '.join(_missing)}", file=sys.stderr)
    sys.exit(1)

PG_DSN = os.getenv("PG_DSN", "").strip()
LISTEN_CHANNEL = "new_response"        # Listen for LLM responses
NOTIFY_CHANNEL = "alert_structured"   # Notify when structuring complete

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

# --- Initialize Systemd Notifier ---
if sdnotify:
    notifier = sdnotify.SystemdNotifier() # ADDED: Initialize sdnotify notifier
else:
    class DummyNotifier: # Dummy class if sdnotify isn't available
        def notify(self, message):
            pass
    notifier = DummyNotifier()


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
            f"(?:{re.escape(section)}[:-])" for section in self.get_expected_sections() # Used re.escape
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
    """
    Parser for JSON-formatted LLM responses.
    Improved to more robustly extract JSON from mixed text.
    """

    def get_expected_sections(self) -> List[str]:
        return ["severity", "summary", "technical_details", "recommendations", "related_systems"]

    def parse(self, response_text: str) -> Dict[str, str]:
        sections = {}
        json_data = None

        # --- IMPROVED JSON EXTRACTION ---
        # Find the first opening curly brace and the last closing curly brace
        # This is more robust than a fixed regex for varying JSON outputs
        first_brace = response_text.find('{')
        last_brace = response_text.rfind('}')

        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            json_substring = response_text[first_brace : last_brace + 1]
            try:
                json_data = json.loads(json_substring)
                log.debug("Successfully extracted and parsed JSON from LLM response.")
            except json.JSONDecodeError as e:
                log.warning(f"Failed to parse extracted JSON substring: {e}. Falling back to line-by-line.")
                json_data = None
        else:
            log.debug("No valid JSON object structure found in response_text. Falling back to line-by-line.")


        if json_data:
            # Convert all values to strings and format lists/dicts
            for key, value in json_data.items():
                if isinstance(value, list):
                    # For lists, join items with bullet points for readability
                    sections[key] = "\n• " + "\n• ".join(str(item) for item in value)
                elif isinstance(value, dict):
                    # For nested dictionaries, format as key-value pairs
                    sections[key] = "\n".join(f"{k}: {v}" for k, v in value.items())
                else:
                    sections[key] = str(value)
        else:
            # --- FALLBACK PARSING (Original logic from your script) ---
            # This handles cases where LLM output is not strictly JSON but has "key: value" lines
            log.debug("Using line-by-line fallback parsing for JSONResponseParser.")
            for line in response_text.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().strip('"\'')
                    value = value.strip().strip('",\'')
                    if key.lower() in [s.lower() for s in self.get_expected_sections()]:
                        sections[key] = value

            if not sections:
                # If even fallback fails, put entire response into a 'content' section
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


# ───── DefaultFallbackParser (Now inherits from ResponseParser ABC) ─────────────────────────────
class DefaultFallbackParser(ResponseParser): # CONSOLIDATED: Inherits from ResponseParser
    """Simple fallback parser when no specific parser is matched or fails."""

    def get_expected_sections(self) -> List[str]:
        return ["Summary", "Details"] # Define some generic sections

    def parse(self, response_text: str) -> Dict[str, str]:
        # Simple fallback: put the whole response into a summary or details section
        return {
            "Summary": response_text[:300] + "..." if len(response_text) > 300 else response_text,
            "Details": response_text
        }

    def validate_output(self, sections: Dict[str, str]) -> bool:
        return "Summary" in sections or "Details" in sections


# ───── PARSER REGISTRY ─────────────────────────────────
class ParserRegistry:
    """Central registry for all parsers"""

    _parsers: Dict[str, Type[ResponseParser]] = { # Type hint for _parsers
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
        'default': DefaultFallbackParser, # CONSOLIDATED: Added DefaultFallbackParser
    }

    @classmethod
    def register(cls, prompt_type: str, parser_class: Type[ResponseParser]):
        """Register a parser for a prompt type"""
        if not issubclass(parser_class, ResponseParser): # Ensure it's a ResponseParser subclass
            raise TypeError(f"Parser class {parser_class.__name__} must inherit from ResponseParser.")
        cls._parsers[prompt_type] = parser_class
        log.info(f"Registered parser {parser_class.__name__} for prompt type: {prompt_type}")

    @classmethod
    def get_parser(cls, prompt_type: str) -> ResponseParser:
        """Get parser instance for prompt type"""
        parser_class = cls._parsers.get(prompt_type)
        if not parser_class:
            log.warning(f"No parser registered for prompt_type: {prompt_type}, using DefaultFallbackParser")
            return cls._parsers["default"]() # CONSOLIDATED: Use the properly defined DefaultFallbackParser
        return parser_class()

    @classmethod
    def list_parsers(cls) -> List[str]:
        """List all registered prompt types"""
        return list(cls._parsers.keys())


# ───── CIRCUIT BREAKER ─────────────────────────────────
class ParserCircuitBreaker:
    """
    Circuit breaker to prevent cascading parser failures.
    Implemented as a three-state (CLOSED, OPEN, HALF_OPEN) pattern.
    """

    def __init__(self, failure_threshold: int = 5, timeout: int = 300):
        self.failure_threshold = failure_threshold
        self.timeout = timedelta(seconds=timeout) # Use timedelta for easier comparison
        self.failures: Dict[str, List[datetime]] = defaultdict(list)
        self.state: Dict[str, str] = defaultdict(lambda: "CLOSED") # CLOSED, OPEN, HALF_OPEN
        self.last_state_change: Dict[str, datetime] = defaultdict(lambda: datetime.min.replace(tzinfo=timezone.utc))

    def record_failure(self, prompt_type: str):
        """Record a parser failure for a given prompt type."""
        now = datetime.now(timezone.utc)
        self.failures[prompt_type].append(now)
        # Keep only failures within the last hour to prevent unbounded list growth
        self.failures[prompt_type] = [
            f for f in self.failures[prompt_type]
            if f > now - timedelta(hours=1) # Keep failures for the last hour
        ]
        self._update_state(prompt_type)
        log.warning(f"Circuit for '{prompt_type}' recorded failure. Current failures: {len(self.failures[prompt_type])}")

    def record_success(self, prompt_type: str):
        """Record a parser success for a given prompt type."""
        if self.state[prompt_type] != "CLOSED":
            log.info(f"Circuit for '{prompt_type}' moved to CLOSED after success.")
            notifier.notify(f"STATUS=Circuit for '{prompt_type}' is CLOSED.") # ADDED: sdnotify on circuit closed
        self.failures[prompt_type].clear() # Reset failures on success
        self.state[prompt_type] = "CLOSED"
        self.last_state_change[prompt_type] = datetime.now(timezone.utc)


    def allow_request(self, prompt_type: str) -> bool:
        """
        Determines if a request for the given prompt_type should be allowed based on circuit breaker state.
        Handles state transitions: CLOSED -> OPEN, OPEN -> HALF_OPEN, HALF_OPEN -> (CLOSED/OPEN).
        """
        now = datetime.now(timezone.utc)
        current_state = self.state[prompt_type]
        
        # Prune old failures for accurate count
        self.failures[prompt_type] = [
            f for f in self.failures[prompt_type]
            if f > now - timedelta(hours=1) # Only count failures within the last hour
        ]
        
        recent_failures_count = len(self.failures[prompt_type])

        # State transitions based on current state and recent failures
        if current_state == "CLOSED":
            # If failures accumulate beyond threshold in CLOSED state, trip to OPEN
            if recent_failures_count >= self.failure_threshold:
                self.state[prompt_type] = "OPEN"
                self.last_state_change[prompt_type] = now
                log.error(f"Circuit for '{prompt_type}' tripped to OPEN due to {recent_failures_count} failures.")
                notifier.notify(f"STATUS=Circuit for '{prompt_type}' tripped to OPEN.") # ADDED: sdnotify on circuit open
                return False # Do not allow request immediately after tripping
            return True # Allow request if CLOSED and below threshold

        elif current_state == "OPEN":
            # If timeout period has passed in OPEN state, move to HALF_OPEN
            if now > self.last_state_change[prompt_type] + self.timeout:
                self.state[prompt_type] = "HALF_OPEN"
                log.warning(f"Circuit for '{prompt_type}' moved to HALF_OPEN. Allowing a single test request.")
                notifier.notify(f"STATUS=Circuit for '{prompt_type}' is HALF_OPEN. Allowing test.") # ADDED: sdnotify on circuit half-open
                return True # Allow ONE request to test the system
            log.warning(f"Circuit for '{prompt_type}' is OPEN. Blocking request.")
            return False # Continue blocking if timeout not reached

        elif current_state == "HALF_OPEN":
            # In HALF_OPEN, only one request should be allowed since last transition.
            # If this request succeeds, circuit closes. If it fails, circuit re-opens.
            # We already allowed the request when transitioning to HALF_OPEN.
            # Subsequent requests while in HALF_OPEN (before the first one resolves) should wait.
            # For this synchronous parser, this typically means the first parser call after timeout.
            log.info(f"Circuit for '{prompt_type}' is HALF_OPEN. Test request is being processed.")
            # The logic that calls this method should ensure only one request is made
            # per HALF_OPEN cycle. For a simple synchronous loop, the `time.sleep`
            # and next poll cycle will naturally limit it.
            return True # Allow the request that triggered the HALF_OPEN state
        
        return False # Default safe fallback


    def _update_state(self, prompt_type: str):
        """Internal helper to ensure state is consistent based on failures."""
        now = datetime.now(timezone.utc)
        recent_failures = len([
            f for f in self.failures[prompt_type]
            if f > now - timedelta(hours=1) # Recalculate based on 1-hour window
        ])

        # This method is primarily called by record_failure.
        # Its main role is to trip the circuit to OPEN if threshold is met.
        if recent_failures >= self.failure_threshold and self.state[prompt_type] != "OPEN":
            self.state[prompt_type] = "OPEN"
            self.last_state_change[prompt_type] = now
            log.error(f"Circuit for '{prompt_type}' tripped to OPEN due to {recent_failures} failures.")
            notifier.notify(f"STATUS=Circuit for '{prompt_type}' tripped to OPEN (from _update_state).") # ADDED: sdnotify

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status for monitoring"""
        now = datetime.now(timezone.utc)
        status_summary = {}
        for prompt_type in self.failures.keys() | self.state.keys(): # Include all tracked prompt types
            recent_failures_count = len([
                f for f in self.failures[prompt_type]
                if f > now - timedelta(hours=1) # Failures in the last hour
            ])
            is_open_state = self.state[prompt_type] == "OPEN"
            is_half_open_state = self.state[prompt_type] == "HALF_OPEN"
            
            status_summary[prompt_type] = {
                'state': self.state[prompt_type],
                'failures_in_last_hour': recent_failures_count,
                'last_failure_time_utc': max(self.failures[prompt_type]).isoformat() if self.failures[prompt_type] else None,
                'time_since_last_state_change_sec': (now - self.last_state_change[prompt_type]).total_seconds() if self.last_state_change.get(prompt_type) else None
            }
        return status_summary


class AlertStructurer:
    """Orchestrates alert structuring using dynamic parsers"""

    def __init__(self, circuit_breaker: ParserCircuitBreaker):
        self.circuit_breaker = circuit_breaker

    def determine_prompt_type(self, llm_response_text: str, rule_level: int) -> str:
        """
        Determines the prompt type based on rule level or LLM response analysis.
        For now, primarily based on rule_level and A/B test logic for 'security_analysis'.
        """
        # A/B Test for 'security_analysis'
        if rule_level >= 7 and AB_TEST_PERCENTAGE > 0 and random.randint(1, 100) <= AB_TEST_PERCENTAGE:
            log.info("A/B test activated for security_analysis prompt type.")
            # This would dynamically select between A/B variants defined in your A/B testing system.
            # For this example, we'll assign a specific parser name that ParserRegistry understands
            # You might return a specific variant name like 'security_analysis_variant_A'
            return "security_analysis_AB_TEST" # This would then map to a specific parser in ParserRegistry

        if rule_level >= 10:
            return "security_analysis" # Critical alerts
        elif rule_level >= 7:
            return "delphi_notify_short" # Important operational alerts
        elif rule_level >= 5:
            return "numbered_investigation" # General investigation
        else:
            return "json_response" # Default for lower levels. Consider a 'hybrid' or 'conversational' as default.

    def structure_alert(self, alert_data: Dict) -> Dict:
        """
        Structures the LLM response based on determined prompt type and parser.
        """
        llm_response_text = alert_data.get('response_text', '')
        rule_level = alert_data.get('rule_level', 0)
        alert_id = alert_data.get('id')
        
        prompt_type = self.determine_prompt_type(llm_response_text, rule_level)
        
        # Determine which parser to use based on prompt_type
        # This is simplified; in a real scenario, prompt_type would map to parser names
        # Default to 'hybrid' for unknown types for better resilience than a specific parser
        parser_name = prompt_type 
        if prompt_type not in ParserRegistry.list_parsers():
             log.warning(f"No direct parser mapping for prompt_type '{prompt_type}'. Falling back to 'hybrid'.")
             parser_name = 'hybrid' # Use hybrid or default fallback if direct mapping is missing
        elif prompt_type == "security_analysis_AB_TEST":
            # This is where your A/B test manager would decide which specific parser to use
            # e.g., parser_name = ab_test_manager.get_parser_for_variant(alert_data)
            # For simplicity, let's hardcode a specific A/B test parser here if such a parser exists
            log.info(f"A/B test prompt type '{prompt_type}' detected. Assigning a specific parser for test.")
            parser_name = "security_analysis" # Assuming security_analysis parser handles both
        
        parser = ParserRegistry.get_parser(parser_name) # Get parser instance
        
        structured_data = {}
        parse_success = False
        parse_error = ""
        parse_time_ms = 0.0
        
        # Check circuit breaker before attempting to parse
        if not self.circuit_breaker.allow_request(prompt_type):
            log.warning(f"Circuit breaker OPEN for {prompt_type}. Skipping parsing for alert {alert_id}.")
            parse_error = f"Circuit breaker OPEN for {prompt_type}."
            # Provide a basic structured output even if circuit is open
            structured_data = {
                "subject": f"Circuit Breaker Open: {prompt_type} Parser Disabled",
                "sections": {
                    "Raw LLM Response": llm_response_text,
                    "Error": parse_error,
                    "Recommendation": "The parser for this prompt type is temporarily disabled due to consecutive failures. It will automatically re-enable for testing after a timeout."
                },
                ""
"metadata": {
                    "alert_id": alert_id,
                    "prompt_type": prompt_type,
                    "parser_used": parser_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "circuit_breaker_blocked"
                }
            }
            # Record circuit breaker block as a failure in parser_metrics for audit
            save_parser_metrics(
                conn_for_metrics, alert_id, prompt_type, parser_name,
                False, parse_time_ms, parse_error
            )
            return structured_data

        start_time = time.perf_counter()
        try:
            structured_data = parser.parse(llm_response_text) # Rule ID isn't always available/needed by parsers
            parse_success = parser.validate_output(structured_data) # Validate output after parsing
            if not parse_success:
                parse_error = "Parser produced invalid or incomplete output."
                raise ValueError(parse_error) # Raise error to trigger failure handling
            
            log.info(f"Successfully parsed alert {alert_id} using {parser_name} for prompt type {prompt_type}")
            self.circuit_breaker.record_success(prompt_type)
        except Exception as e:
            parse_error = str(e)
            log.error(f"Failed to parse alert {alert_id} using {parser_name} for prompt type {prompt_type}: {e}")
            self.circuit_breaker.record_failure(prompt_type)
            # Fallback to a default structure on parse failure
            structured_data = {
                "subject": f"Failed to Parse Alert: {alert_id}",
                "sections": {
                    "Raw LLM Response": llm_response_text,
                    "Error Details": parse_error,
                    "Recommendation": "The system failed to extract structured information. Please review the raw LLM response and error details."
                },
                "metadata": {
                    "alert_id": alert_id,
                    "prompt_type": prompt_type,
                    "parser_used": parser_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "status": "parse_failed"
                }
            }
        finally:
            parse_time_ms = (time.perf_counter() - start_time) * 1000
            # Save metrics to DB
            save_parser_metrics(
                conn_for_metrics, alert_id, prompt_type, parser_name,
                parse_success, parse_time_ms, parse_error
            )
        
        # Add metadata to the structured_data
        if 'metadata' not in structured_data:
            structured_data['metadata'] = {}
        structured_data['metadata'].update({
            "alert_id": alert_id,
            "prompt_type": prompt_type,
            "parser_used": parser_name,
            "parse_success": parse_success,
            "parse_time_ms": parse_time_ms,
            "parse_error": parse_error if parse_error else None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        return structured_data


# Global variable for connection within AlertStructurer.structure_alert
# This is a bit of a hack for simplicity, but in a real app,
# you'd pass the connection down or use a connection pool.
conn_for_metrics: Optional[psycopg2.extensions.connection] = None


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


def ensure_columns_exist(conn: psycopg2.extensions.connection):
    """Ensure necessary columns exist in alerts and parser_metrics tables."""
    try:
        with conn.cursor() as cur:
            # Alerts table updates
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='structured_data') THEN
                        ALTER TABLE alerts ADD COLUMN structured_data JSONB;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='structured_at') THEN
                        ALTER TABLE alerts ADD COLUMN structured_at TIMESTAMP WITH TIME ZONE;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='prompt_type') THEN
                        ALTER TABLE alerts ADD COLUMN prompt_type TEXT;
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='alerts' AND column_name='parser_used') THEN
                        ALTER TABLE alerts ADD COLUMN parser_used TEXT;
                    END IF;
                END $$;
            """)

            # Parser Metrics table creation
            cur.execute("""
                CREATE TABLE IF NOT EXISTS parser_metrics (
                    id SERIAL PRIMARY KEY,
                    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
                    prompt_type TEXT NOT NULL,
                    parser_used TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    parse_time_ms NUMERIC(10, 2),
                    error_message TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                );
            """)
            conn.commit()
        log.info("Ensured alerts and parser_metrics columns/tables exist.")
    except Exception as e:
        log.critical(f"Failed to ensure database schema exists: {e}", exc_info=True)
        notifier.notify("STATUS=FATAL: Failed to ensure DB schema. Exiting.") # ADDED: sdnotify on schema ensure failure
        notifier.notify("STOPPING=1")
        sys.exit(1)


def fetch_alert_to_structure(conn, alert_id: int) -> Optional[Dict]:
    """Fetch an alert that needs structuring"""
    sql = """
        SELECT
            id,
            raw,
            response_text,
            prompt_text,
            response_received_at,
            prompt_type, -- Fetch existing prompt_type if available
            rule_level,
            agent_id -- Needed for A/B testing cohort assignment
        FROM alerts
        WHERE state = 'summarized' AND id = %s
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, (alert_id,))
        row = cur.fetchone()
        return row

def save_structured_data(conn, alert_id: int, structured_data: Dict[str, Any]):
    """Save structured data and update alert state"""
    try:
        with conn.cursor() as cur:
            prompt_type = structured_data.get('metadata', {}).get('prompt_type', 'unknown')
            parser_used = structured_data.get('metadata', {}).get('parser_used', 'unknown')

            cur.execute("""
                UPDATE alerts
                SET structured_data = %s,
                    state = 'STRUCTURED', -- FIX: Set to 'STRUCTURED' enum value
                    structured_at = NOW(),
                    prompt_type = %s,
                    parser_used = %s
                WHERE id = %s
            """, (json.dumps(structured_data), prompt_type, parser_used, alert_id))

            # Notify next worker (email formatter)
            cur.execute(f"NOTIFY {NOTIFY_CHANNEL}, %s", (str(alert_id),))

        log.info(f"Saved structured data for alert {alert_id} (Type: {prompt_type}, Parser: {parser_used})")
    except Exception as e:
        log.error(f"Failed to save structured data for alert {alert_id}: {e}")
        notifier.notify(f"STATUS=DB update failed for alert {alert_id}. See logs.") # ADDED: sdnotify on DB update failure
        raise


def save_parser_metrics(conn, alert_id: int, prompt_type: str,
                       parser_used: str, success: bool,
                       parse_time_ms: float, error_message: Optional[str] = None):
    """Record parser success/failure in metrics"""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO parser_metrics
                (alert_id, prompt_type, parser_used, success, parse_time_ms, error_message)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (alert_id, prompt_type, parser_used, success, parse_time_ms, error_message))
    except Exception as e:
        log.error(f"Failed to save parser metrics for alert {alert_id}: {e}")
        notifier.notify(f"STATUS=Error saving parser metrics for alert {alert_id}. See logs.") # ADDED: sdnotify


def get_circuit_breaker_status(conn) -> List[Dict[str, Any]]: # Changed return type to List[Dict[str, Any]]
    """Get circuit breaker status from database (for monitoring/logging, not internal CB logic)"""
    sql = """
        SELECT
            prompt_type,
            COUNT(*) FILTER (WHERE NOT success) as failures_last_hour,
            MAX(created_at) FILTER (WHERE NOT success) as last_failure_ts
        FROM parser_metrics
        WHERE created_at > NOW() - INTERVAL '1 hour'
        GROUP BY prompt_type
    """
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql)
        return list(cur.fetchall()) # Ensure it returns a list of dicts


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
                f"avg: {stat['avg_parse_time_ms']:.1f}ms" if stat['avg_parse_time_ms'] is not None else "N/A"
            )
        notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog after logging stats

# ───── SIGNAL HANDLING ─────────────────────────────────
shutdown = False

def on_signal(signum, _frame):
    global shutdown
    shutdown = True
    log.info(f"Signal {signum} received; shutting down")
    notifier.notify("STOPPING=1") # ADDED: sdnotify on signal received


signal.signal(signal.SIGINT, on_signal)
signal.signal(signal.SIGTERM, on_signal)


# ───── MAIN LOOP ─────────────────────────────────────────
def main():
    """Main event loop"""
    global conn_for_metrics # ADDED: Declare global usage

    log.info("Email Structurer starting up...")
    notifier.notify("READY=1") # ADDED: Signal Systemd that the service is ready
    notifier.notify("STATUS=Starting up...")

    # Connect to database
    conn = connect_db()
    conn_for_metrics = conn # Assign to global variable for use in structure_alert
    ensure_columns_exist(conn)
    notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog after DB connection and schema check

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
    notifier.notify(f"STATUS=Initialized. Parsers: {ParserRegistry.list_parsers()}. CB Config: T={CIRCUIT_BREAKER_THRESHOLD}, TO={CIRCUIT_BREAKER_TIMEOUT}s. A/B Test: {AB_TEST_PERCENTAGE}%.") # ADDED: sdnotify status update

    # Process any backlog
    log.info("Processing backlog...")
    catch_up(conn, structurer)
    notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog after backlog processing

    # Listen for new alerts
    cur = conn.cursor()
    cur.execute(f"LISTEN {LISTEN_CHANNEL};")
    log.info(f"Listening on channel '{LISTEN_CHANNEL}' for alerts to structure")
    notifier.notify(f"STATUS=Listening on '{LISTEN_CHANNEL}' for alerts...") # ADDED: sdnotify status update

    # Statistics logging
    last_stats_log = time.time()
    stats_interval = 3600  # Log stats every hour

    while not shutdown:
        notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping at the start of each loop iteration

        # Initialize alert_data for each iteration to avoid "possibly unbound" warning
        alert_data: Optional[Dict[str, Any]] = None # Pylance fix: initialize here

        try:
            # Log statistics periodically
            if time.time() - last_stats_log > stats_interval:
                log_parser_statistics(conn)
                cb_status = circuit_breaker.get_status()
                log.info(f"Circuit breaker status: {cb_status}")
                notifier.notify(f"STATUS=Logging stats. CB Status: {json.dumps(cb_status)}.") # ADDED: sdnotify for stats/CB status
                last_stats_log = time.time()

            if not select.select([conn], [], [], 5)[0]: # Wait up to 5 seconds for events
                continue # If no events, loop back and ping watchdog again

            conn.poll()

            for notify in conn.notifies:
                notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping before processing each notification
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
                    notifier.notify("WATCHDOG=1") # ADDED: Ping after successful processing

                except Exception as e:
                    log.exception(f"Failed to process alert {notify.payload}: {e}")
                    notifier.notify(f"STATUS=Error processing alert {notify.payload}. See logs.") # ADDED: sdnotify on processing error
                    # Try to save failure metrics
                    try:
                        alert_id_for_failure = int(notify.payload) # Ensure it's an int
                        
                        prompt_type_for_failure = 'unknown'
                        # Check if alert_data was successfully retrieved before trying to access it
                        if alert_data: # Pylance fix: check if alert_data is not None
                            prompt_type_for_failure = alert_data.get('prompt_type', 'unknown')
                        
                        parser_used_for_failure = 'unknown' # Default value

                        save_parser_metrics( # Changed from save_parser_failure
                            conn, alert_id_for_failure,
                            prompt_type_for_failure,
                            parser_used_for_failure, False, 0, str(e) # Pass success=False, parse_time_ms=0
                        )
                    except Exception as inner_e: # Catch errors in saving failure metrics
                        log.error(f"Failed to save inner parser failure metrics for alert {notify.payload}: {inner_e}")
            conn.notifies.clear()

        except psycopg2.OperationalError:
            log.exception("DB connection lost; reconnecting in 5s")
            notifier.notify("STATUS=DB connection lost. Attempting to reconnect...") # ADDED: sdnotify on DB connection loss
            time.sleep(5) # Keep this sleep for reconnection back-off
            try:
                conn = connect_db()
                conn_for_metrics = conn # Re-assign global connection on reconnect
                cur = conn.cursor()
                cur.execute(f"LISTEN {LISTEN_CHANNEL};")
                log.info("Reconnected to Postgres and re-listening.")
                notifier.notify("STATUS=Reconnected to DB. Listening for alerts...") # ADDED: sdnotify on successful reconnect
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
        notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog at start of batch processing

        for alert_id in alert_ids:
            notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog for each item in batch

            # Initialize alert_data for each iteration to avoid "possibly unbound" warning
            alert_data: Optional[Dict[str, Any]] = None # Pylance fix: initialize here

            try:
                alert_data = fetch_alert_to_structure(conn, alert_id)
                if alert_data:
                    structured_data = structurer.structure_alert(alert_data)
                    save_structured_data(conn, alert_id, structured_data)
                    processed += 1
                else:
                    log.debug(f"Backlog alert {alert_id} not found or not in 'summarized' state during catch-up.")
            except Exception as e:
                log.error(f"Failed to process backlog alert {alert_id}: {e}")
                notifier.notify(f"STATUS=Error processing backlog alert {alert_id}. See logs.") # ADDED: sdnotify on backlog error
                # Record failure for backlog processing as well
                try:
                    prompt_type_for_failure = 'unknown'
                    # Check if alert_data was successfully retrieved before trying to access it
                    if alert_data: # Pylance fix: check if alert_data is not None
                        prompt_type_for_failure = alert_data.get('prompt_type', 'unknown')
                    parser_used_for_failure = 'unknown' # Default value
                    save_parser_metrics( # Changed from save_parser_failure
                        conn, alert_id,
                        prompt_type_for_failure,
                        parser_used_for_failure, False, 0, str(e) # Pass success=False, parse_time_ms=0
                    )
                except Exception as inner_e:
                    log.error(f"Failed to save inner parser failure metrics for backlog alert {alert_id}: {inner_e}")

    if processed > 0:
        log.info(f"Processed {processed} backlog alerts")


if __name__ == "__main__":
    main()
