#!/usr/bin/env python3
# /usr/local/bin/prompt-ab-tester.py
# stanley:stanley 0750

"""
Advanced A/B/C Testing Worker for Delphi System Prompts

This worker replaces the static prompt loading in llm-worker.py with dynamic 
prompt selection for A/B/C testing. It:

* Monitors the 'agent_enriched' PostgreSQL notification channel
* Randomly selects prompts from configured test groups
* Tracks prompt performance and effectiveness metrics
* Supports weighted distribution and cohort testing
* Maintains experiment state and controls
* Logs detailed metrics for analysis

Features:
- Multi-variant testing (A/B/C/D/etc.)
- Weighted prompt selection
- User cohort assignment (sticky sessions)
- Performance metrics collection
- Experiment configuration via JSON
- Fallback to default prompt on errors
- Comprehensive logging and monitoring
"""

import os
import sys
import json
import time
import logging
import hashlib
import random
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

try:
    import requests  # type: ignore
except ImportError:
    requests = None

try:
    import psycopg2  # type: ignore
    from psycopg2.extras import DictCursor  # type: ignore
except ImportError:
    psycopg2 = None
    DictCursor = None

try:
    from dotenv import load_dotenv  # type: ignore
except ImportError:
    load_dotenv = None

# --- Configuration & Environment Variables ---

if load_dotenv is not None:
    load_dotenv("/opt/stackstorm/packs/delphi/.env")

# PostgreSQL Database Connection
PG_DSN = os.getenv("PG_DSN")
if not PG_DSN:
    raise ValueError("PG_DSN environment variable not set.")

# Azure OpenAI API Configuration
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
ENDPOINT_URL = os.getenv("ENDPOINT_URL")
DEPLOYMENT_NAME = os.getenv("DEPLOYMENT_NAME")
AZURE_API_VERSION = os.getenv("AZURE_API_VERSION")

if not all([AZURE_OPENAI_API_KEY, ENDPOINT_URL, DEPLOYMENT_NAME, AZURE_API_VERSION]):
    raise ValueError("Missing required Azure OpenAI environment variables.")

# A/B Testing Configuration
EXPERIMENT_CONFIG_FILE = os.environ.get("EXPERIMENT_CONFIG_FILE", "/opt/delphi/ab-test-config.json")
SYSTEM_PROMPTS_DIR = os.environ.get("SYSTEM_PROMPTS_DIR", "/srv/eos/system-prompts")
DEFAULT_PROMPT_FILE = os.environ.get("DEFAULT_PROMPT_FILE", "/srv/eos/system-prompts/default.txt")

# Logging and Monitoring
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/stackstorm/prompt-ab-tester.log")
HEARTBEAT_FILE = os.environ.get("HEARTBEAT_FILE", "/var/log/stackstorm/prompt-ab-tester.heartbeat")
METRICS_FILE = os.environ.get("METRICS_FILE", "/var/log/stackstorm/ab-test-metrics.log")
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", 10485760))

# PostgreSQL LISTEN channel
LISTEN_CHANNEL = "agent_enriched"

# --- Data Structures ---

class ExperimentConfig:
    """Configuration for A/B/C testing experiments"""
    
    def __init__(self, config_data: Dict):
        self.name = config_data.get("name", "default")
        self.description = config_data.get("description", "")
        self.enabled = config_data.get("enabled", True)
        self.start_date = config_data.get("start_date")
        self.end_date = config_data.get("end_date")
        self.cohort_assignment = config_data.get("cohort_assignment", "random")
        self.sticky_sessions = config_data.get("sticky_sessions", True)
        self.variants = self._parse_variants(config_data.get("variants", []))
        self.metrics_tracking = config_data.get("metrics_tracking", {})
        
    def _parse_variants(self, variants_data: List[Dict]) -> List['PromptVariant']:
        """Parse variant configurations into PromptVariant objects"""
        variants = []
        total_weight = sum(v.get("weight", 1) for v in variants_data)
        
        for variant_data in variants_data:
            variant = PromptVariant(
                name=variant_data.get("name", ""),
                prompt_file=variant_data.get("prompt_file", ""),
                weight=variant_data.get("weight", 1) / total_weight,
                description=variant_data.get("description", ""),
                parameters=variant_data.get("parameters", {})
            )
            variants.append(variant)
        
        return variants
    
    def is_active(self) -> bool:
        """Check if experiment is currently active"""
        if not self.enabled:
            return False
            
        now = datetime.now(timezone.utc)
        
        if self.start_date:
            start = datetime.fromisoformat(self.start_date.replace('Z', '+00:00'))
            if now < start:
                return False
                
        if self.end_date:
            end = datetime.fromisoformat(self.end_date.replace('Z', '+00:00'))
            if now > end:
                return False
                
        return True

class PromptVariant:
    """Individual prompt variant in an A/B test"""
    
    def __init__(self, name: str, prompt_file: str, weight: float, 
                 description: str = "", parameters: Dict = None):
        self.name = name
        self.prompt_file = prompt_file
        self.weight = weight
        self.description = description
        self.parameters = parameters or {}
        self._prompt_content: Optional[str] = None
    
    def get_prompt_content(self, prompts_dir: str) -> str:
        """Load and return prompt content, with caching"""
        if self._prompt_content is None:
            prompt_path = Path(prompts_dir) / self.prompt_file
            try:
                with open(prompt_path, 'r', encoding='utf-8') as f:
                    self._prompt_content = f.read().strip()
            except FileNotFoundError:
                raise FileNotFoundError(f"Prompt file not found: {prompt_path}")
            except Exception as e:
                raise Exception(f"Error loading prompt from {prompt_path}: {e}")
        
        return self._prompt_content

class ABTestManager:
    """Manages A/B/C testing logic and prompt selection"""
    
    def __init__(self, config_file: str, prompts_dir: str):
        self.config_file = config_file
        self.prompts_dir = prompts_dir
        self.experiment: Optional[ExperimentConfig] = None
        self.user_assignments: Dict[str, str] = {}  # user_id -> variant_name
        self.variant_metrics: Dict[str, Dict] = {}  # variant_name -> metrics
        self._load_experiment_config()
        
    def _load_experiment_config(self):
        """Load experiment configuration from JSON file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            self.experiment = ExperimentConfig(config_data)
            
            # Initialize metrics tracking for each variant
            for variant in self.experiment.variants:
                if variant.name not in self.variant_metrics:
                    self.variant_metrics[variant.name] = {
                        "total_uses": 0,
                        "successful_responses": 0,
                        "failed_responses": 0,
                        "avg_response_time": 0.0,
                        "total_tokens": 0,
                        "first_used": None,
                        "last_used": None
                    }
                    
        except FileNotFoundError:
            log.warning(f"Experiment config file not found: {self.config_file}. Using fallback mode.")
            self.experiment = None
        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON in experiment config: {e}. Using fallback mode.")
            self.experiment = None
        except Exception as e:
            log.error(f"Error loading experiment config: {e}. Using fallback mode.")
            self.experiment = None
    
    def get_user_cohort_id(self, alert_data: Dict) -> str:
        """Generate a consistent cohort ID for sticky sessions"""
        # Use agent_id + rule_id for consistency
        agent_id = str(alert_data.get('agent_id', ''))
        rule_id = str(alert_data.get('rule', {}).get('id', ''))
        
        # Create a stable hash for cohort assignment
        cohort_data = f"{agent_id}:{rule_id}"
        return hashlib.md5(cohort_data.encode()).hexdigest()[:8]
    
    def select_prompt_variant(self, alert_data: Dict) -> Tuple[str, str]:
        """
        Select which prompt variant to use for this alert.
        Returns: (variant_name, prompt_content)
        """
        # Fallback to default if no experiment configured
        if not self.experiment or not self.experiment.is_active():
            return self._get_default_prompt()
        
        # Get user cohort for sticky sessions
        cohort_id = self.get_user_cohort_id(alert_data)
        
        # Check if user already has a variant assignment (sticky sessions)
        if self.experiment.sticky_sessions and cohort_id in self.user_assignments:
            assigned_variant = self.user_assignments[cohort_id]
            variant = self._get_variant_by_name(assigned_variant)
            if variant:
                try:
                    prompt_content = variant.get_prompt_content(self.prompts_dir)
                    return assigned_variant, prompt_content
                except Exception as e:
                    log.error(f"Error loading assigned variant {assigned_variant}: {e}")
                    # Fall through to new assignment
        
        # Select new variant based on weights
        selected_variant = self._weighted_variant_selection()
        
        if not selected_variant:
            return self._get_default_prompt()
        
        try:
            prompt_content = selected_variant.get_prompt_content(self.prompts_dir)
            
            # Record assignment for sticky sessions
            if self.experiment.sticky_sessions:
                self.user_assignments[cohort_id] = selected_variant.name
            
            return selected_variant.name, prompt_content
            
        except Exception as e:
            log.error(f"Error loading variant {selected_variant.name}: {e}")
            return self._get_default_prompt()
    
    def _weighted_variant_selection(self) -> Optional[PromptVariant]:
        """Select variant based on configured weights"""
        if not self.experiment or not self.experiment.variants:
            return None
        
        # Generate random number for selection
        rand = random.random()
        cumulative_weight = 0.0
        
        for variant in self.experiment.variants:
            cumulative_weight += variant.weight
            if rand <= cumulative_weight:
                return variant
        
        # Fallback to last variant
        return self.experiment.variants[-1] if self.experiment.variants else None
    
    def _get_variant_by_name(self, name: str) -> Optional[PromptVariant]:
        """Get variant by name"""
        if not self.experiment:
            return None
        
        for variant in self.experiment.variants:
            if variant.name == name:
                return variant
        return None
    
    def _get_default_prompt(self) -> Tuple[str, str]:
        """Load default prompt as fallback"""
        try:
            with open(DEFAULT_PROMPT_FILE, 'r', encoding='utf-8') as f:
                default_content = f.read().strip()
            return "default", default_content
        except Exception as e:
            log.error(f"Error loading default prompt: {e}")
            return "fallback", "You are a helpful AI assistant for security analysis."
    
    def record_usage_metrics(self, variant_name: str, success: bool, 
                           response_time: float, token_count: int):
        """Record metrics for a variant usage"""
        if variant_name not in self.variant_metrics:
            return
        
        metrics = self.variant_metrics[variant_name]
        metrics["total_uses"] += 1
        
        if success:
            metrics["successful_responses"] += 1
        else:
            metrics["failed_responses"] += 1
        
        # Update average response time
        total_responses = metrics["successful_responses"] + metrics["failed_responses"]
        if total_responses > 1:
            metrics["avg_response_time"] = (
                (metrics["avg_response_time"] * (total_responses - 1) + response_time) 
                / total_responses
            )
        else:
            metrics["avg_response_time"] = response_time
        
        metrics["total_tokens"] += token_count
        
        now = datetime.now(timezone.utc).isoformat()
        if not metrics["first_used"]:
            metrics["first_used"] = now
        metrics["last_used"] = now
    
    def get_metrics_summary(self) -> Dict:
        """Get comprehensive metrics summary for reporting"""
        if not self.experiment:
            return {"error": "No active experiment"}
        
        summary = {
            "experiment": {
                "name": self.experiment.name,
                "description": self.experiment.description,
                "active": self.experiment.is_active(),
                "variants_count": len(self.experiment.variants)
            },
            "variants": {},
            "total_assignments": len(self.user_assignments),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
        for variant_name, metrics in self.variant_metrics.items():
            success_rate = 0.0
            total_responses = metrics["successful_responses"] + metrics["failed_responses"]
            if total_responses > 0:
                success_rate = metrics["successful_responses"] / total_responses
            
            summary["variants"][variant_name] = {
                **metrics,
                "success_rate": success_rate,
                "avg_tokens_per_use": metrics["total_tokens"] / max(metrics["total_uses"], 1)
            }
        
        return summary

# --- Logger Setup ---
def setup_logging() -> logging.Logger:
    """Configure logging for the A/B testing worker"""
    logger = logging.getLogger("prompt-ab-tester")
    logger.setLevel(logging.INFO)
    
    # Ensure log directory exists
    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=3
    )
    file_formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(file_formatter)
    logger.addHandler(console_handler)
    
    return logger

log = setup_logging()

# --- Metrics Logging ---
def log_metrics(metrics_data: Dict):
    """Log metrics to dedicated metrics file"""
    try:
        metrics_dir = os.path.dirname(METRICS_FILE)
        os.makedirs(metrics_dir, exist_ok=True)
        
        with open(METRICS_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(metrics_data) + '\n')
    except Exception as e:
        log.error(f"Failed to write metrics: {e}")

# --- Heartbeat Management ---
def update_heartbeat_file():
    """Update heartbeat file with current timestamp"""
    try:
        with open(HEARTBEAT_FILE, 'w', encoding='utf-8') as f:
            f.write(datetime.now(timezone.utc).isoformat())
    except IOError as e:
        log.error(f"Failed to update heartbeat file: {e}")

# --- Initialize A/B Test Manager ---
ab_test_manager = ABTestManager(EXPERIMENT_CONFIG_FILE, SYSTEM_PROMPTS_DIR)

# --- LLM Interaction with A/B Testing ---
def get_llm_response_with_testing(raw_alert_json: Dict, agent_details_json: Dict, 
                                 alert_id: int) -> Optional[Dict]:
    """
    Enhanced LLM response function with A/B testing capabilities
    """
    if requests is None:
        log.error("requests module not available")
        return None
    
    start_time = time.time()
    variant_name = None
    
    try:
        # Select prompt variant using A/B testing logic
        variant_name, system_prompt = ab_test_manager.select_prompt_variant(raw_alert_json)
        
        log.info(f"Alert {alert_id}: Using prompt variant '{variant_name}'")
        
        # Construct user message
        user_message_content = {
            "alert": raw_alert_json,
            "agent_details": agent_details_json
        }
        user_message_str = json.dumps(user_message_content, indent=2)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message_str}
        ]
        
        # API call setup
        headers = {
            "api-key": AZURE_OPENAI_API_KEY,
            "Content-Type": "application/json"
        }
        
        api_url = f"{ENDPOINT_URL}/openai/deployments/{DEPLOYMENT_NAME}/chat/completions?api-version={AZURE_API_VERSION}"
        
        payload = {
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.7,
            "top_p": 0.95,
            "frequency_penalty": 0,
            "presence_penalty": 0,
            "stop": ["<|im_end|>"]
        }
        
        log.info(f"Alert {alert_id}: Sending request to Azure OpenAI API...")
        response = requests.post(api_url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        
        response_data = response.json()
        
        # Extract response details
        completion_content = response_data['choices'][0]['message']['content']
        prompt_tokens = response_data['usage']['prompt_tokens']
        completion_tokens = response_data['usage']['completion_tokens']
        total_tokens = response_data['usage']['total_tokens']
        
        response_time = time.time() - start_time
        
        log.info(f"Alert {alert_id}: LLM response received. "
                f"Variant: {variant_name}, Tokens: {total_tokens}, "
                f"Response time: {response_time:.2f}s")
        
        # Record metrics for this variant
        ab_test_manager.record_usage_metrics(
            variant_name, True, response_time, total_tokens
        )
        
        # Log metrics for analysis
        metrics_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "variant_name": variant_name,
            "success": True,
            "response_time": response_time,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "agent_id": raw_alert_json.get('agent_id'),
            "rule_level": raw_alert_json.get('rule', {}).get('level')
        }
        log_metrics(metrics_entry)
        
        return {
            "parsed_response": completion_content,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "variant_name": variant_name,
            "response_time": response_time
        }
        
    except Exception as e:
        response_time = time.time() - start_time
        
        log.error(f"Alert {alert_id}: LLM API error with variant '{variant_name}': {e}")
        
        # Record failure metrics
        if variant_name:
            ab_test_manager.record_usage_metrics(
                variant_name, False, response_time, 0
            )
            
            # Log failure metrics
            metrics_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_id": alert_id,
                "variant_name": variant_name,
                "success": False,
                "response_time": response_time,
                "error": str(e),
                "agent_id": raw_alert_json.get('agent_id'),
                "rule_level": raw_alert_json.get('rule', {}).get('level')
            }
            log_metrics(metrics_entry)
        
        return None

# --- Enhanced Alert Processing ---
def process_alert_for_llm_with_testing(alert_id: int) -> Optional[Dict]:
    """
    Enhanced alert processing with A/B testing integration
    """
    if psycopg2 is None:
        log.error("psycopg2 module not available")
        return None
    
    conn = None
    cur = None
    
    try:
        conn = psycopg2.connect(PG_DSN)
        cur = conn.cursor(cursor_factory=DictCursor)
        
        # Fetch alert record
        cur.execute("SELECT * FROM alerts WHERE id = %s;", (alert_id,))
        alert_record = cur.fetchone()
        
        if not alert_record:
            log.error(f"Alert {alert_id} not found in database")
            return None
        
        # Check if already processed
        if isinstance(alert_record, tuple):
            current_state = alert_record[8] if len(alert_record) > 8 else None  # Adjust index
            agent_id = alert_record[5] if len(alert_record) > 5 else None
            raw_alert = alert_record[3] if len(alert_record) > 3 else {}
        else:
            current_state = alert_record.get('state')
            agent_id = alert_record.get('agent_id')
            raw_alert = alert_record.get('raw', {})
        
        if current_state != 'agent_enriched':
            log.info(f"Alert {alert_id} state is '{current_state}', skipping")
            return dict(alert_record) if alert_record else None
        
        # Fetch agent details
        agent_details = {}
        if agent_id:
            cur.execute("SELECT api_response FROM agents WHERE id = %s;", (agent_id,))
            agent_data = cur.fetchone()
            if agent_data:
                agent_details = agent_data[0] if isinstance(agent_data, tuple) else agent_data.get('api_response', {})
        
        # Process with A/B testing
        llm_response = get_llm_response_with_testing(raw_alert, agent_details, alert_id)
        
        if not llm_response:
            log.error(f"Alert {alert_id}: No valid LLM response received")
            return dict(alert_record) if alert_record else None
        
        # Update database with A/B testing metadata
        variant_name = llm_response.get('variant_name', 'unknown')
        response_time = llm_response.get('response_time', 0.0)
        
        update_query = """
        UPDATE alerts
        SET
            prompt_sent_at = %s,
            prompt_text = %s,
            response_received_at = %s,
            response_text = %s,
            prompt_tokens = %s,
            completion_tokens = %s,
            total_tokens = %s,
            state = %s
        WHERE id = %s;
        """
        
        # Store the variant information in prompt_text field as metadata
        prompt_metadata = {
            "variant_name": variant_name,
            "system_prompt": "A/B test variant",
            "response_time": response_time,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        cur.execute(update_query, (
            datetime.now(timezone.utc),
            json.dumps(prompt_metadata),
            datetime.now(timezone.utc),
            llm_response.get('parsed_response'),
            llm_response.get('prompt_tokens'),
            llm_response.get('completion_tokens'),
            llm_response.get('total_tokens'),
            'summarized',
            alert_id
        ))
        conn.commit()
        
        log.info(f"Alert {alert_id}: Successfully processed with variant '{variant_name}'")
        
        # Notify next stage
        cur.execute("SELECT pg_notify('new_response', %s);", (str(alert_id),))
        conn.commit()
        
        # Return updated record
        cur.execute("SELECT * FROM alerts WHERE id = %s;", (alert_id,))
        return dict(cur.fetchone()) if cur.fetchone() else None
        
    except Exception as e:
        log.error(f"Alert {alert_id}: Processing error: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            if cur:
                cur.close()
            conn.close()

# --- PostgreSQL Listener ---
def listen_for_enriched_alerts():
    """Listen for agent_enriched notifications and process with A/B testing"""
    if psycopg2 is None:
        log.error("psycopg2 module not available")
        return
    
    log.info(f"Starting A/B Testing worker - listening on '{LISTEN_CHANNEL}'")
    log.info(f"Experiment config: {EXPERIMENT_CONFIG_FILE}")
    log.info(f"Prompts directory: {SYSTEM_PROMPTS_DIR}")
    
    # Log current experiment status
    if ab_test_manager.experiment:
        log.info(f"Active experiment: {ab_test_manager.experiment.name} "
                f"({len(ab_test_manager.experiment.variants)} variants)")
    else:
        log.info("No active experiment - using fallback mode")
    
    conn = None
    cur = None
    
    try:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        
        log.info("A/B Testing worker ready - listening for notifications...")
        
        while True:
            conn.poll()
            while conn.notifies:
                notify = conn.notifies.pop(0)
                alert_id_str = notify.payload
                
                log.info(f"Received notification: channel='{notify.channel}', payload='{alert_id_str}'")
                update_heartbeat_file()
                
                try:
                    alert_id = int(alert_id_str)
                    processed_alert = process_alert_for_llm_with_testing(alert_id)
                    
                    if processed_alert:
                        log.info(f"Alert {alert_id}: A/B testing processing complete")
                    else:
                        log.error(f"Alert {alert_id}: A/B testing processing failed")
                        
                except ValueError:
                    log.error(f"Invalid alert_id in notification: {alert_id_str}")
                except Exception as e:
                    log.error(f"Error processing alert {alert_id_str}: {e}", exc_info=True)
            
            time.sleep(0.1)
            
    except Exception as e:
        log.critical(f"Critical error in listener: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if conn:
            if cur:
                cur.close()
            conn.close()

# --- Main Function ---
def main():
    """Main entry point for the A/B testing worker"""
    log.info("=== Starting Delphi Prompt A/B Testing Worker ===")
    
    # Validate dependencies
    if psycopg2 is None:
        log.critical("psycopg2 module not available")
        sys.exit(1)
    
    if requests is None:
        log.critical("requests module not available")
        sys.exit(1)
    
    # Test database connection
    try:
        test_conn = psycopg2.connect(PG_DSN, connect_timeout=5)
        test_conn.close()
        log.info("Database connection test: SUCCESS")
    except Exception as e:
        log.critical(f"Database connection test: FAILED - {e}")
        sys.exit(1)
    
    # Test prompts directory
    if os.path.isdir(SYSTEM_PROMPTS_DIR):
        prompt_files = list(Path(SYSTEM_PROMPTS_DIR).glob("*.txt"))
        log.info(f"Found {len(prompt_files)} prompt files in {SYSTEM_PROMPTS_DIR}")
    else:
        log.warning(f"Prompts directory not found: {SYSTEM_PROMPTS_DIR}")
    
    # Log experiment summary
    if ab_test_manager.experiment:
        metrics_summary = ab_test_manager.get_metrics_summary()
        log.info(f"Experiment status: {json.dumps(metrics_summary, indent=2)}")
    
    # Initial heartbeat
    update_heartbeat_file()
    
    # Start listening
    listen_for_enriched_alerts()

if __name__ == "__main__":
    main()