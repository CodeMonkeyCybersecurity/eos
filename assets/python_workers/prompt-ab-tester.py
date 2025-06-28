#!/usr/bin/env python3
# /usr/local/bin/prompt-ab-tester.py
# stanley:stanley 0750
"""
Prompt A/B Testing Coordinator - Pipeline Phase 2.5
Coordinates prompt selection experiments without duplicating LLM processing

IMPROVEMENTS:
- Fixed state/channel alignment with schema.sql
- Separated prompt selection from LLM API calls
- Integrated properly with existing llm-worker.py
- Enhanced experiment tracking and metrics collection
- Streamlined database operations
- Improved error handling and monitoring

This worker acts as a "prompt selection service" that:
1. Listens for enriched alerts
2. Selects appropriate prompt variants based on A/B test configuration
3. Records prompt assignments in the database
4. Tracks experiment metrics and performance
5. Coordinates with LLM worker for actual processing
"""
import os
import sys
import json
import time
import select
import signal
import logging
import hashlib
import random
import psycopg2
import psycopg2.extensions
import psycopg2.extras
from datetime import datetime, timezone, timedelta
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
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

# Pipeline configuration - FIXED: Aligned with schema.sql
LISTEN_CHANNEL = "alert_enriched"     # FIXED: Listen for enriched alerts from schema trigger
NOTIFY_CHANNEL = "alert_analyzed"     # FIXED: Notify LLM worker when prompt assigned
STATE_ENRICHED = "enriched"          # FIXED: Match schema enum values  
STATE_PROMPT_ASSIGNED = "enriched"   # Keep in enriched state until LLM processes

# A/B Testing configuration
EXPERIMENT_CONFIG_FILE = os.getenv("EXPERIMENT_CONFIG_FILE", "/opt/delphi/ab-test-config.json")
PROMPTS_BASE_DIR = os.getenv("PROMPTS_BASE_DIR", "/opt/stackstorm/packs/delphi/prompts")
DEFAULT_PROMPT_TYPE = os.getenv("DEFAULT_PROMPT_TYPE", "delphi_notify_short")

# Performance configuration
BATCH_SIZE = int(os.getenv("AB_TESTER_BATCH_SIZE", "5"))
METRICS_FLUSH_INTERVAL = int(os.getenv("METRICS_FLUSH_INTERVAL", "300"))  # 5 minutes
EXPERIMENT_REFRESH_INTERVAL = int(os.getenv("EXPERIMENT_REFRESH_INTERVAL", "3600"))  # 1 hour

class ExperimentStatus(Enum):
    """Experiment status states"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    DRAFT = "draft"

@dataclass
class PromptVariant:
    """Configuration for a single prompt variant"""
    name: str
    prompt_type: str  # Maps to parser_type enum values
    weight: float
    description: str = ""
    parameters: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}

@dataclass
class ExperimentConfig:
    """A/B test experiment configuration"""
    name: str
    description: str
    status: ExperimentStatus
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    variants: List[PromptVariant]
    cohort_strategy: str = "agent_rule"  # How to assign cohorts
    sticky_sessions: bool = True
    target_rules: List[int] = None  # Specific rule IDs to test, None = all
    min_rule_level: int = 0  # Minimum rule level for inclusion
    sample_rate: float = 1.0  # Percentage of eligible alerts to include
    
    def __post_init__(self):
        if self.target_rules is None:
            self.target_rules = []
    
    def is_active(self) -> bool:
        """Check if experiment is currently active"""
        if self.status != ExperimentStatus.ACTIVE:
            return False
            
        now = datetime.now(timezone.utc)
        
        if self.start_date and now < self.start_date:
            return False
            
        if self.end_date and now > self.end_date:
            return False
            
        return True
    
    def is_alert_eligible(self, alert_data: Dict[str, Any]) -> bool:
        """Check if alert is eligible for this experiment"""
        if not self.is_active():
            return False
        
        rule_id = alert_data.get('rule_id', 0)
        rule_level = alert_data.get('rule_level', 0)
        
        # Check rule level requirement
        if rule_level < self.min_rule_level:
            return False
        
        # Check specific rule targeting
        if self.target_rules and rule_id not in self.target_rules:
            return False
        
        # Check sample rate
        if self.sample_rate < 1.0:
            # Use alert hash for consistent sampling
            alert_hash = alert_data.get('alert_hash', '')
            sample_seed = int(hashlib.md5(alert_hash.encode()).hexdigest()[:8], 16)
            if (sample_seed % 100) / 100.0 > self.sample_rate:
                return False
        
        return True

# ───── LOGGER SETUP ─────────────────────────────────────
def setup_logging() -> logging.Logger:
    """Configure structured logging"""
    logger = logging.getLogger("prompt-ab-tester")
    logger.setLevel(logging.INFO)

    handler = RotatingFileHandler(
        "/var/log/stackstorm/prompt-ab-tester.log",
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

# ───── EXPERIMENT MANAGER ─────────────────────────────────
class ExperimentManager:
    """Manages A/B testing experiments and prompt selection"""
    
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.experiments: List[ExperimentConfig] = []
        self.cohort_assignments: Dict[str, str] = {}  # cohort_id -> variant_name
        self.variant_metrics: Dict[str, Dict[str, Any]] = {}
        self.last_config_refresh = datetime.min.replace(tzinfo=timezone.utc)
        self._load_experiments()
        
    def _load_experiments(self):
        """Load experiment configurations from file"""
        try:
            if not os.path.exists(self.config_file):
                log.warning("Experiment config file not found: %s", self.config_file)
                self.experiments = []
                return
                
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            self.experiments = []
            experiments_data = config_data.get('experiments', [])
            
            for exp_data in experiments_data:
                try:
                    # Parse dates
                    start_date = None
                    if exp_data.get('start_date'):
                        start_date = datetime.fromisoformat(
                            exp_data['start_date'].replace('Z', '+00:00')
                        )
                    
                    end_date = None  
                    if exp_data.get('end_date'):
                        end_date = datetime.fromisoformat(
                            exp_data['end_date'].replace('Z', '+00:00')
                        )
                    
                    # Parse variants
                    variants = []
                    total_weight = sum(v.get('weight', 1) for v in exp_data.get('variants', []))
                    
                    for variant_data in exp_data.get('variants', []):
                        variant = PromptVariant(
                            name=variant_data.get('name', ''),
                            prompt_type=variant_data.get('prompt_type', DEFAULT_PROMPT_TYPE),
                            weight=variant_data.get('weight', 1) / total_weight,
                            description=variant_data.get('description', ''),
                            parameters=variant_data.get('parameters', {})
                        )
                        variants.append(variant)
                    
                    experiment = ExperimentConfig(
                        name=exp_data.get('name', ''),
                        description=exp_data.get('description', ''),
                        status=ExperimentStatus(exp_data.get('status', 'draft')),
                        start_date=start_date,
                        end_date=end_date,
                        variants=variants,
                        cohort_strategy=exp_data.get('cohort_strategy', 'agent_rule'),
                        sticky_sessions=exp_data.get('sticky_sessions', True),
                        target_rules=exp_data.get('target_rules', []),
                        min_rule_level=exp_data.get('min_rule_level', 0),
                        sample_rate=exp_data.get('sample_rate', 1.0)
                    )
                    
                    self.experiments.append(experiment)
                    log.info("Loaded experiment: %s (%d variants)", 
                            experiment.name, len(experiment.variants))
                    
                except Exception as e:
                    log.error("Failed to parse experiment config: %s", e)
                    continue
            
            self.last_config_refresh = datetime.now(timezone.utc)
            log.info("Loaded %d experiments from config", len(self.experiments))
            
        except Exception as e:
            log.error("Failed to load experiment config: %s", e)
            self.experiments = []
    
    def refresh_config_if_needed(self):
        """Refresh configuration if enough time has passed"""
        if (datetime.now(timezone.utc) - self.last_config_refresh).total_seconds() > EXPERIMENT_REFRESH_INTERVAL:
            log.info("Refreshing experiment configuration...")
            self._load_experiments()
    
    def get_cohort_id(self, alert_data: Dict[str, Any], strategy: str = "agent_rule") -> str:
        """Generate cohort ID for consistent assignment"""
        if strategy == "agent_rule":
            # Combine agent_id and rule_id for sticky assignment per agent/rule combo
            agent_id = str(alert_data.get('agent_id', ''))
            rule_id = str(alert_data.get('rule_id', ''))
            cohort_data = f"{agent_id}:{rule_id}"
        elif strategy == "agent_only":
            # Only use agent_id (same prompt for all rules on an agent)
            cohort_data = str(alert_data.get('agent_id', ''))
        elif strategy == "rule_only":
            # Only use rule_id (same prompt for all agents with this rule)
            cohort_data = str(alert_data.get('rule_id', ''))
        else:
            # Default fallback
            cohort_data = str(alert_data.get('alert_hash', ''))
        
        return hashlib.md5(cohort_data.encode()).hexdigest()[:12]
    
    def select_prompt_variant(self, alert_data: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        """
        Select prompt variant for an alert
        Returns: (prompt_type, experiment_name)
        """
        # Find eligible experiment
        active_experiment = None
        for experiment in self.experiments:
            if experiment.is_alert_eligible(alert_data):
                active_experiment = experiment
                break
        
        if not active_experiment:
            log.debug("No active experiment for alert %s, using default", 
                     alert_data.get('id'))
            return DEFAULT_PROMPT_TYPE, None
        
        # Get cohort ID
        cohort_id = self.get_cohort_id(alert_data, active_experiment.cohort_strategy)
        
        # Check for existing assignment (sticky sessions)
        if active_experiment.sticky_sessions:
            assignment_key = f"{active_experiment.name}:{cohort_id}"
            if assignment_key in self.cohort_assignments:
                assigned_variant = self.cohort_assignments[assignment_key]
                # Verify variant still exists in experiment
                for variant in active_experiment.variants:
                    if variant.name == assigned_variant:
                        log.debug("Using sticky assignment for cohort %s: %s", 
                                 cohort_id, variant.prompt_type)
                        return variant.prompt_type, active_experiment.name
        
        # Select new variant based on weights
        selected_variant = self._weighted_selection(active_experiment.variants)
        
        if not selected_variant:
            log.warning("No variant selected from experiment %s, using default", 
                       active_experiment.name)
            return DEFAULT_PROMPT_TYPE, None
        
        # Record assignment for sticky sessions
        if active_experiment.sticky_sessions:
            assignment_key = f"{active_experiment.name}:{cohort_id}"
            self.cohort_assignments[assignment_key] = selected_variant.name
        
        log.info("Selected variant for alert %s: %s (experiment: %s)", 
                alert_data.get('id'), selected_variant.prompt_type, active_experiment.name)
        
        return selected_variant.prompt_type, active_experiment.name
    
    def _weighted_selection(self, variants: List[PromptVariant]) -> Optional[PromptVariant]:
        """Select variant using weighted random selection"""
        if not variants:
            return None
        
        rand = random.random()
        cumulative_weight = 0.0
        
        for variant in variants:
            cumulative_weight += variant.weight
            if rand <= cumulative_weight:
                return variant
        
        # Fallback to last variant
        return variants[-1] if variants else None
    
    def record_assignment(self, alert_id: int, prompt_type: str, experiment_name: Optional[str]):
        """Record prompt assignment for metrics tracking"""
        # Initialize metrics if needed
        metric_key = f"{experiment_name or 'default'}:{prompt_type}"
        if metric_key not in self.variant_metrics:
            self.variant_metrics[metric_key] = {
                "assignments": 0,
                "successes": 0,
                "failures": 0,
                "total_tokens": 0,
                "avg_response_time": 0.0,
                "first_used": datetime.now(timezone.utc).isoformat(),
                "last_used": None
            }
        
        # Update assignment count
        self.variant_metrics[metric_key]["assignments"] += 1
        self.variant_metrics[metric_key]["last_used"] = datetime.now(timezone.utc).isoformat()
        
        log.debug("Recorded assignment for alert %s: %s", alert_id, metric_key)
    
    def record_result(self, prompt_type: str, experiment_name: Optional[str], 
                     success: bool, response_time: float = 0.0, token_count: int = 0):
        """Record processing result for metrics"""
        metric_key = f"{experiment_name or 'default'}:{prompt_type}"
        
        if metric_key not in self.variant_metrics:
            return  # No assignment recorded
        
        metrics = self.variant_metrics[metric_key]
        
        if success:
            metrics["successes"] += 1
        else:
            metrics["failures"] += 1
        
        # Update average response time
        total_responses = metrics["successes"] + metrics["failures"]
        if total_responses > 1:
            metrics["avg_response_time"] = (
                (metrics["avg_response_time"] * (total_responses - 1) + response_time) 
                / total_responses
            )
        else:
            metrics["avg_response_time"] = response_time
        
        metrics["total_tokens"] += token_count
        metrics["last_used"] = datetime.now(timezone.utc).isoformat()
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        summary = {
            "experiments": len(self.experiments),
            "active_experiments": len([e for e in self.experiments if e.is_active()]),
            "total_assignments": len(self.cohort_assignments),
            "variant_metrics": {},
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
        for metric_key, metrics in self.variant_metrics.items():
            total_responses = metrics["successes"] + metrics["failures"]
            success_rate = metrics["successes"] / max(total_responses, 1)
            
            summary["variant_metrics"][metric_key] = {
                **metrics,
                "success_rate": success_rate,
                "total_responses": total_responses
            }
        
        return summary

# ───── DATABASE OPERATIONS ─────────────────────────────────
class DatabaseManager:
    """Manage database operations for A/B testing"""
    
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
            
    def fetch_enriched_alerts(self, batch_size: int) -> List[Dict[str, Any]]:
        """Fetch alerts ready for prompt assignment"""
        self.ensure_connection()
        
        sql = """
            SELECT
                a.id,
                a.alert_hash,
                a.agent_id,
                a.rule_id,
                a.rule_level,
                a.rule_desc,
                a.raw,
                a.enriched_at,
                a.prompt_type,
                ag.name as agent_name
            FROM alerts a
            JOIN agents ag ON ag.id = a.agent_id
            WHERE a.state = %s
              AND a.prompt_type IS NULL
              AND a.archived_at IS NULL
            ORDER BY a.rule_level DESC, a.enriched_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        """
        
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, (STATE_ENRICHED, batch_size))
                alerts = cur.fetchall()
                return [dict(alert) for alert in alerts]
                
        except Exception as e:
            log.error("Failed to fetch enriched alerts: %s", e)
            return []
    
    def assign_prompt_type(self, alert_id: int, prompt_type: str) -> bool:
        """Assign prompt type to alert and trigger LLM processing"""
        self.ensure_connection()
        
        sql = """
            UPDATE alerts
            SET prompt_type = %s,
                prompt_template = %s
            WHERE id = %s
              AND state = %s
              AND prompt_type IS NULL
        """
        
        try:
            with self.conn.cursor() as cur:
                # Use prompt_type as template identifier for now
                cur.execute(sql, (prompt_type, prompt_type, alert_id, STATE_ENRICHED))
                
                if cur.rowcount == 0:
                    log.warning("Alert %s was not updated (already processed or wrong state)", alert_id)
                    return False
                
                # Notify LLM worker that prompt is assigned
                cur.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, str(alert_id)))
                
            log.debug("Assigned prompt type %s to alert %s", prompt_type, alert_id)
            return True
            
        except Exception as e:
            log.error("Failed to assign prompt type to alert %s: %s", alert_id, e)
            return False
    
    def save_ab_test_metrics(self, metrics_data: Dict[str, Any]):
        """Save A/B test metrics to database or file"""
        # For now, save to a JSON file. In production, you might want a dedicated metrics table
        try:
            metrics_file = "/var/log/stackstorm/ab-test-metrics.jsonl"
            os.makedirs(os.path.dirname(metrics_file), exist_ok=True)
            
            with open(metrics_file, 'a') as f:
                f.write(json.dumps(metrics_data) + '\n')
                
        except Exception as e:
            log.error("Failed to save A/B test metrics: %s", e)

# ───── MAIN SERVICE LOGIC ─────────────────────────────────
class PromptABTesterService:
    """Main A/B testing service orchestrator"""
    
    def __init__(self):
        self.shutdown = False
        self.db = DatabaseManager(PG_DSN)
        self.experiment_manager = ExperimentManager(EXPERIMENT_CONFIG_FILE)
        self.stats = {
            'assignments': 0,
            'experiments_used': 0,
            'defaults_used': 0
        }
        self.last_metrics_flush = time.time()
        
        # Signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        log.info("Received signal %d, initiating shutdown", signum)
        self.shutdown = True
        self._flush_metrics()
        notifier.status("Shutting down gracefully")
        notifier.stopping()
        
    def run(self):
        """Main service loop"""
        log.info("Prompt A/B Tester Service starting...")
        notifier.ready()
        notifier.status("Starting prompt A/B testing service")
        
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
        """Process any alerts waiting for prompt assignment"""
        log.info("Processing backlog...")
        backlog_count = 0
        
        while not self.shutdown:
            alerts = self.db.fetch_enriched_alerts(BATCH_SIZE)
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
            
            # Refresh config and flush metrics periodically
            current_time = time.time()
            if current_time - self.last_metrics_flush > METRICS_FLUSH_INTERVAL:
                self.experiment_manager.refresh_config_if_needed()
                self._flush_metrics()
                
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
        alerts = self.db.fetch_enriched_alerts(BATCH_SIZE)
        
        for alert in alerts:
            if self.shutdown:
                break
            self._process_alert(alert)
            notifier.watchdog()
            
    def _process_alert(self, alert: Dict[str, Any]):
        """Process a single alert for prompt assignment"""
        alert_id = alert['id']
        
        log.info("Processing alert %s for prompt assignment", alert_id)
        
        try:
            # Select prompt variant
            prompt_type, experiment_name = self.experiment_manager.select_prompt_variant(alert)
            
            # Assign prompt type in database
            if self.db.assign_prompt_type(alert_id, prompt_type):
                # Record assignment metrics
                self.experiment_manager.record_assignment(alert_id, prompt_type, experiment_name)
                
                self.stats['assignments'] += 1
                if experiment_name:
                    self.stats['experiments_used'] += 1
                else:
                    self.stats['defaults_used'] += 1
                
                log.info("Assigned prompt %s to alert %s (experiment: %s)", 
                        prompt_type, alert_id, experiment_name or "default")
            else:
                log.warning("Failed to assign prompt to alert %s", alert_id)
                
        except Exception as e:
            log.error("Failed to process alert %s: %s", alert_id, e)
            
    def _flush_metrics(self):
        """Flush current metrics to storage"""
        try:
            metrics_summary = self.experiment_manager.get_metrics_summary()
            metrics_summary['service_stats'] = self.stats.copy()
            
            self.db.save_ab_test_metrics(metrics_summary)
            
            log.info("A/B test metrics: assignments=%d, experiments=%d, defaults=%d",
                    self.stats['assignments'], self.stats['experiments_used'], 
                    self.stats['defaults_used'])
            
            notifier.status(f"Assignments: {self.stats['assignments']}, "
                          f"Experiments: {self.stats['experiments_used']}")
            
            self.last_metrics_flush = time.time()
            
        except Exception as e:
            log.error("Failed to flush metrics: %s", e)

# ───── ENTRY POINT ─────────────────────────────────────
def main():
    """Service entry point"""
    try:
        service = PromptABTesterService()
        service.run()
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as e:
        log.critical("Fatal error: %s", e, exc_info=True)
        notifier.status(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        log.info("Prompt A/B Tester Service stopped")
        notifier.stopping()

if __name__ == "__main__":
    main()