#!/usr/bin/env python3
# /usr/local/bin/alert-to-db.py
"""
Alert Database Loader - Phase 1 of Delphi Pipeline

This script receives Wazuh alerts from the webhook listener and stores them
in PostgreSQL, initiating the alert processing pipeline.

Key responsibilities:
1. Validate incoming alert data against schema constraints
2. Create minimal agent records to satisfy foreign key requirements
3. Implement deduplication to prevent alert flooding
4. Insert alerts with 'new' state to trigger pipeline processing
"""

import sys
import json
import os
import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple

# ───── Third-party imports with graceful fallbacks ─────
try:
    import psycopg2
    from psycopg2.extras import Json
except ModuleNotFoundError:
    sys.stderr.write(
        "ERROR: Missing dependency 'psycopg2-binary'. "
        "Install it with:\n\n    pip install psycopg2-binary\n\n"
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    # Provide a stub for environments without python-dotenv
    def load_dotenv(*_args, **_kwargs):
        pass
    logging.warning(
        "Optional dependency 'python-dotenv' not found; "
        "continuing without loading a .env file."
    )

# ───── Configuration and Environment ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN = os.getenv("PG_DSN")

if not PG_DSN:
    sys.stderr.write(
        "ERROR: Environment variable PG_DSN is not set "
        "and no .env file supplied it.\n"
    )
    sys.exit(1)

# ───── Logging Configuration ─────
LOG_FILE = "/var/log/stackstorm/alert-to-db.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("alert-to-db")

# ───── Constants Based on Schema Constraints ─────
MIN_RULE_LEVEL = 0
MAX_RULE_LEVEL = 15
DEDUP_WINDOW_MINUTES = 30


class AlertProcessor:
    """Encapsulates alert processing logic with proper validation and error handling"""
    
    def __init__(self, pg_dsn: str):
        self.pg_dsn = pg_dsn
        
    def compute_alert_hash(self, alert_data: Dict[str, Any]) -> Optional[str]:
        """
        Generate a consistent SHA-256 hash of alert content.
        
        This hash is used for deduplication - identical alerts will produce
        the same hash regardless of when they arrive or in what order the
        JSON keys appear.
        """
        try:
            # Create a deterministic representation by sorting items
            # This ensures the same alert always produces the same hash
            sorted_items = sorted(alert_data.items())
            alert_string = json.dumps(sorted_items)
            return hashlib.sha256(alert_string.encode('utf-8')).hexdigest()
        except Exception as e:
            log.error(f"Error computing alert hash: {e}")
            return None
    
    def validate_alert(self, alert: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate alert data against schema constraints.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check required agent fields
        agent_data = alert.get("agent", {})
        agent_id = agent_data.get("id")
        if not agent_id:
            return False, "Alert missing required field 'agent.id'"
        
        # Check required rule fields
        rule_data = alert.get("rule", {})
        rule_id = rule_data.get("id")
        rule_level = rule_data.get("level")
        
        if rule_id is None:  # Allow 0 as a valid rule_id
            return False, "Alert missing required field 'rule.id'"
        
        # Validate rule_level against schema constraint
        if rule_level is None:
            return False, "Alert missing required field 'rule.level'"
        
        try:
            rule_level_int = int(rule_level)
        except (ValueError, TypeError):
            return False, f"Rule level must be numeric, got: {rule_level}"
        
        if not (MIN_RULE_LEVEL <= rule_level_int <= MAX_RULE_LEVEL):
            return False, f"Rule level {rule_level_int} outside valid range [{MIN_RULE_LEVEL}, {MAX_RULE_LEVEL}]"
        
        return True, None
    
    def check_recent_duplicate(self, cur, alert_hash: str) -> Optional[Tuple[int, datetime]]:
        """
        Check if this alert was already processed recently.
        
        This implements our Tier 1 deduplication - we skip alerts that are
        exact duplicates of alerts received in the last 30 minutes to prevent
        alert flooding from misconfigured systems.
        """
        dedup_cutoff = datetime.now(timezone.utc) - timedelta(minutes=DEDUP_WINDOW_MINUTES)
        
        cur.execute("""
            SELECT id, ingest_timestamp 
            FROM alerts
            WHERE alert_hash = %s AND ingest_timestamp >= %s
            LIMIT 1
        """, (alert_hash, dedup_cutoff))
        
        return cur.fetchone()
    
    def ensure_agent_exists(self, cur, agent_data: Dict[str, Any]) -> None:
        """
        Create or update minimal agent record to satisfy foreign key constraint.
        
        The full agent enrichment happens later in the pipeline - we just need
        enough data here to allow the alert to be inserted.
        """
        agent_id = agent_data.get("id")
        agent_name = agent_data.get("name")
        agent_ip = agent_data.get("ip")
        
        log.debug(f"Ensuring agent '{agent_id}' exists (name={agent_name}, ip={agent_ip})")
        
        cur.execute("""
            INSERT INTO agents (id, name, ip, registered, last_seen)
            VALUES (%s, %s, %s, now(), now())
            ON CONFLICT (id) DO UPDATE
            SET name = EXCLUDED.name,
                ip = EXCLUDED.ip,
                last_seen = now()
        """, (agent_id, agent_name, agent_ip))
        
        if cur.rowcount == 1:
            log.info(f"Agent '{agent_id}' created in database")
        else:
            log.debug(f"Agent '{agent_id}' updated (last_seen refreshed)")
    
    def insert_alert(self, cur, alert: Dict[str, Any], alert_hash: str) -> Optional[Tuple[int, datetime]]:
        """
        Insert alert into database with proper deduplication handling.
        
        This implements Tier 2 deduplication using the database's UNIQUE
        constraint. If another process inserts the same alert simultaneously,
        the database will prevent duplication.
        """
        agent_id = alert.get("agent", {}).get("id")
        rule_data = alert.get("rule", {})
        rule_id = rule_data.get("id")
        rule_level = int(rule_data.get("level"))  # Already validated
        rule_desc = rule_data.get("description", "")
        
        try:
            cur.execute("""
                INSERT INTO alerts (
                    alert_hash,
                    agent_id,
                    rule_id,
                    rule_level,
                    rule_desc,
                    raw,
                    state,
                    ingest_timestamp
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (alert_hash) DO NOTHING
                RETURNING id, ingest_timestamp
            """, (
                alert_hash,
                agent_id,
                rule_id,
                rule_level,
                rule_desc,
                Json(alert),  # Use psycopg2's Json adapter for proper JSONB handling
                "new"  # Initial state - triggers pipeline processing
            ))
            
            return cur.fetchone()
            
        except psycopg2.IntegrityError as e:
            # This catches any other integrity violations beyond the hash uniqueness
            # For example, if the agent_id foreign key is somehow invalid
            log.warning(f"Integrity error inserting alert: {e}")
            raise
    
    def process_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Main processing logic for a single alert.
        
        Returns True if alert was successfully processed (either inserted or
        deduplicated), False if there was an error.
        """
        # Validate the alert first
        is_valid, error_msg = self.validate_alert(alert)
        if not is_valid:
            log.error(f"Alert validation failed: {error_msg}")
            log.debug(f"Invalid alert data: {json.dumps(alert)}")
            return False
        
        # Compute hash for deduplication
        alert_hash = self.compute_alert_hash(alert)
        if not alert_hash:
            log.error("Failed to compute alert hash")
            return False
        
        # Extract key fields for logging
        agent_id = alert.get("agent", {}).get("id")
        rule_id = alert.get("rule", {}).get("id")
        
        log.info(f"Processing alert (agent={agent_id}, rule_id={rule_id}, hash={alert_hash[:8]}...)")
        
        conn = None
        try:
            conn = psycopg2.connect(self.pg_dsn)
            with conn.cursor() as cur:
                # Tier 1: Check for recent duplicates
                existing = self.check_recent_duplicate(cur, alert_hash)
                if existing:
                    existing_id, existing_timestamp = existing
                    log.info(
                        f"Alert skipped - duplicate of alert {existing_id} "
                        f"from {existing_timestamp.isoformat()} "
                        f"(within {DEDUP_WINDOW_MINUTES} minute window)"
                    )
                    # This is not an error - deduplication is working as intended
                    return True
                
                # Ensure agent exists
                self.ensure_agent_exists(cur, alert.get("agent", {}))
                
                # Tier 2: Insert with database-level deduplication
                result = self.insert_alert(cur, alert, alert_hash)
                
                if result:
                    new_id, new_timestamp = result
                    log.info(
                        f"Alert inserted successfully - "
                        f"ID: {new_id}, "
                        f"Hash: {alert_hash[:8]}..., "
                        f"Timestamp: {new_timestamp.isoformat()}"
                    )
                    # Note: We do NOT call pg_notify here - the database trigger handles it!
                    # This prevents duplicate notifications
                else:
                    # Another process inserted this alert concurrently
                    log.info(
                        f"Alert skipped - concurrent insert detected "
                        f"(hash: {alert_hash[:8]}...)"
                    )
                
                conn.commit()
                return True
                
        except psycopg2.Error as e:
            log.error(f"Database error processing alert: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        except Exception as e:
            log.error(f"Unexpected error processing alert: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()


def main():
    """Main entry point - reads alert from stdin and processes it"""
    start_time = datetime.now(timezone.utc)
    log.info(f"=== alert-to-db.py started at {start_time.isoformat()} ===")
    
    # Read input from stdin
    raw_input = sys.stdin.read()
    if not raw_input.strip():
        log.warning("No input received on stdin - exiting gracefully")
        sys.exit(0)
    
    # Parse JSON input
    try:
        alert = json.loads(raw_input)
        log.debug(f"Received alert: {json.dumps(alert)[:500]}...")  # Log first 500 chars
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse JSON from stdin: {e}")
        log.debug(f"Raw input: {raw_input[:500]}...")
        sys.exit(1)
    
    # Process the alert
    processor = AlertProcessor(PG_DSN)
    success = processor.process_alert(alert)
    
    end_time = datetime.now(timezone.utc)
    duration_ms = (end_time - start_time).total_seconds() * 1000
    log.info(f"=== alert-to-db.py completed in {duration_ms:.1f}ms ===")
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()