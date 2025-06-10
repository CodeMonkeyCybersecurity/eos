#!/usr/bin/env python3
# /usr/local/bin/alert-to-db.py
# st2ctl reload --register-all

import sys
import json
import os
import psycopg2
import hashlib
import logging
from dotenv import load_dotenv
from datetime import datetime, timedelta # Import datetime and timedelta

# ───── Load Environment Variables ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN = os.getenv("PG_DSN")

# ───── Set Up Logging ─────
LOG_FILE = "/var/log/stackstorm/alert-to-db.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO, # Changed to INFO to capture all operational messages
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("alert-to-db")

def compute_alert_hash(alert_data):
    """Generate SHA-256 hash of alert JSON string."""
    try:
        # Sort items to ensure consistent hash regardless of key order
        sorted_items = sorted(alert_data.items())
        alert_string = json.dumps(sorted_items)
        return hashlib.sha256(alert_string.encode('utf-8')).hexdigest()
    except Exception as e:
        log.error(f"Error computing alert hash: {e}")
        return None # Return None on error

def main():
    log.info("=== alert-to-db.py start ===")

    raw_input = sys.stdin.read() # Use a different variable name to avoid shadowing
    if not raw_input.strip():
        log.warning("No input received on stdin. Exiting gracefully.")
        sys.exit(0)

    try:
        alert = json.loads(raw_input)
        # Log the full raw alert for debugging if needed (at DEBUG level)
        log.debug(f"Received raw alert: {json.dumps(alert, indent=2)}") 
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse JSON from stdin: {e}. Raw input: {raw_input[:200]}...") # Log snippet of raw input
        sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred during JSON parsing: {e}. Raw input: {raw_input[:200]}...")
        sys.exit(1)

    agent = alert.get("agent", {})
    agent_id   = agent.get("id")
    agent_name = agent.get("name")
    agent_ip   = agent.get("ip")
    agent_os   = agent.get("os")

    if not agent_id:
        log.error(f"Alert missing 'agent.id'. Cannot process alert. Alert details: {json.dumps(alert.get('rule', {}))}")
        sys.exit(1)

    alert_hash = compute_alert_hash(alert)
    if alert_hash is None:
        log.error(f"Failed to compute alert hash for agent ID '{agent_id}'. Skipping alert insertion.")
        sys.exit(1)

    log.info(f"Processing alert (agent={agent_id}, rule_id={alert.get('rule', {}).get('id')}, hash={alert_hash})")

    conn = None # Initialize conn to None for proper cleanup in finally block
    cur = None  # Initialize cur to None

    try:
        conn = psycopg2.connect(PG_DSN)
        cur = conn.cursor()

        # 1) Upsert agent into agents table
        log.debug(f"Attempting to upsert agent '{agent_id}' (name={agent_name}, ip={agent_ip}, os={agent_os})")
        cur.execute("""
            INSERT INTO agents (id, name, ip, os, registered)
            VALUES (%s, %s, %s, %s, now())
            ON CONFLICT (id) DO UPDATE
              SET name       = EXCLUDED.name,
                  ip         = EXCLUDED.ip,
                  os         = EXCLUDED.os,
                  last_seen  = now()
        """, (
            agent_id,
            agent_name,
            agent_ip,
            agent_os
        ))
        # Check rowcount to see if it was an INSERT or UPDATE
        if cur.rowcount == 1:
            log.info(f"Agent '{agent_id}' **inserted** into 'agents' table.")
        elif cur.rowcount == 0:
            log.info(f"Agent '{agent_id}' **updated** (last_seen) in 'agents' table.")
        else:
            log.warning(f"Unexpected rowcount ({cur.rowcount}) after upserting agent '{agent_id}'.")


        # 2) Check for identical alerts in the last 30 minutes
        thirty_minutes_ago = datetime.now() - timedelta(minutes=30)
        
        log.debug(f"Checking for existing alert_hash '{alert_hash}' created after {thirty_minutes_ago}...")
        cur.execute("""
            SELECT timestamp FROM alerts
            WHERE alert_hash = %s AND timestamp >= %s
            LIMIT 1
        """, (alert_hash, thirty_minutes_ago))

        existing_alert = cur.fetchone()

        if existing_alert:
            existing_timestamp = existing_alert[0]
            log.info(f"Alert **skipped**: Identical alert (hash={alert_hash}) found recently (timestamp={existing_timestamp}).")
        else:
            # 3) Insert the alert if no identical one was found recently
            log.debug(f"No recent identical alert found for hash '{alert_hash}'. Attempting to insert new alert.")
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
                      timestamp
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, now())
                """, (
                    alert_hash,
                    agent_id,
                    alert.get("rule", {}).get("id"),
                    alert.get("rule", {}).get("level"),
                    alert.get("rule", {}).get("description"),
                    json.dumps(alert),
                    "new"
                ))
                if cur.rowcount == 1:
                    log.info(f"Alert **inserted successfully** with hash: {alert_hash} for agent '{agent_id}'.")
                else:
                    log.warning(f"Alert insertion for hash {alert_hash} returned {cur.rowcount} rows affected, expected 1. Check for possible issues.")
            except psycopg2.IntegrityError as e:
                # This could happen if a race condition allows two identical alerts to try inserting
                # and the unique constraint on alert_hash (if it exists) kicks in here.
                conn.rollback() # Rollback the transaction on integrity error
                log.warning(f"Alert **skipped due to integrity error** (e.g., race condition duplicate insert) for hash {alert_hash}: {e}")
            except Exception as e:
                conn.rollback() # Rollback on any other insertion error
                log.error(f"Error inserting alert {alert_hash} for agent '{agent_id}': {e}", exc_info=True)
                sys.exit(1)

        conn.commit() # Commit changes if all operations within the try block succeed
        print("ok") # Always print ok to stdout if no unhandled exception occurred

    except psycopg2.Error as e:
        log.error(f"Database error occurred: {e}", exc_info=True)
        if conn:
            conn.rollback() # Ensure rollback on database errors
        sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred during database operations: {e}", exc_info=True)
        if conn:
            conn.rollback() # Ensure rollback for unexpected errors too
        sys.exit(1)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
        log.info("=== alert-to-db.py end ===")

if __name__ == "__main__":
    main()