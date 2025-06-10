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
from datetime import datetime, timedelta

# ───── Load Environment Variables ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN = os.getenv("PG_DSN")

# ───── Set Up Logging ─────
LOG_FILE = "/var/log/stackstorm/alert-to-db.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO, # Capture all operational messages
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("alert-to-db")

def compute_alert_hash(alert_data):
    """Generate SHA-256 hash of alert JSON string."""
    try:
        # Sort items to ensure consistent hash regardless of key order
        # Exclude 'id' and 'ingest_timestamp' if they were accidentally included in the raw alert
        # as they would change the hash on retries/updates, but generally raw data shouldn't have them.
        # This function should hash the *alert content itself*, not database-assigned metadata.
        sorted_items = sorted(alert_data.items())
        alert_string = json.dumps(sorted_items)
        return hashlib.sha256(alert_string.encode('utf-8')).hexdigest()
    except Exception as e:
        log.error(f"Error computing alert hash: {e}")
        return None # Return None on error

def main():
    script_start_time = datetime.now() # Log script start time
    log.info(f"=== alert-to-db.py start at {script_start_time.strftime('%Y-%m-%d %H:%M:%S')} ===")

    raw_input = sys.stdin.read()
    if not raw_input.strip():
        log.warning("No input received on stdin. Exiting gracefully.")
        sys.exit(0)

    try:
        alert = json.loads(raw_input)
        log.debug(f"Received raw alert: {json.dumps(alert, indent=2)}") 
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse JSON from stdin: {e}. Raw input snippet: {raw_input[:500]}...")
        sys.exit(1)
    except Exception as e:
        log.error(f"An unexpected error occurred during JSON parsing: {e}. Raw input snippet: {raw_input[:500]}...")
        sys.exit(1)

    agent = alert.get("agent", {})
    agent_id   = agent.get("id")
    agent_name = agent.get("name")
    agent_ip   = agent.get("ip")
    agent_os   = agent.get("os")

    rule_id = alert.get("rule", {}).get("id")
    rule_level = alert.get("rule", {}).get("level")
    rule_desc = alert.get("rule", {}).get("description")

    if not agent_id:
        log.error(f"Alert missing 'agent.id'. Cannot process alert. Rule details: {json.dumps(alert.get('rule', {}))}")
        sys.exit(1)
    
    if not rule_id:
        log.warning(f"Alert for agent '{agent_id}' is missing 'rule.id'. This alert might be harder to trace.")

    alert_hash = compute_alert_hash(alert)
    if alert_hash is None:
        log.error(f"Failed to compute alert hash for agent ID '{agent_id}'. Skipping alert insertion.")
        sys.exit(1)

    log.info(f"Processing alert (agent={agent_id}, rule_id={rule_id}, hash={alert_hash})")

    conn = None
    cur = None

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
        if cur.rowcount == 1:
            log.info(f"Agent '{agent_id}' **inserted** into 'agents' table.")
        elif cur.rowcount == 0:
            log.info(f"Agent '{agent_id}' **updated** (last_seen) in 'agents' table.")
        else:
            log.warning(f"Unexpected rowcount ({cur.rowcount}) after upserting agent '{agent_id}'. This should not happen for a single upsert.")


        # 2) Check for identical alerts in the last 30 minutes using 'ingest_timestamp'
        thirty_minutes_ago = datetime.now() - timedelta(minutes=30)
        
        log.debug(f"Checking for existing alert with hash '{alert_hash}' ingested after {thirty_minutes_ago}...")
        cur.execute("""
            SELECT id, ingest_timestamp FROM alerts
            WHERE alert_hash = %s AND ingest_timestamp >= %s
            LIMIT 1
        """, (alert_hash, thirty_minutes_ago))

        existing_alert = cur.fetchone()

        if existing_alert:
            existing_alert_db_id = existing_alert[0]
            existing_ingest_timestamp = existing_alert[1]
            log.info(
                f"Alert **skipped**: Identical alert (hash={alert_hash}, rule_id={rule_id}) found recently "
                f"(DB ID: {existing_alert_db_id}, Ingested: {existing_ingest_timestamp}). "
                f"Less than 30 minutes since last occurrence."
            )
        else:
            # 3) Insert the alert if no identical one was found recently
            log.info(f"No recent identical alert found for hash '{alert_hash}'. Attempting to insert new alert.")
            try:
                # Use RETURNING clause to get the ID and ingest_timestamp of the newly inserted row
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
                    RETURNING id, ingest_timestamp
                """, (
                    alert_hash,
                    agent_id,
                    rule_id,
                    rule_level,
                    rule_desc,
                    json.dumps(alert),
                    "new"
                ))
                new_alert_data = cur.fetchone() # Fetch the returned values

                if new_alert_data:
                    new_alert_db_id, new_ingest_timestamp = new_alert_data
                    log.info(
                        f"Alert **inserted successfully**. "
                        f"DB ID: {new_alert_db_id}, "
                        f"Agent ID: '{agent_id}', "
                        f"Rule ID: '{rule_id}', "
                        f"Alert Hash: '{alert_hash}', "
                        f"Ingest Timestamp: {new_ingest_timestamp}."
                    )
                else:
                    log.warning(f"Alert insertion for hash {alert_hash} returned no data despite success. This is unexpected.")
            except psycopg2.IntegrityError as e:
                conn.rollback() 
                log.warning(
                    f"Alert **skipped due to database integrity error** (e.g., unique constraint violation, race condition). "
                    f"Hash: {alert_hash}, Rule ID: {rule_id}, Error: {e}"
                )
            except Exception as e:
                conn.rollback() 
                log.error(
                    f"**Critical error inserting alert** (hash: {alert_hash}, agent: '{agent_id}', rule: {rule_id}): {e}", 
                    exc_info=True
                )
                sys.exit(1)

        conn.commit()
        print("ok") 

    except psycopg2.Error as e:
        log.error(f"**Database error occurred**: {e}", exc_info=True)
        if conn:
            conn.rollback()
        sys.exit(1)
    except Exception as e:
        log.error(f"**An unexpected non-database error occurred**: {e}", exc_info=True)
        if conn:
            conn.rollback()
        sys.exit(1)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
        log.info(f"=== alert-to-db.py end at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")

if __name__ == "__main__":
    main()