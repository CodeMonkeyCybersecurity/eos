#!/usr/bin/env python3
# /usr/local/bin/alert-to-db.py
# st2ctl reload --register-all

# stdlib
import sys
import json
import os
import hashlib
import logging
from datetime import datetime, timedelta, timezone

# ───── Third-party imports with graceful fallbacks ─────
try:
    import psycopg2  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: Missing dependency 'psycopg2-binary'. "
        "Install it with:\n\n    pip install psycopg2-binary\n\n"
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    # Provide a stub so Pylance/mypy are happy and runtime doesn’t break
    def load_dotenv(*_args, **_kwargs):  # type: ignore
        pass
    logging.warning(
        "Optional dependency 'python-dotenv' not found; "
        "continuing without loading a .env file."
    )

# ───── Load Environment Variables ─────
# (If python-dotenv is installed this loads overrides from the file;
# otherwise we rely solely on real env vars, as logged above.)
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN = os.getenv("PG_DSN")

# Abort early if the DSN is still missing
if not PG_DSN:
    sys.stderr.write(
        "ERROR: Environment variable PG_DSN is not set "
        "and no .env file supplied it.\n"
    )
    sys.exit(1)

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
    script_start_time = datetime.now(timezone.utc) # Log script start time in UTC
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
    # For OS, use the 'os' field as a dictionary and let the agents table handle its parsing
    # as the agent_enrichment_agent.py will handle the string conversion for the DB
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
        # We don't set 'os' here because the agent_enrichment_agent.py will provide a full JSON representation
        # and more detailed breakdown of OS. This initial insert is minimal for FK constraint.
        log.debug(f"Attempting to upsert agent '{agent_id}' (name={agent_name}, ip={agent_ip}) for initial record.")
        cur.execute("""
            INSERT INTO agents (id, name, ip, registered, last_seen)
            VALUES (%s, %s, %s, now(), now())
            ON CONFLICT (id) DO UPDATE
              SET name       = EXCLUDED.name,
                  ip         = EXCLUDED.ip,
                  last_seen  = now()
        """, (
            agent_id,
            agent_name,
            agent_ip
        ))
        if cur.rowcount == 1:
            log.info(f"Agent '{agent_id}' **inserted** into 'agents' table (minimal record).")
        elif cur.rowcount == 0:
            log.info(f"Agent '{agent_id}' **updated** (last_seen) in 'agents' table.")
        else:
            log.warning(f"Unexpected rowcount ({cur.rowcount}) after upserting agent '{agent_id}'. This should not happen for a single upsert.")


        # --- Deduplication Logic: Tier 1 (Python Script / Time-based) ---
        thirty_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=30) # Use UTC for comparison
        
        log.debug(f"Tier 1 Check: Looking for existing alert with hash '{alert_hash}' ingested after {thirty_minutes_ago.isoformat()}...")
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
                f"Tier 1 Result: Alert **SKIPPED by business logic**. "
                f"Reason: Identical alert (Hash: '{alert_hash}', Rule ID: '{rule_id}', Agent: '{agent_id}') "
                f"found in database (DB ID: {existing_alert_db_id}, Ingested: {existing_ingest_timestamp.isoformat()}) "
                f"within the last 30 minutes. No new insertion needed as per policy."
            )
        else:
            log.info(f"Tier 1 Result: No recent identical alert (within 30 min) found for hash '{alert_hash}'. Proceeding to Tier 2 (Database Insert).")
            new_alert_db_id = None # Initialize to None

            try:
                # --- Deduplication Logic: Tier 2 (Database Constraint / Race Condition Handler) ---
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
                    json.dumps(alert),
                    "new" # Initial state for new alerts
                ))
                new_alert_data = cur.fetchone() # Fetch the returned values

                if new_alert_data:
                    new_alert_db_id, new_ingest_timestamp = new_alert_data
                    log.info(
                        f"Tier 2 Result: Alert **inserted successfully**. "
                        f"DB ID: {new_alert_db_id}, "
                        f"Agent ID: '{agent_id}', "
                        f"Rule ID: '{rule_id}', "
                        f"Alert Hash: '{alert_hash}', "
                        f"Ingest Timestamp: {new_ingest_timestamp.isoformat()}."
                    )
                    # --- ADDED: pg_notify for 'new_alert' channel ---
                    try:
                        cur.execute("SELECT pg_notify('new_alert', %s);", (str(new_alert_db_id),))
                        # The conn.commit() below will also commit this notification
                        log.info(f"Queued pg_notify('new_alert', {new_alert_db_id}) for alert-enrichment-agent.py.")
                    except Exception as notify_err:
                        log.error(f"Failed to queue pg_notify for alert ID {new_alert_db_id}: {notify_err}", exc_info=True)
                        # Don't rollback the main alert insertion if notification fails, just log.
                    # --- END ADDED ---
                else:
                    # This branch is taken if ON CONFLICT DO NOTHING happened (i.e., a concurrent insert won the race)
                    log.info(
                        f"Tier 2 Result: Alert **skipped due to database integrity constraint** (Hash: '{alert_hash}'). "
                        f"Reason: Another process concurrently inserted this exact alert (same hash) into the DB "
                        f"before this script's transaction could commit. No new insertion needed."
                    )
                    # Re-query to get the DB ID of the winning alert for debug logging
                    cur.execute("""
                        SELECT id, ingest_timestamp FROM alerts
                        WHERE alert_hash = %s
                        LIMIT 1
                    """, (alert_hash,)) # Removed timestamp filter here, as we know it's in the DB now.
                    existing_alert_recheck = cur.fetchone()
                    if existing_alert_recheck:
                        log.debug(f"Confirmed existing alert DB ID: {existing_alert_recheck[0]}, Ingested: {existing_alert_recheck[1].isoformat()} (from concurrent insert).")
                        # If a concurrent insert occurred, get its ID to potentially notify if the process chain allows for existing IDs
                        new_alert_db_id = existing_alert_recheck[0] # Set new_alert_db_id to the existing one

            # The psycopg2.IntegrityError exception block will now rarely, if ever, be hit for unique constraint violations
            # because ON CONFLICT handles it. It might still be useful for other types of integrity errors.
            except psycopg2.IntegrityError as e:
                conn.rollback() # Rollback the transaction
                log.warning(
                    f"Tier 2 Error: Alert **skipped due to other database integrity error** (Hash: '{alert_hash}', Rule ID: '{rule_id}'). "
                    f"Reason: Not a unique constraint violation, but potentially a foreign key or check constraint issue. Error: {e}"
                )
            except Exception as e:
                conn.rollback() # Rollback the transaction
                log.error(
                    f"Tier 2 Critical Error: **Unhandled exception during alert insertion** (hash: '{alert_hash}', agent: '{agent_id}', rule: '{rule_id}'): {e}",
                    exc_info=True
                )
                sys.exit(1)

        conn.commit() # Commit the main transaction (including the notification)
        # Removed print("ok")

    except psycopg2.Error as e:
        log.error(f"**Database connection or transaction error occurred**: {e}", exc_info=True)
        if conn:
            conn.rollback()
        sys.exit(1)
    except Exception as e:
        log.error(f"**An unexpected non-database error occurred during main execution**: {e}", exc_info=True)
        if conn:
            conn.rollback()
        sys.exit(1)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
        log.info(f"=== alert-to-db.py end at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} ===") # Use UTC for end time

if __name__ == "__main__":
    main()
