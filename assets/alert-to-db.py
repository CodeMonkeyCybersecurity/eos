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

# ───── Load Environment Variables ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN = os.getenv("PG_DSN")

# ───── Set Up Logging ─────
LOG_FILE = "/var/log/stackstorm/alert-to-db.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("alert-to-db")

def compute_alert_hash(alert):
    """Generate SHA-256 hash of alert JSON string."""
    sorted_items = sorted(alert_data.items())
    alert_string = json.dumps(sorted_items)
    return hashlib.sha256(alert_string.encode('utf-8')).hexdigest()

def main():
    log.info("=== alert-to-db.py start ===")

    raw = sys.stdin.read()
    if not raw.strip():
        log.warning("No input received on stdin, exiting")
        sys.exit(0)

    try:
        alert = json.loads(raw)
    except json.JSONDecodeError:
        log.exception("Failed to parse JSON from stdin")
        sys.exit(1)

    agent = alert.get("agent", {})
    agent_id   = agent.get("id")
    agent_name = agent.get("name")
    agent_ip   = agent.get("ip")
    agent_os   = agent.get("os")  # may be None if not provided

    if not agent_id:
        log.error("Alert missing agent.id, skipping insert")
        sys.exit(1)

    alert_hash = compute_alert_hash(alert)
    log.info(f"Processing alert (agent={agent_id}, hash={alert_hash})")

    try:
        with psycopg2.connect(PG_DSN) as conn:
            with conn.cursor() as cur:
                # 1) Upsert agent into agents table (id, name, ip, os, registered / last_seen)
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
                log.info(f"Upserted agent '{agent_id}' (name={agent_name}, ip={agent_ip}, os={agent_os})")

                # 2) Check for identical alerts in the last 30 minutes
                thirty_minutes_ago = datetime.now() - timedelta(minutes=30)
                
                cur.execute("""
                    SELECT 1 FROM alerts
                    WHERE alert_hash = %s AND timestamp >= %s
                    LIMIT 1
                """, (alert_hash, thirty_minutes_ago))

                if cur.fetchone():
                    log.info(f"Skipped alert {alert_hash}: identical alert found within the last 30 minutes.")
                else:
                    # 3) Insert the alert if no identical one was found recently
                    cur.execute("""
                        INSERT INTO alerts (
                          alert_hash,
                          agent_id,
                          rule_id,
                          rule_level,
                          rule_desc,
                          raw,
                          state,
                          timestamp -- Ensure you have this column in your alerts table
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
                    log.info("Inserted new alert %s", alert_hash)

        # always print ok to stdout if no exception
        print("ok")
 
    except Exception:
        log.exception("Unexpected database error")
        sys.exit(1)

if __name__ == "__main__":
    main()