#!/usr/bin/env python3
# /usr/local/bin/llm-worker.py
# 750 stanley:stanley

"""
Wazuh Alert LLM Worker – Azure-native, REST-only, real-time with backlog drain + NOTIFY+POLL
Enhanced with verbose debug logging to provide deep insight into operations, including LLM token usage.
"""

import os, select, json, psycopg2, time, requests, hashlib, traceback
from datetime import datetime
from dotenv import load_dotenv

# ───── Load Environment Variables ─────
load_dotenv("/opt/stackstorm/packs/delphi/.env")
PG_DSN         = os.getenv("PG_DSN")
API_KEY        = os.getenv("AZURE_OPENAI_API_KEY")
ENDPOINT       = os.getenv("ENDPOINT_URL")
DEPLOYMENT     = os.getenv("DEPLOYMENT_NAME")
API_VERSION    = os.getenv("AZURE_API_VERSION")

PROMPT_FILE    = os.getenv("PROMPT_FILE", "/opt/system-prompt.txt")
LOG_FILE       = os.getenv("LOG_FILE", "/var/log/stackstorm/llm-worker.log")
HEARTBEAT_FILE = os.getenv("HEARTBEAT_FILE", "/var/log/stackstorm/llm-worker.heartbeat")
MAX_LOG_SIZE   = int(os.getenv("MAX_LOG_SIZE", 10 * 1024 * 1024))

# ───── Logging setup ─────
import logging

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO, # Default to INFO, change to logging.DEBUG for maximum verbosity
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("llm-worker")

def update_heartbeat():
    """Updates the heartbeat file to indicate the worker is alive."""
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(int(time.time())))
        log.debug("Heartbeat file updated successfully.")
    except Exception as e:
        log.error(f"Heartbeat update failed: {e}", exc_info=True)

def load_system_prompt():
    """Loads the system prompt from the configured file."""
    log.info(f"Loading system prompt from {PROMPT_FILE!r}")
    if not os.path.exists(PROMPT_FILE):
        log.critical(f"ERROR: System prompt file missing at {PROMPT_FILE!r}. Exiting.")
        exit(2) # Critical exit as prompt is essential
    txt = open(PROMPT_FILE).read().strip()
    if not txt:
        log.critical(f"ERROR: System prompt file at {PROMPT_FILE!r} is empty. Exiting.")
        exit(2) # Critical exit as prompt is essential
    log.info(f"Loaded system prompt ({len(txt)} chars).")
    return txt

def azure_chat(system_prompt, alert_id, alert_raw_json, alert_hash, rule_id, retries=3):
    """
    Calls the Azure OpenAI API to get a response for an alert.
    Includes verbose logging for each step, attempt, and potential failure, and token usage.
    Returns: prompt_text, prompt_sent_at, response_text, resp_received_at, prompt_tokens, completion_tokens, total_tokens
    """
    log.debug(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): Preparing for Azure API call.")
    url = f"{ENDPOINT}/openai/deployments/{DEPLOYMENT}/chat/completions?api-version={API_VERSION}"
    headers = {"Content-Type":"application/json", "api-key":API_KEY}
    
    user_payload = json.dumps(alert_raw_json) if isinstance(alert_raw_json, dict) else alert_raw_json

    prompt = (
        system_prompt
        + "\n\nPlease explain what happened, what to do, and how to check for a non-technical user in one paragraph:\n\n"
        + user_payload
    )
    prompt_hash = hashlib.sha1(prompt.encode()).hexdigest()
    log.info(f"Alert {alert_id} (Rule: {rule_id}): Preparing LLM prompt (Prompt Hash: {prompt_hash}, Length: {len(prompt)} chars).")
    
    body = {
        "messages": [
            {"role":"system","content":system_prompt},
            {"role":"user","content":prompt}
        ],
        "max_tokens":800,
        "temperature":1.0,
        "top_p":1.0
    }

    # Initialize token metrics
    prompt_tokens = None
    completion_tokens = None
    total_tokens = None

    for attempt in range(1, retries+1):
        try:
            log.info(f"Alert {alert_id} (Rule: {rule_id}): HTTP POST to Azure endpoint (Attempt {attempt}/{retries}). URL: {url}")
            start = time.time()
            r = requests.post(url, headers=headers, json=body, timeout=45)
            response_time = time.time() - start
            log.info(f"Alert {alert_id} (Rule: {rule_id}): HTTP status={r.status_code} (Time: {response_time:.2f}s).")
            
            r.raise_for_status()

            response_json = r.json()
            resp = response_json["choices"][0]["message"]["content"].strip()
            
            # Extract token usage
            if "usage" in response_json:
                usage = response_json["usage"]
                prompt_tokens = usage.get("prompt_tokens")
                completion_tokens = usage.get("completion_tokens")
                total_tokens = usage.get("total_tokens")
                log.info(
                    f"Alert {alert_id} (Rule: {rule_id}): LLM Token Usage: "
                    f"Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}."
                )
            else:
                log.warning(f"Alert {alert_id} (Rule: {rule_id}): 'usage' field not found in Azure API response.")

            log.info(f"Alert {alert_id} (Rule: {rule_id}): Successfully received {len(resp)} chars response from Azure.")
            return prompt, datetime.utcnow(), resp, datetime.utcnow(), prompt_tokens, completion_tokens, total_tokens
        
        except requests.exceptions.RequestException as e:
            log.error(f"Alert {alert_id} (Rule: {rule_id}): Azure API Request Error on attempt #{attempt}: {e}")
            log.debug(f"Full traceback for Alert {alert_id} request error:\n{traceback.format_exc()}")
            if attempt < retries:
                sleep_for = 5 * attempt
                log.warning(f"Alert {alert_id} (Rule: {rule_id}): Retrying Azure API call after {sleep_for}s...")
                time.sleep(sleep_for)
            else:
                log.error(f"Alert {alert_id} (Rule: {rule_id}): All {retries} Azure API retries failed. Propagating error.")
                raise
        except json.JSONDecodeError as e:
            log.error(f"Alert {alert_id} (Rule: {rule_id}): Failed to parse JSON response from Azure on attempt #{attempt}: {e}. Response content: {r.text[:500]}...")
            log.debug(f"Full traceback for Alert {alert_id} JSON decode error:\n{traceback.format_exc()}")
            if attempt < retries:
                sleep_for = 5 * attempt
                log.warning(f"Alert {alert_id} (Rule: {rule_id}): Retrying after {sleep_for}s...")
                time.sleep(sleep_for)
            else:
                log.error(f"Alert {alert_id} (Rule: {rule_id}): All {retries} retries failed due to JSON decode error. Propagating error.")
                raise
        except Exception as e:
            log.error(f"Alert {alert_id} (Rule: {rule_id}): Unexpected error during Azure API call on attempt #{attempt}: {e}")
            log.debug(f"Full traceback for Alert {alert_id} unexpected error:\n{traceback.format_exc()}")
            if attempt < retries:
                sleep_for = 5 * attempt
                log.warning(f"Alert {alert_id} (Rule: {rule_id}): Retrying after {sleep_for}s...")
                time.sleep(sleep_for)
            else:
                log.error(f"Alert {alert_id} (Rule: {rule_id}): All {retries} retries failed due to unexpected error. Propagating error.")
                raise

def process_alerts(conn, system_prompt, batch_size=5):
    """
    Fetches and processes a batch of new alerts.
    Includes verbose logging for fetching, parsing, LLM calls, and DB updates.
    """
    processed_count = 0
    with conn.cursor() as curs:
        log.info(f"Attempting to fetch up to {batch_size} new alerts (state='new').")
        try:
            curs.execute("""
                SELECT id, raw, alert_hash, rule_id
                  FROM alerts
                 WHERE state = 'new'
                 ORDER BY ingest_timestamp
                 LIMIT %s
                 FOR UPDATE SKIP LOCKED
            """, (batch_size,))
            rows = curs.fetchall()
            ids_fetched = [r[0] for r in rows]
            log.info(f"Fetched {len(rows)} new alerts. IDs: {ids_fetched!r}")
            if not rows:
                return 0 # No new alerts to process

        except psycopg2.Error as e:
            log.error(f"Database error during alert fetch: {e}", exc_info=True)
            conn.rollback()
            return 0
        except Exception as e:
            log.error(f"Unexpected error during alert fetch: {e}", exc_info=True)
            return 0

        for alert_id, raw_alert_data, alert_hash, rule_id in rows:
            log.info(f"--- Processing Alert DB ID: {alert_id} (Hash: {alert_hash}, Rule: {rule_id}) ---")
            
            alert_json = None
            try:
                alert_json = raw_alert_data if isinstance(raw_alert_data, dict) else json.loads(raw_alert_data)
                log.debug(f"Alert {alert_id}: Successfully parsed raw JSON data.")
            except json.JSONDecodeError as e:
                log.error(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): JSON parse error on raw data: {e}. Raw data snippet: {str(raw_alert_data)[:500]}...")
                log.debug(f"Full traceback for Alert {alert_id} JSON parse error:\n{traceback.format_exc()}")
                try:
                    curs.execute("UPDATE alerts SET state = 'parsing_failed' WHERE id = %s", (alert_id,))
                    conn.commit()
                    log.warning(f"Alert {alert_id}: Marked as 'parsing_failed' due to JSON error.")
                except psycopg2.Error as db_e:
                    log.critical(f"Alert {alert_id}: Failed to mark as 'parsing_failed' after JSON error: {db_e}. Data might be stuck. Rolling back current transaction.")
                    conn.rollback()
                continue

            if alert_json is None:
                log.error(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): 'raw' alert data was null or invalid after parsing. Skipping LLM call.")
                continue

            # Modified call to azure_chat to receive token metrics
            prompt_text, prompt_sent_at, resp_text, resp_received_at, prompt_tokens, completion_tokens, total_tokens = \
                (None,) * 7 # Initialize all return values

            try:
                prompt_text, prompt_sent_at, resp_text, resp_received_at, prompt_tokens, completion_tokens, total_tokens = \
                    azure_chat(system_prompt, alert_id, alert_json, alert_hash, rule_id)
            except Exception as e:
                log.error(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): LLM API call failed completely: {e}. Skipping DB update for this alert.")
                try:
                    curs.execute("UPDATE alerts SET state = 'llm_failed' WHERE id = %s", (alert_id,))
                    conn.commit()
                    log.warning(f"Alert {alert_id}: Marked as 'llm_failed' due to LLM processing error.")
                except psycopg2.Error as db_e:
                    log.critical(f"Alert {alert_id}: Failed to mark as 'llm_failed' after LLM error: {db_e}. Data might be stuck. Rolling back current transaction.")
                    conn.rollback()
                continue

            try:
                log.debug(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): Initiating DB transaction for update.")
                
                curs.execute("BEGIN")
                curs.execute("""
                    UPDATE alerts
                       SET prompt_sent_at       = %s,
                           prompt_text          = %s,
                           response_received_at = %s,
                           response_text        = %s,
                           prompt_tokens        = %s,
                           completion_tokens    = %s,
                           total_tokens         = %s,
                           state                = 'summarized'
                     WHERE id = %s
                """, (prompt_sent_at, prompt_text, resp_received_at, resp_text,
                      prompt_tokens, completion_tokens, total_tokens, # New parameters
                      alert_id))
                
                if curs.rowcount == 1:
                    log.info(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): Successfully updated DB. State set to 'summarized'.")
                    log.info(f"Alert {alert_id}: Token usage stored - Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}.")
                    curs.execute("COMMIT")
                    processed_count += 1
                else:
                    log.warning(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): DB UPDATE affected {curs.rowcount} rows, expected 1. Rolling back.")
                    curs.execute("ROLLBACK")
                    try:
                        curs.execute("UPDATE alerts SET state = 'update_failed_unexpected_rowcount' WHERE id = %s", (alert_id,))
                        conn.commit()
                        log.warning(f"Alert {alert_id}: Marked as 'update_failed_unexpected_rowcount'.")
                    except psycopg2.Error as db_e:
                        log.critical(f"Alert {alert_id}: Failed to mark as 'update_failed_unexpected_rowcount': {db_e}. Rolling back current transaction.")
                        conn.rollback()

            except psycopg2.Error as e:
                log.error(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): Database update failed (psycopg2.Error): {e}")
                log.debug(f"Full traceback for Alert {alert_id} DB update error:\n{traceback.format_exc()}")
                try:
                    curs.execute("ROLLBACK")
                    log.warning(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): DB transaction rolled back due to error.")
                    curs.execute("UPDATE alerts SET state = 'db_update_failed' WHERE id = %s", (alert_id,))
                    conn.commit()
                    log.warning(f"Alert {alert_id}: Marked as 'db_update_failed'.")
                except psycopg2.Error as db_e:
                    log.critical(f"Alert {alert_id}: Failed to mark as 'db_update_failed' after DB error: {db_e}. Data might be stuck. Rolling back current transaction.")
                    conn.rollback()
                except Exception as ex:
                    log.critical(f"Alert {alert_id}: FATAL: Exception during rollback or marking as failed: {ex}", exc_info=True)
                    conn.rollback()

            except Exception as e:
                log.error(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): Unexpected error during DB update: {e}")
                log.debug(f"Full traceback for Alert {alert_id} unexpected DB update error:\n{traceback.format_exc()}")
                try:
                    curs.execute("ROLLBACK")
                    log.warning(f"Alert {alert_id} (Hash: {alert_hash}, Rule: {rule_id}): DB transaction rolled back due to unexpected error.")
                    curs.execute("UPDATE alerts SET state = 'unexpected_update_failed' WHERE id = %s", (alert_id,))
                    conn.commit()
                    log.warning(f"Alert {alert_id}: Marked as 'unexpected_update_failed'.")
                except psycopg2.Error as db_e:
                    log.critical(f"Alert {alert_id}: Failed to mark as 'unexpected_update_failed' after unexpected error: {db_e}. Data might be stuck. Rolling back current transaction.")
                    conn.rollback()
                except Exception as ex:
                    log.critical(f"Alert {alert_id}: FATAL: Exception during rollback or marking as failed: {ex}", exc_info=True)
                    conn.rollback()

        return processed_count

def main():
    log.info(f"--- LLM Worker Script Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---")
    
    system_prompt_content = load_system_prompt()
    if not system_prompt_content:
        log.critical("System prompt is empty or failed to load. Exiting.")
        exit(2)

    conn = None
    try:
        conn = psycopg2.connect(PG_DSN)
        log.info("Successfully connected to PostgreSQL database.")
    except psycopg2.Error as e:
        log.critical(f"FATAL: Database connection failed: {e}", exc_info=True)
        exit(1)
    except Exception as e:
        log.critical(f"FATAL: An unexpected error occurred during database connection: {e}", exc_info=True)
        exit(1)

    log.info("Initiating initial backlog drain...")
    drained_count = process_alerts(conn, system_prompt_content, batch_size=1000)
    log.info(f"Initial backlog drain complete: {drained_count} alerts processed.")

    try:
        with conn.cursor() as curs:
            curs.execute("LISTEN new_alert;")
            log.info("Listening for 'new_alert' notifications from PostgreSQL.")
    except psycopg2.Error as e:
        log.critical(f"FATAL: Failed to establish LISTEN on 'new_alert': {e}", exc_info=True)
        conn.close()
        exit(1)
    except Exception as e:
        log.critical(f"FATAL: Unexpected error while setting up LISTEN: {e}", exc_info=True)
        conn.close()
        exit(1)


    while True:
        update_heartbeat()
        log.info("Waiting for NOTIFY or timeout (30 seconds)...")
        try:
            r,_,_ = select.select([conn], [], [], 30)
            if r:
                conn.poll()
                notifies = [n.payload for n in conn.notifies]
                log.info(f"Woke on NOTIFY. Payloads received: {notifies!r}. Clearing notifications.")
                conn.notifies.clear()
            else:
                log.info("Notify timeout reached. Falling back to manual poll to check for new alerts.")

            alerts_processed_this_cycle = process_alerts(conn, system_prompt_content, batch_size=5)
            log.info(f"Cycle complete: {alerts_processed_this_cycle} alerts processed.")

        except psycopg2.Error as e:
            log.error(f"Database error during main loop (LISTEN/POLL/process_alerts): {e}. Attempting to reconnect...", exc_info=True)
            if conn:
                try:
                    conn.close()
                    log.info("Closed broken DB connection.")
                except Exception as close_e:
                    log.error(f"Error closing broken DB connection: {close_e}")
            
            for i in range(5):
                log.info(f"Attempting to reconnect to DB (attempt {i+1}/5)...")
                time.sleep(5)
                try:
                    conn = psycopg2.connect(PG_DSN)
                    with conn.cursor() as curs: # Re-listen after reconnect
                        curs.execute("LISTEN new_alert;")
                    log.info("Successfully reconnected and re-established LISTEN.")
                    break
                except psycopg2.Error as reconnect_e:
                    log.error(f"Reconnect attempt failed: {reconnect_e}")
                except Exception as reconnect_e:
                    log.error(f"Unexpected error during reconnect: {reconnect_e}")
            else:
                log.critical("FATAL: Failed to reconnect to database after multiple attempts. Exiting.")
                exit(1)
            
        except Exception as e:
            log.critical(f"FATAL: An unexpected error occurred in the main loop: {e}", exc_info=True)
            if conn:
                conn.close()
            exit(1)

if __name__ == "__main__":
    main()