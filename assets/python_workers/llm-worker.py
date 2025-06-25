#!/usr/bin/env python3
# /usr/local/bin/llm-worker.py
# stanley:stanley 0750

import os
import sys
import json
import time
import logging
from logging.handlers import RotatingFileHandler
try:
    import requests # type: ignore # For interacting with Azure OpenAI API
except ImportError:
    requests = None

try:
    import psycopg2 # type: ignore
    from psycopg2.extras import DictCursor # type: ignore
except ImportError:
    psycopg2 = None
    DictCursor = None
from datetime import datetime, timezone

# --- Import sdnotify for Systemd Watchdog Integration ---
import sdnotify # ADDED: Import sdnotify

# Handle dotenv import gracefully
try:
    from dotenv import load_dotenv # type: ignore
except ImportError:
    load_dotenv = None

from typing import Union

# --- Configuration & Environment Variable Validation ---

# Load environment variables from a single .env file.
# This file should contain ALL necessary variables.
if load_dotenv is not None:
    load_dotenv("/opt/stackstorm/packs/delphi/.env")

# PostgreSQL Database Connection String (DSN)
PG_DSN = os.getenv("PG_DSN")
if not PG_DSN:
    raise ValueError("PG_DSN environment variable not set. Please configure your PostgreSQL DSN in the .env file.")

# Azure OpenAI API details
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY")
ENDPOINT_URL = os.getenv("ENDPOINT_URL")
DEPLOYMENT_NAME = os.getenv("DEPLOYMENT_NAME")
AZURE_API_VERSION = os.getenv("AZURE_API_VERSION")

if not all([AZURE_OPENAI_API_KEY, ENDPOINT_URL, DEPLOYMENT_NAME, AZURE_API_VERSION]):
    raise ValueError("One or more Azure OpenAI environment variables (AZURE_OPENAI_API_KEY, ENDPOINT_URL, DEPLOYMENT_NAME, AZURE_API_VERSION) not set.")

# Paths & Quotas
PROMPT_FILE = os.environ.get("PROMPT_FILE", "/srv/eos/system-prompts/default.txt")
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/stackstorm/llm-worker.log") # Ensure this is correct
# HEARTBEAT_FILE = os.environ.get("HEARTBEAT_FILE", "/var/log/stackstorm/llm-worker.heartbeat") # REMOVED: No longer needed with sdnotify
MAX_LOG_SIZE = int(os.environ.get("MAX_LOG_SIZE", 10485760)) # Default 10 MB

# PostgreSQL LISTEN channel for enriched alerts
LISTEN_CHANNEL = "agent_enriched"  # Listen for alerts with enriched agent data
NOTIFY_CHANNEL = "new_response"    # Notify when LLM response is ready

# --- Logger Setup ---
def setup_logging() -> logging.Logger:
    """Configure a rotating file logger and return it."""
    logger = logging.getLogger("delphi-llm-worker") # Renamed logger for clarity
    logger.setLevel(logging.INFO) # Set to INFO for production, DEBUG for development

    log_dir = os.path.dirname(LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)

    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=MAX_LOG_SIZE,
        backupCount=3
    )
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    logger.info("Logger initialized; script starting.")
    return logger

log = setup_logging()

# --- Initialize Systemd Notifier ---
notifier = sdnotify.SystemdNotifier() # ADDED: Initialize sdnotify notifier

# --- Heartbeat File Management (REMOVED or adapted if needed elsewhere) ---
# Removed update_heartbeat_file function and its calls from the main loop
# as sdnotify will handle this.

# --- Load System Prompt ---
def load_system_prompt(file_path: str) -> str:
    """Loads the system prompt from a file."""
    try:
        with open(file_path, 'r') as f:
            prompt = f.read().strip()
            log.info(f"System prompt loaded from {file_path}")
            return prompt
    except FileNotFoundError:
        log.critical(f"System prompt file not found at {file_path}. Please ensure it exists.")
        notifier.notify("STATUS=System prompt file not found. Exiting.") # ADDED: sdnotify on critical error
        notifier.notify("STOPPING=1")
        sys.exit(1)
    except Exception as e:
        log.critical(f"Error loading system prompt from {file_path}: {e}")
        notifier.notify("STATUS=Error loading system prompt. Exiting.") # ADDED: sdnotify on critical error
        notifier.notify("STOPPING=1")
        sys.exit(1)

SYSTEM_PROMPT_CONTENT = load_system_prompt(PROMPT_FILE)

# --- LLM Interaction Function ---
def get_llm_response(raw_alert_json: dict, agent_details_json: dict) -> Union[dict, None]:
    """
    Sends the raw alert and agent details to the LLM and returns its response.
    Returns:
        dict: A dictionary containing the raw text response from the LLM,
              and token usage, or None on failure.
    """
    if requests is None:
        log.error("requests module not available")
        return None
        
    response = None
    response_data = None
    try:
        # Construct the user message combining raw alert and agent details
        user_message_content = {
            "alert": raw_alert_json,
            "agent_details": agent_details_json
        }

        # Convert to JSON string for the prompt
        user_message_str = json.dumps(user_message_content, indent=2)

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT_CONTENT},
            {"role": "user", "content": user_message_str}
        ]

        headers = {
            "api-key": AZURE_OPENAI_API_KEY,
            "Content-Type": "application/json"
        }

        api_url = f"{ENDPOINT_URL}/openai/deployments/{DEPLOYMENT_NAME}/chat/completions?api-version={AZURE_API_VERSION}"

        payload = {
            "messages": messages,
            "max_tokens": 1024, # Adjust as needed
            "temperature": 0.7,
            "top_p": 0.95,
            "frequency_penalty": 0,
            "presence_penalty": 0,
            "stop": ["<|im_end|>"]
        }

        log.info("Sending request to Azure OpenAI API...")
        # During this potentially long operation, the watchdog might timeout.
        # If your WatchdogSec is very short and LLM calls are long, you might
        # consider a separate thread for watchdog pings, but usually Systemd's
        # 1-minute default for WatchdogSec is enough for network calls.
        response = requests.post(api_url, headers=headers, json=payload, timeout=60) # Increased timeout
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

        response_data = response.json()
        
        # Extract content and token usage
        completion_content = response_data['choices'][0]['message']['content']
        prompt_tokens = response_data['usage']['prompt_tokens']
        completion_tokens = response_data['usage']['completion_tokens']
        total_tokens = response_data['usage']['total_tokens']

        log.info(f"LLM Response received. Tokens: Prompt={prompt_tokens}, Completion={completion_tokens}, Total={total_tokens}")

        return {
            "parsed_response": completion_content, # Store raw string, not parsed JSON
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens
        }

    except requests.exceptions.HTTPError as http_err:
        response_text = response.text if response is not None else 'No response available'
        log.error(f"HTTP error during LLM API call: {http_err} - {response_text}", exc_info=True)
        return None
    except requests.exceptions.ConnectionError as conn_err:
        log.error(f"Connection error during LLM API call: {conn_err}", exc_info=True)
        return None
    except requests.exceptions.Timeout as timeout_err:
        log.error(f"Timeout error during LLM API call: {timeout_err}", exc_info=True)
        return None
    except requests.exceptions.RequestException as req_err:
        log.error(f"An unexpected request error occurred during LLM API call: {req_err}", exc_info=True)
        return None
    except KeyError as ke:
        response_data_str = str(response_data) if response_data is not None else 'No response data available'
        log.error(f"KeyError in LLM response structure: {ke}. Full response: {response_data_str}", exc_info=True)
        return None
    except Exception as e:
        log.error(f"An unexpected error occurred in get_llm_response: {e}", exc_info=True)
        return None

# --- Main Alert Processing Logic ---
def process_alert_for_llm(alert_id: int) -> Union[dict, None]:
    """
    Fetches an alert and its enriched agent details, sends to LLM,
    and updates the alerts table with the LLM response.
    """
    if psycopg2 is None:
        log.error("psycopg2 module not available")
        return None
        
    conn = None
    cur = None
    alert_record = None
    try:
        conn = psycopg2.connect(PG_DSN)
        cur = conn.cursor(cursor_factory=DictCursor)

        # 1. Fetch the alert record from the alerts table
        cur.execute("SELECT * FROM alerts WHERE id = %s;", (alert_id,))
        alert_record = cur.fetchone()

        if not alert_record:
            log.error(f"Alert with ID {alert_id} not found in alerts table for LLM processing.")
            return None
        
        # ADDED: Fetch a fresh record to avoid race conditions with state updates
        # If the state was just updated by alert-enrichment-agent.py, we want the latest.
        # This will prevent re-processing by this worker if another LLM worker instance
        # somehow processed it in the interim, or if the notification was delayed.
        cur.execute("SELECT state FROM alerts WHERE id = %s;", (alert_id,))
        state_row = cur.fetchone()
        if not state_row:
            log.warning(f"No state found for alert ID {alert_id}; skipping.")
            return dict(alert_record)
        current_state = state_row[0] if isinstance(state_row, tuple) else state_row['state']

        if current_state != 'agent_enriched':
            log.info(f"Alert ID {alert_id} is in state '{current_state}', not 'agent_enriched'. Skipping LLM processing.")
            return dict(alert_record) # Return alert as dict for consistency

        if isinstance(alert_record, tuple):
            # For tuple records, we need to get the column index
            agent_id = None
            try:
                # Assuming standard column order, adjust as needed
                agent_id = alert_record[5] if len(alert_record) > 5 else None
            except IndexError:
                agent_id = None
        else:
            agent_id = alert_record.get('agent_id')
        if not agent_id:
            log.error(f"Alert ID {alert_id} is missing agent_id. Cannot fetch agent details for LLM.")
            return dict(alert_record)

        # 2. Fetch the associated agent details from the agents table
        cur.execute("SELECT api_response FROM agents WHERE id = %s;", (agent_id,))
        agent_data_from_db = cur.fetchone()

        agent_details_for_llm = {}
        if agent_data_from_db:
            if isinstance(agent_data_from_db, tuple):
                agent_details_for_llm = agent_data_from_db[0] if agent_data_from_db[0] else {}
            elif hasattr(agent_data_from_db, 'get') and agent_data_from_db.get('api_response'):
                agent_details_for_llm = agent_data_from_db['api_response']
            log.info(f"Successfully retrieved agent details for agent {agent_id} from DB for alert {alert_id}.")
        else:
            log.warning(f"No detailed agent data found in 'agents' table for agent ID {agent_id}. LLM prompt will lack agent context.")
            # If no agent data, send an empty dict to LLM to prevent errors

        # 3. Send to LLM
        if isinstance(alert_record, tuple):
            # For tuple records, get raw data by index (adjust index as needed)
            raw_alert = alert_record[3] if len(alert_record) > 3 else {}
        else:
            raw_alert = alert_record['raw']
        llm_response_data = get_llm_response(raw_alert, agent_details_for_llm)

        if not llm_response_data:
            log.error(f"LLM did not return a valid response for alert ID {alert_id}. Not updating alert table.")
            # We don't change the state here, so it can be retried later or manually inspected.
            return dict(alert_record) # Return original alert record

        # 4. Update the alerts table with LLM response and new state
        log.info(f"Updating alert {alert_id} with LLM response and state 'summarized'.")
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
        
        # Prepare the prompt_text (combine system and user messages sent to LLM)
        full_prompt_text = json.dumps([
            {"role": "system", "content": SYSTEM_PROMPT_CONTENT},
            {"role": "user", "content": json.dumps({"alert": raw_alert, "agent_details": agent_details_for_llm}, indent=2)}
        ], indent=2)

        cur.execute(update_query, (
            datetime.now(timezone.utc),
            full_prompt_text,
            datetime.now(timezone.utc),
            llm_response_data.get('parsed_response'),
            llm_response_data.get('prompt_tokens'),
            llm_response_data.get('completion_tokens'),
            llm_response_data.get('total_tokens'),
            'summarized',
            alert_id
        ))
        conn.commit()
        log.info(f"Alert ID {alert_id} successfully updated with LLM response.")

        # 5. Notify the next stage (Emailer)
        cur.execute("SELECT pg_notify('new_response', %s);", (str(alert_id),))
        conn.commit()
        log.info(f"pg_notify('new_response', {alert_id}) sent.")

        # Return the updated alert record with LLM details
        cur.execute("SELECT * FROM alerts WHERE id = %s;", (alert_id,))
        updated_record = cur.fetchone()
        return dict(updated_record) if updated_record else None

    except psycopg2.Error as db_err:
        log.critical(f"Database error in process_alert_for_llm for alert ID {alert_id}: {db_err}", exc_info=True)
        if conn:
            conn.rollback()
        notifier.notify("STATUS=Database error during alert processing. See logs.") # ADDED: sdnotify on DB error
        return None
    except Exception as e:
        log.critical(f"An unexpected error occurred in process_alert_for_llm for alert ID {alert_id}: {e}", exc_info=True)
        notifier.notify("STATUS=Unexpected error during alert processing. See logs.") # ADDED: sdnotify on unexpected error
        return None
    finally:
        if conn:
            if cur is not None:
                cur.close()
            conn.close()

# --- Listener for agent_enriched notifications ---
def listen_for_enriched_alerts():
    """
    Connects to PostgreSQL and listens for 'agent_enriched' notifications.
    When a notification is received, it triggers process_alert_for_llm.
    """
    if psycopg2 is None:
        log.error("psycopg2 module not available")
        notifier.notify("STATUS=psycopg2 module not available. Exiting.") # ADDED: sdnotify on missing psycopg2
        notifier.notify("STOPPING=1")
        return
        
    log.info(f"Starting PostgreSQL listener for channel '{LISTEN_CHANNEL}'...")
    conn = None
    cur = None
    try:
        conn = psycopg2.connect(PG_DSN)
        conn.autocommit = True # Important for LISTEN to work without explicit commits
        cur = conn.cursor()
        cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        log.info("Listening for notifications...")

        while True:
            # Ping watchdog regularly, especially when waiting for notifications
            notifier.notify("WATCHDOG=1") # ADDED: Watchdog ping at the start of each loop iteration

            conn.poll() # Check for new notifications
            while conn.notifies:            # consume queue
                notify = conn.notifies.pop(0)
                alert_id_str = notify.payload
                log.info(f"Received notification on channel '{notify.channel}' with payload: {alert_id_str}")
                # update_heartbeat_file() # REMOVED: No longer needed with sdnotify
                try:
                    alert_id = int(alert_id_str)
                    processed_alert = process_alert_for_llm(alert_id)
                    if processed_alert:
                        log.info(f"Alert ID {alert_id} LLM processing complete.")
                    else:
                        log.error(f"Failed to LLM process alert ID {alert_id}.")
                except ValueError:
                    log.error(f"Invalid alert_id received in notification payload: {alert_id_str}")
                except Exception as e:
                    log.error(f"Error processing notification for alert ID {alert_id_str}: {e}", exc_info=True)
            # Removed time.sleep(0.1) as select.select's implicit block or more explicit watchdog pings cover it
            # If your loop is extremely tight and CPU usage is high, you might re-introduce a *small* sleep,
            # but rely on watchdog for aliveness.

    except psycopg2.Error as db_err:
        log.critical(f"Database error during listener setup or operation: {db_err}", exc_info=True)
        notifier.notify("STATUS=Database error in listener. Exiting.") # ADDED: sdnotify on DB error
        notifier.notify("STOPPING=1")
        sys.exit(1)
    except Exception as e:
        log.critical(f"An unexpected error occurred in the listener: {e}", exc_info=True)
        notifier.notify("STATUS=Unexpected error in listener. Exiting.") # ADDED: sdnotify on unexpected error
        notifier.notify("STOPPING=1")
        sys.exit(1)
    finally:
        if conn:
            if cur is not None:
                cur.close()
            conn.close()

# --- Main function to run the script ---
def main():
    log.info("--- Starting LLM Worker Script ---")
    notifier.notify("READY=1") # ADDED: Signal Systemd that the service is ready

    # Test database connection immediately
    if psycopg2 is None:
        log.critical("psycopg2 module not available. Cannot connect to database.")
        notifier.notify("STATUS=psycopg2 module not available. Exiting.") # ADDED: sdnotify on missing psycopg2
        notifier.notify("STOPPING=1")
        sys.exit(1)
        
    try:
        conn_test = psycopg2.connect(PG_DSN, connect_timeout=5)
        conn_test.close()
        log.info("Successfully connected to PostgreSQL database using DSN.")
        notifier.notify("WATCHDOG=1") # ADDED: Ping watchdog after successful DB connection
    except psycopg2.Error as e:
        log.critical(f"ERROR: Could not connect to PostgreSQL database. Please check PG_DSN environment variable. Error: {e}")
        notifier.notify("STATUS=Failed to connect to DB. Exiting.") # ADDED: sdnotify on DB connection failure
        notifier.notify("STOPPING=1")
        sys.exit(1)

    # Initial heartbeat update (REMOVED: No longer needed with sdnotify)
    # update_heartbeat_file() 

    # Start the listener (this will block and run continuously)
    listen_for_enriched_alerts()

    log.info("--- LLM Worker Script Shutting Down ---")
    notifier.notify("STOPPING=1") # ADDED: Signal Systemd that the service is stopping

if __name__ == "__main__":
    main()
