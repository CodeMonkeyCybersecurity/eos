#!/usr/bin/env python3
# /usr/local/bin/delphi-agent-enricher.py
# stanley:stanley 0750

# ─── Standard library ────────────────────────────────────────────────────────
import select
import json
import os
import sys
import time
import logging
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from base64 import b64encode
from typing import Union, Optional, cast, Any

# ─── Third-party libraries (import-guarded for IDE happiness) ───────────────
try:
    import requests  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: Missing dependency 'requests'.\n"
        "Install it with:\n\n    pip install requests\n\n"
    )
    sys.exit(1)

try:
    import psycopg2  # type: ignore
    import psycopg2.extras as extras  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: Missing dependency 'psycopg2-binary'.\n"
        "Install it with:\n\n    pip install psycopg2-binary\n\n"
    )
    sys.exit(1)

try:
    from dotenv import load_dotenv  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    # Provide a harmless stub so type-checkers stop complaining
    def load_dotenv(*_args: object, **_kwargs: object) -> None:  # type: ignore
        pass
    logging.warning(
        "Optional dependency 'python-dotenv' not found – "
        "continuing without loading .env files."
    )

# --- Configuration & Environment Variable Validation ---

# Load environment variables from a single .env file.
# Ensure this path is correct for your StackStorm setup.
# This file should contain ALL variables like PG_DSN, WAZUH_API_URL, etc.
load_dotenv("/opt/stackstorm/packs/delphi/.env")

# PostgreSQL Database Connection String (DSN)
AGENTS_PG_DSN = os.getenv("AGENTS_PG_DSN")
if not AGENTS_PG_DSN:
    raise ValueError("AGENTS_PG_DSN environment variable not set. Please configure your PostgreSQL DSN in the .env file.")

# Wazuh API Connection Details
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://delphi.cybermonkey.net.au:55000") # Fallback for robustness
WAZUH_API_USER = os.environ.get("WAZUH_API_USER")
WAZUH_API_PASSWD = os.getenv("WAZUH_API_PASSWD") # Use getenv for consistency and safety

# Global variable to store JWT token after successful authentication.
# It will be populated by authenticate_wazuh_api if not already set in .env.
WAZUH_JWT_TOKEN = os.getenv("WAZUH_JWT_TOKEN") # Use getenv for consistency and safety

# PostgreSQL LISTEN channel for new alerts (this script's input)
LISTEN_CHANNEL = "new_alert" # This script explicitly listens to 'new_alert' notifications.

# --- Logger Setup ---
def setup_logging() -> logging.Logger:
    """Configure a rotating file logger and return it."""
    logger = logging.getLogger("delphi-agent-enricher") # Renamed logger for clarity
    logger.setLevel(logging.DEBUG) # Set to DEBUG for detailed logs during debugging

    # Ensure log directory exists
    log_dir = "/var/log/stackstorm"
    os.makedirs(log_dir, exist_ok=True)

    handler = RotatingFileHandler(
        os.path.join(log_dir, "delphi-agent-enricher.log"), # Log file name changed
        maxBytes=5 * 1024 * 1024, # 5 MB
        backupCount=3
    )
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)
    logger.addHandler(handler)

    # Also add a stream handler to see logs in console during development/debugging
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(fmt)
    logger.addHandler(stream_handler)

    logger.info("Logger initialized; script starting.")
    return logger

log = setup_logging()

# --- Wazuh API Authentication Function ---
def authenticate_wazuh_api(api_url: str, user: str, password: str) -> Union[str, None]:
    """
    Authenticates with the Wazuh API and returns a JWT token.
    """
    if not user or not password:
        log.warning("Wazuh API username or password not provided. Cannot authenticate using user/pass.")
        return None

    # SSL verification enabled for security - ensure Wazuh API has valid certificates

    login_endpoint = 'security/user/authenticate'
    login_url = f"{api_url}/{login_endpoint}"
    basic_auth_string = f"{user}:{password}".encode('utf-8')
    login_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64encode(basic_auth_string).decode("utf-8")}'
    }

    response = None  # ensures 'response' is always defined for except blocks
    log.info("Attempting Wazuh API login...")
    try:
        response = requests.post(login_url, headers=login_headers, timeout=10)
        response.raise_for_status()

        token_data = response.json()
        token = token_data.get('data', {}).get('token')
        if token:
            log.info("Successfully obtained Wazuh API JWT token.")
            return token
        else:
            log.error(f"Wazuh API login failed: No token in response. Response: {token_data}")
            return None
    except requests.exceptions.HTTPError as http_err:
        log.error(
            "Wazuh API login HTTP error: %s - %s",
            http_err,
            response.text if response is not None else "",
        )
        return None
    except requests.exceptions.RequestException as req_err:
        log.error(f"Wazuh API login request error: {req_err}")
        return None
    except json.JSONDecodeError as json_err:
        log.error(
            "Failed to decode JSON from Wazuh API login: %s. Response text: %s",
            json_err,
            response.text if response is not None else "",
        )
        return None
    except Exception as e:
        log.error(f"An unexpected error occurred during Wazuh API login: {e}")
        return None

# --- Wazuh API Interaction Function (Modified to fetch all agents and filter) ---
def get_wazuh_agent_info(agent_id: str) -> Union[dict, None]:
    """
    Fetches information about a specific Wazuh agent from the API by retrieving
    all agents and then filtering locally, mimicking 'curl ... | jq'.
    """
    global WAZUH_JWT_TOKEN

    # If JWT token is not set, try to authenticate using user/password
    if not WAZUH_JWT_TOKEN:
        log.warning("JWT token is not set. Attempting to authenticate Wazuh API using user/password from .env.")
        if WAZUH_API_USER and WAZUH_API_PASSWD:
            WAZUH_JWT_TOKEN = authenticate_wazuh_api(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWD)
        else:
            log.error("Wazuh API user/password are not set in .env, and JWT token is missing. Cannot fetch agent info.")
            return None

    if not WAZUH_JWT_TOKEN: # If authentication still failed
        log.error("Failed to obtain Wazuh API JWT token. Cannot proceed with agent info fetch.")
        return None

    # Construct the API endpoint to get ALL agents (mimicking your curl command)
    api_endpoint = f"{WAZUH_API_URL}/agents"

    headers = {
        "Authorization": f"Bearer {WAZUH_JWT_TOKEN}",
        "Content-Type": "application/json"
    }

    response = None  # avoids 'possibly unbound' IDE warning
    log.debug(f"Attempting to fetch all agents from Wazuh API: {api_endpoint}")
    try:
        response = requests.get(api_endpoint, headers=headers, timeout=30)
        response.raise_for_status()

        all_agents_data = response.json()
        log.debug(f"Received response from Wazuh API for all agents (truncated): {json.dumps(all_agents_data, indent=2)[:500]}...")

        if all_agents_data.get('error') == 0 and all_agents_data.get('data') and 'affected_items' in all_agents_data['data']:
            affected_items = all_agents_data['data']['affected_items']
            log.debug(f"Found {len(affected_items)} agents in Wazuh API response. Filtering for agent ID '{agent_id}'.")
            
            # Filter locally for the specific agent_id (mimicking jq select)
            for agent_item in affected_items:
                if agent_item.get('id') == agent_id:
                    log.info(f"Successfully found agent {agent_id} from the list of all agents retrieved from Wazuh API.")
                    return agent_item # Return the found agent's dictionary
            
            log.warning(f"Agent ID '{agent_id}' not found in the list of agents returned by '{api_endpoint}' after filtering.")
            return None # Agent not found in the list
        else:
            log.warning(f"Wazuh API returned unexpected data structure from '{api_endpoint}'. Response: {all_agents_data}")
            return None

    except requests.exceptions.HTTPError as http_err:
        log.error(
            "HTTP error during Wazuh API call for all agents: %s - %s",
            http_err,
            response.text if response is not None else "",
        )
        if response is not None and response.status_code in [401, 403]:
            log.warning("JWT token might be expired or invalid. Clearing token for re-authentication attempt.")
            WAZUH_JWT_TOKEN = None # Clear token to force re-authentication on next call
        return None
    except requests.exceptions.ConnectionError as conn_err:
        log.error(f"Connection error during Wazuh API call for all agents: {conn_err}. Is Wazuh API running and accessible at {WAZUH_API_URL}?", exc_info=True)
        return None
    except requests.exceptions.Timeout as timeout_err:
        log.error(f"Timeout error during Wazuh API call for all agents: {timeout_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        log.error(f"An unexpected request error occurred during Wazuh API call for all agents: {req_err}", exc_info=True)
        return None
    except json.JSONDecodeError as json_err:
        log.error(
            "Failed to decode JSON response from Wazuh API for all agents: %s. Response text: %s",
            json_err,
            response.text if response is not None else "",
        )
        return None
    except Exception as e:
        log.error(f"An unexpected error occurred in get_wazuh_agent_info: {e}", exc_info=True)
        return None

# --- Database Interaction Function ---
def update_agent_info_in_db(agent_id: str, agent_data: dict, api_fetch_timestamp: datetime) -> bool:
    """
    Updates or inserts agent information into the 'agents' table.
    """
    conn: Optional["psycopg2.extensions.connection"] = None
    cur: Optional["psycopg2.extensions.cursor"] = None
    try:
        conn = psycopg2.connect(AGENTS_PG_DSN)
        cur = conn.cursor()

        # --- Extract and prepare all fields from agent_data for database insertion ---
        name = agent_data.get('name')
        ip = agent_data.get('ip')

        os_info = agent_data.get('os')
        os_string = None
        if os_info:
            os_name = os_info.get('name', 'Unknown OS')
            os_version = os_info.get('version', '')
            os_arch = os_info.get('arch', '')
            os_string = f"{os_name}"
            if os_version:
                os_string += f" {os_version}"
            if os_arch:
                os_string += f" ({os_arch})"

        registered_at = None
        if agent_data.get('dateAdd'):
            try:
                registered_at = datetime.fromisoformat(agent_data['dateAdd'].replace('Z', '+00:00')).astimezone(timezone.utc)
            except ValueError:
                log.warning(f"Could not parse dateAdd '{agent_data['dateAdd']}' for agent {agent_id}. Storing as NULL.")

        last_seen_at = None
        if agent_data.get('lastKeepAlive'):
            try:
                if agent_data['lastKeepAlive'].startswith("9999"): # Handle special "never expires" timestamp
                    last_seen_at = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
                else:
                    last_seen_at = datetime.fromisoformat(agent_data['lastKeepAlive'].replace('Z', '+00:00')).astimezone(timezone.utc)
            except ValueError:
                log.warning(f"Could not parse lastKeepAlive '{agent_data['lastKeepAlive']}' for agent {agent_id}. Storing as NULL.")

        disconnection_time = None
        if agent_data.get('disconnection_time'):
            try:
                disconnection_time = datetime.fromisoformat(agent_data['disconnection_time'].replace('Z', '+00:00')).astimezone(timezone.utc)
            except ValueError:
                log.warning(f"Could not parse disconnection_time '{agent_data['disconnection_time']}' for agent {agent_id}. Storing as NULL.")

        agent_version = agent_data.get('version')
        register_ip = agent_data.get('registerIP')
        node_name = agent_data.get('node_name')
        config_sum = agent_data.get('configSum')
        merged_sum = agent_data.get('mergedSum')
        group_config_status = agent_data.get('group_config_status')
        status_text = agent_data.get('status')
        status_code_api = agent_data.get('status_code')
        manager_name = agent_data.get('manager')
        groups = agent_data.get('group')

        api_fetch_timestamp_utc = api_fetch_timestamp.astimezone(timezone.utc)
        # Ensure agent_data is stored as JSON string (or directly as JSONB if column type allows)
        agent_data_json_to_store = json.dumps(agent_data) 

        log.debug(f"Preparing to UPSERT agent '{agent_id}' with data: Name='{name}', IP='{ip}', OS='{os_string}', Status='{status_text}', Manager='{manager_name}'.")

        # --- UPSERT Query ---
        upsert_query = """
        INSERT INTO agents (
            id, name, ip, os, registered, last_seen,
            agent_version, register_ip, node_name, config_sum, merged_sum,
            group_config_status, status_text, status_code_api, groups,
            disconnection_time, manager_name,
            api_response, api_fetch_timestamp
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (id) DO UPDATE SET
            name = EXCLUDED.name,
            ip = EXCLUDED.ip,
            os = EXCLUDED.os,
            registered = COALESCE(agents.registered, EXCLUDED.registered), -- Only update if existing is NULL
            last_seen = EXCLUDED.last_seen,
            agent_version = EXCLUDED.agent_version,
            register_ip = EXCLUDED.register_ip,
            node_name = EXCLUDED.node_name,
            config_sum = EXCLUDED.config_sum,
            merged_sum = EXCLUDED.merged_sum,
            group_config_status = EXCLUDED.group_config_status,
            status_text = EXCLUDED.status_text,
            status_code_api = EXCLUDED.status_code_api,
            groups = EXCLUDED.groups,
            disconnection_time = EXCLUDED.disconnection_time,
            manager_name = EXCLUDED.manager_name,
            api_response = EXCLUDED.api_response,
            api_fetch_timestamp = EXCLUDED.api_fetch_timestamp;
        """

        cur.execute(upsert_query, (
            agent_id,
            name,
            ip,
            os_string,
            registered_at,
            last_seen_at,
            agent_version,
            register_ip,
            node_name,
            config_sum,
            merged_sum,
            group_config_status,
            status_text,
            status_code_api,
            json.dumps(groups) if groups is not None else None, # Convert Python list to JSON string for JSONB
            disconnection_time,
            manager_name,
            agent_data_json_to_store, # Use the JSON string here
            api_fetch_timestamp_utc
        ))
        conn.commit()
        log.info(f"Agent '{agent_id}' info updated/inserted in database successfully. (Name: '{name}', OS: '{os_string}')")
        return True

    except psycopg2.Error as db_err:
        log.error(f"Database error while updating agent '{agent_id}': {db_err}", exc_info=True)
        if conn:
            conn.rollback()
        return False
    except Exception as e:
        log.error(f"An unexpected error occurred during DB update for agent '{agent_id}': {e}", exc_info=True)
        return False
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# --- Main Alert Processing Logic ---
def process_new_alert(alert_id: int) -> Union[dict, None]:
    """
    Processes a new alert, fetches agent info, updates the database,
    and returns an enriched alert.
    It also updates the alerts table state and sends a notification.
    """
    conn: Optional["psycopg2.extensions.connection"] = None
    cur: Optional["psycopg2.extensions.cursor"] = None
    try:
        conn = psycopg2.connect(AGENTS_PG_DSN)
        cur = conn.cursor(cursor_factory=extras.DictCursor)

        log.debug(f"Attempting to fetch alert ID {alert_id} for processing.")
        cur.execute("SELECT * FROM alerts WHERE id = %s;", (alert_id,))
        raw_record = cur.fetchone()
        
        if not raw_record:
            log.error(f"Alert with ID {alert_id} not found in alerts table after notification. Skipping.")
            return None

        alert_record: dict[str, Any] = dict(raw_record)  # cast for Pylance

        current_state = alert_record.get('state')
        log.debug(f"Alert ID {alert_id} fetched. Current state: '{current_state}'.")

        if current_state != 'new':
            log.info(f"Alert {alert_id} is in state '{current_state}', not 'new'. Skipping redundant agent enrichment for this notification.")
            return dict(alert_record) 

        agent_id = alert_record.get('agent_id')
        if not agent_id:
            log.error(f"Alert ID {alert_id} does not contain 'agent_id'. Cannot enrich without agent ID. Skipping.")
            return dict(alert_record)

        log.info(f"Alert ID {alert_id} (Agent ID: {agent_id}) is 'new'. Proceeding with agent enrichment.")

        # 2. Fetch agent info from Wazuh API
        api_fetch_time = datetime.now(timezone.utc)
        log.debug(f"Fetching agent info for agent ID '{agent_id}' from Wazuh API at {api_fetch_time.isoformat()}.")
        agent_info = get_wazuh_agent_info(agent_id)

        # 3. Update agent info in PostgreSQL database
        db_updated = False
        if agent_info:
            db_updated = update_agent_info_in_db(agent_id, agent_info, api_fetch_time)
            if db_updated:
                log.debug(f"Agent details for '{agent_id}' successfully updated/inserted in 'agents' table.")
            else:
                log.warning(f"Failed to update/insert agent details for '{agent_id}' in 'agents' table.")
        else:
            log.warning(f"Could not retrieve agent info from Wazuh API for agent ID '{agent_id}' (alert ID {alert_id}). DB update skipped for this agent.")


        # 4. Update the alerts table state and send notification
        log.info(f"Attempting to update alert {alert_id} state from 'new' to 'agent_enriched' and send notification.")
        # This update is conditional: it only proceeds if the state is still 'new'.
        cur.execute(
            """
            UPDATE alerts
            SET state = 'agent_enriched'
            WHERE id = %s
            AND state = 'new'
            RETURNING 1;
            """,
            (alert_id,),
        )
        if cur.rowcount: # row changed → first time we saw it
            conn.commit() # Commit the state change before notifying
            cur.execute("SELECT pg_notify('agent_enriched', %s);", (str(alert_id),))
            conn.commit() # Commit the notification
            log.info(f"Alert {alert_id} successfully transitioned from 'new' to 'agent_enriched' and 'agent_enriched' notification sent.")
        else:
            log.debug(f"Alert {alert_id} was already processed (state was not 'new'). No 'agent_enriched' state update or notification sent from this instance.")
            conn.rollback() # Rollback if no update happened to release lock/resource if needed, though autocommit makes this less critical

        # Append agent details to the alert record for the next stage (LLM/email)
        enriched_alert = dict(alert_record) # Start with a mutable copy
        if agent_info:
            enriched_alert['agent_details'] = agent_info
            enriched_alert['agent_details_fetch_timestamp'] = api_fetch_time.isoformat()
            log.info(f"Alert {alert_id} record prepared for next stage with enriched agent {agent_id} details.")
        else:
            log.warning(f"Alert {alert_id} record passed to next stage without full agent details due to fetch failure.")

        return enriched_alert

    except psycopg2.Error as db_err:
        log.critical(f"Database error in process_new_alert for alert ID {alert_id}: {db_err}", exc_info=True)
        if conn:
            conn.rollback()
        return None
    except Exception as e:
        log.critical(f"An unexpected error occurred in process_new_alert for alert ID {alert_id}: {e}", exc_info=True)
        return None
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

# --- Listener for new_alert notifications ---
def listen_for_new_alerts():
    """
    Connects to PostgreSQL and listens for 'new_alert' notifications.
    When a notification is received, it triggers process_new_alert.
    """
    log.info(f"Starting PostgreSQL listener for channel '{LISTEN_CHANNEL}'...")
    conn: Optional["psycopg2.extensions.connection"] = None
    cur: Optional["psycopg2.extensions.cursor"] = None
    try:
        conn = psycopg2.connect(AGENTS_PG_DSN)
        conn.autocommit = True # Important for LISTEN to work without explicit commits
        cur = conn.cursor()
        cur.execute(f"LISTEN {LISTEN_CHANNEL};")
        log.info("Listening for notifications...")

        while True:
            # Poll for new notifications with a faster timeout (0.1s)
            # This makes the listener more responsive and reduces busy-waiting
            if not select.select([conn], [], [], 0.1)[0]:
                continue  # Timeout, loop again

            conn.poll()
            
            # Consume the notifications queue, processing each only once
            while conn.notifies:
                notify = conn.notifies.pop(0) # Remove notification as we process it
                alert_id_str = notify.payload
                log.info(f"Received notification on channel '{notify.channel}' with payload: {alert_id_str}. Initiating processing.")
                try:
                    alert_id = int(alert_id_str)
                    processed_alert = process_new_alert(alert_id)
                    # The process_new_alert now handles logging success/skipping based on state.
                    # We just log a final confirmation here.
                    if processed_alert:
                        log.debug(f"Alert ID {alert_id} (from payload) processing cycle completed.")
                    else:
                        log.error(f"Alert ID {alert_id} (from payload) processing failed or returned None.")
                except ValueError:
                    log.error(f"Invalid alert_id received in notification payload: '{alert_id_str}'. Skipping.")
                except Exception as e:
                    log.error(f"Error processing notification for alert ID '{alert_id_str}': {e}", exc_info=True)
            # No explicit sleep needed here, as the select.select timeout manages polling frequency.

    except psycopg2.Error as db_err:
        log.critical(f"Database error during listener setup or operation: {db_err}", exc_info=True)
        sys.exit(1)
    except Exception as e:
        log.critical(f"An unexpected error occurred in the listener: {e}", exc_info=True)
        sys.exit(1)
    finally:
        if conn:
            conn.close()

# --- Main function to run the script ---
def main():
    log.info("--- Starting Alert Enrichment Script ---")

    # Initial authentication attempt for Wazuh API
    global WAZUH_JWT_TOKEN
    if not WAZUH_JWT_TOKEN:
        WAZUH_JWT_TOKEN = authenticate_wazuh_api(
            WAZUH_API_URL,
            cast(str, WAZUH_API_USER),
            cast(str, WAZUH_API_PASSWD),
        )
        if not WAZUH_JWT_TOKEN:
            log.critical("Initial Wazuh API authentication failed. Exiting.")
            sys.exit(1)
    else:
        log.info("Using existing JWT token from environment variable.")

    # Test database connection immediately
    try:
        conn_test = psycopg2.connect(AGENTS_PG_DSN, connect_timeout=5)
        conn_test.close()
        log.info("Successfully connected to PostgreSQL database using DSN.")
    except psycopg2.Error as e:
        log.critical(f"ERROR: Could not connect to PostgreSQL database. Please check AGENTS_PG_DSN environment variable. Error: {e}")
        sys.exit(1)

    # Start the listener (this will block and run continuously)
    listen_for_new_alerts()


if __name__ == "__main__":
    main()