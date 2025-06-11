#!/usr/bin/env python3
# /usr/local/bin/alert-enrichment.py
# stanley:stanley 0750

import requests
import json
import os
import psycopg2
from psycopg2 import extras
from datetime import datetime, timezone
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from base64 import b64encode
import urllib3 # For disabling insecure warnings

# --- Configuration & Environment Variable Validation ---

# Load environment variables from specified .env files
# Ensure these paths are correct for your StackStorm setup.
load_dotenv("/opt/stackstorm/packs/delphi/.env")
load_dotenv("/opt/stackstorm/packs/delphi/.delphi.env") # For Wazuh API specific secrets

# PostgreSQL Database Connection String (DSN)
AGENTS_PG_DSN = os.getenv("AGENTS_PG_DSN")
if not AGENTS_PG_DSN:
    raise ValueError("AGENTS_PG_DSN environment variable not set. Please configure your PostgreSQL DSN.")

# Wazuh API Connection Details
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://delphi.cybermonkey.net.au:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER")
WAZUH_API_PASSWD = os.environ.get("WAZUH_API_PASSWD")

# Global variable to store JWT token after successful authentication
# It will be populated by authenticate_wazuh_api if needed, or by env var if pre-set
WAZUH_JWT_TOKEN = os.environ.get("WAZUH_JWT_TOKEN")

# PostgreSQL LISTEN channel for new alerts
LISTEN_CHANNEL = "new_response" # Or "new_alert" if you want to trigger on initial insert

# --- Logger Setup ---
def setup_logging() -> logging.Logger:
    """Configure a rotating file logger and return it."""
    logger = logging.getLogger("delphi-emailer")
    logger.setLevel(logging.DEBUG) # Set to INFO for production to reduce verbosity

    # Ensure log directory exists
    log_dir = "/var/log/stackstorm"
    os.makedirs(log_dir, exist_ok=True)

    handler = RotatingFileHandler(
        os.path.join(log_dir, "delphi-emailer.log"),
        maxBytes=5 * 1024 * 1024, # 5 MB
        backupCount=3
    )
    # Use a concise formatter
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
def authenticate_wazuh_api(api_url: str, user: str, password: str) -> str | None:
    """
    Authenticates with the Wazuh API and returns a JWT token.

    Args:
        api_url (str): The base URL of the Wazuh API.
        user (str): Wazuh API username.
        password (str): Wazuh API password.

    Returns:
        str | None: The JWT token if authentication is successful, None otherwise.
    """
    if not user or not password:
        log.warning("Wazuh API username or password not provided. Cannot authenticate using user/pass.")
        return None

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable insecure https warnings for self-signed certs

    login_endpoint = 'security/user/authenticate'
    login_url = f"{api_url}/{login_endpoint}"
    basic_auth_string = f"{user}:{password}".encode('utf-8')
    login_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Basic {b64encode(basic_auth_string).decode("utf-8")}'
    }

    log.info("Attempting Wazuh API login...")
    try:
        response = requests.post(login_url, headers=login_headers, verify=False, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses

        token_data = response.json()
        token = token_data.get('data', {}).get('token')
        if token:
            log.info("Successfully obtained Wazuh API JWT token.")
            return token
        else:
            log.error(f"Wazuh API login failed: No token in response. Response: {token_data}")
            return None
    except requests.exceptions.HTTPError as http_err:
        log.error(f"Wazuh API login HTTP error: {http_err} - {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        log.error(f"Wazuh API login request error: {req_err}")
        return None
    except json.JSONDecodeError as json_err:
        log.error(f"Failed to decode JSON from Wazuh API login: {json_err}. Response: {response.text}")
        return None
    except Exception as e:
        log.error(f"An unexpected error occurred during Wazuh API login: {e}")
        return None

# --- Wazuh API Interaction Function ---
def get_wazuh_agent_info(agent_id: str) -> dict | None:
    """
    Fetches detailed information about a specific Wazuh agent from the API.

    Args:
        agent_id (str): The ID of the Wazuh agent (e.g., "000", "001").

    Returns:
        dict: A dictionary containing the agent's information if successful.
              Returns None if the API call fails or agent information is not found.
    """
    global WAZUH_JWT_TOKEN

    # If JWT token is not set, try to authenticate using user/password
    if not WAZUH_JWT_TOKEN:
        log.warning("JWT token is not set. Attempting to authenticate Wazuh API using user/password.")
        if WAZUH_API_USER and WAZUH_API_PASSWD:
            WAZUH_JWT_TOKEN = authenticate_wazuh_api(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWD)
        else:
            log.error("Wazuh API user/password are not set, and JWT token is missing. Cannot fetch agent info.")
            return None

    if not WAZUH_JWT_TOKEN: # If authentication still failed
        log.error("Failed to obtain Wazuh API JWT token. Cannot proceed with agent info fetch.")
        return None

    # Construct the API endpoint for a single agent
    api_endpoint = f"{WAZUH_API_URL}/agents/{agent_id}"

    headers = {
        "Authorization": f"Bearer {WAZUH_JWT_TOKEN}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(api_endpoint, headers=headers, verify=False, timeout=10)
        response.raise_for_status()

        data = response.json()

        # The /agents/{agent_id} endpoint typically returns the agent object directly in 'data'
        if data.get('error') == 0 and data.get('data') and isinstance(data['data'], dict):
            return data['data']
        else:
            log.warning(f"Wazuh API returned unexpected data for agent {agent_id}. Error: {data.get('error')}, Data: {data.get('data')}")
            return None

    except requests.exceptions.HTTPError as http_err:
        log.error(f"HTTP error during Wazuh API call for agent {agent_id}: {http_err} - {response.text}")
        if response.status_code == 401 or response.status_code == 403:
            log.warning("JWT token might be expired or invalid. Clearing token for re-authentication attempt.")
            WAZUH_JWT_TOKEN = None # Clear token to force re-authentication on next call
        return None
    except requests.exceptions.ConnectionError as conn_err:
        log.error(f"Connection error during Wazuh API call for agent {agent_id}: {conn_err}. Is Wazuh API running and accessible at {WAZUH_API_URL}?", exc_info=True)
        return None
    except requests.exceptions.Timeout as timeout_err:
        log.error(f"Timeout error during Wazuh API call for agent {agent_id}: {timeout_err}")
        return None
    except requests.exceptions.RequestException as req_err:
        log.error(f"An unexpected request error occurred during Wazuh API call for agent {agent_id}: {req_err}", exc_info=True)
        return None
    except json.JSONDecodeError as json_err:
        log.error(f"Failed to decode JSON response from Wazuh API for agent {agent_id}: {json_err}. Response text: {response.text}")
        return None
    except Exception as e:
        log.error(f"An unexpected error occurred in get_wazuh_agent_info for agent {agent_id}: {e}", exc_info=True)
        return None

# --- Database Interaction Function ---
def update_agent_info_in_db(agent_id: str, agent_data: dict, api_fetch_timestamp: datetime) -> bool:
    """
    Updates or inserts agent information into the 'agents' table.

    Args:
        agent_id (str): The ID of the agent to update/insert.
        agent_data (dict): The dictionary containing agent information from Wazuh API.
                           This is the 'data' field directly from the API response for one agent.
        api_fetch_timestamp (datetime): The timestamp when the API call was made.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    conn = None
    try:
        conn = psycopg2.connect(AGENTS_PG_DSN)
        cur = conn.cursor()

        # --- Extract and prepare all fields from agent_data for database insertion ---
        name = agent_data.get('name')
        ip = agent_data.get('ip')

        # OS information (complex nested object to string)
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

        # Timestamps
        registered_at = None
        if agent_data.get('dateAdd'):
            try:
                registered_at = datetime.fromisoformat(agent_data['dateAdd'].replace('Z', '+00:00')).astimezone(timezone.utc)
            except ValueError:
                log.warning(f"Could not parse dateAdd '{agent_data['dateAdd']}' for agent {agent_id}")

        last_seen_at = None
        if agent_data.get('lastKeepAlive'):
            try:
                if agent_data['lastKeepAlive'].startswith("9999"): # Handle special "never expires" timestamp
                    last_seen_at = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
                else:
                    last_seen_at = datetime.fromisoformat(agent_data['lastKeepAlive'].replace('Z', '+00:00')).astimezone(timezone.utc)
            except ValueError:
                log.warning(f"Could not parse lastKeepAlive '{agent_data['lastKeepAlive']}' for agent {agent_id}")

        disconnection_time = None
        if agent_data.get('disconnection_time'):
            try:
                disconnection_time = datetime.fromisoformat(agent_data['disconnection_time'].replace('Z', '+00:00')).astimezone(timezone.utc)
            except ValueError:
                log.warning(f"Could not parse disconnection_time '{agent_data['disconnection_time']}' for agent {agent_id}")

        # Other new fields
        agent_version = agent_data.get('version') # Note: API 'version' maps to DB 'agent_version'
        register_ip = agent_data.get('registerIP')
        node_name = agent_data.get('node_name')
        config_sum = agent_data.get('configSum')
        merged_sum = agent_data.get('mergedSum')
        group_config_status = agent_data.get('group_config_status')
        status_text = agent_data.get('status') # API 'status' maps to DB 'status_text'
        status_code_api = agent_data.get('status_code')
        manager_name = agent_data.get('manager')
        groups = agent_data.get('group') # API 'group' (array) maps to DB 'groups' (JSONB)


        # Ensure api_fetch_timestamp is UTC
        api_fetch_timestamp_utc = api_fetch_timestamp.astimezone(timezone.utc)

        # Convert agent_data dict to JSON string for JSONB column
        agent_data_json = json.dumps(agent_data)

        # --- UPSERT Query ---
        # The order of columns in the INSERT and VALUES clause MUST match.
        # The order of columns in the SET clause for UPDATE should match for readability.
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
            -- Only update 'registered' if the existing value is NULL or older than EXCLUDED.registered
            registered = COALESCE(agents.registered, EXCLUDED.registered),
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
            agent_data_json,
            api_fetch_timestamp_utc
        ))
        conn.commit()
        log.info(f"Agent {agent_id} info updated/inserted in database successfully.")
        return True

    except psycopg2.Error as db_err:
        log.error(f"Database error while updating agent {agent_id}: {db_err}", exc_info=True)
        if conn:
            conn.rollback()
        return False
    except Exception as e:
        log.error(f"An unexpected error occurred during DB update for agent {agent_id}: {e}", exc_info=True)
        return False
    finally:
        if conn:
            cur.close()
            conn.close()

# --- Main Alert Processing Logic ---
def process_new_alert(alert: dict) -> dict | None:
    """
    Processes a new alert, fetches agent info, updates the database,
    and returns an enriched alert.

    Args:
        alert (dict): A dictionary representing a new Wazuh alert.
                      It MUST contain 'agent_id'.

    Returns:
        dict | None: An enriched alert dictionary, or None if processing failed.
    """
    agent_id = alert.get('agent_id')
    if not agent_id:
        log.error("Incoming alert does not contain 'agent_id'. Skipping enrichment.")
        return None

    log.info(f"Processing alert for agent ID: {agent_id}")

    # 1. Fetch agent info from Wazuh API
    api_fetch_time = datetime.now(timezone.utc) # Get current UTC time for API fetch
    agent_info = get_wazuh_agent_info(agent_id)

    if not agent_info:
        log.warning(f"Could not retrieve agent info for {agent_id}. Alert will not be enriched with agent details.")
        return alert # Return original alert if agent info can't be fetched

    # 2. Update agent info in PostgreSQL database
    db_updated = update_agent_info_in_db(agent_id, agent_info, api_fetch_time)

    enriched_alert = alert.copy()
    if db_updated:
        # Add the fetched agent info to the alert for further processing (LLM, email)
        # You can select specific fields from agent_info if you don't want the whole JSON
        enriched_alert['agent_details'] = agent_info
        enriched_alert['agent_details_fetch_timestamp'] = api_fetch_time.isoformat()
        log.info(f"Successfully enriched alert with agent {agent_id} details.")
    else:
        log.warning(f"Failed to update database for agent {agent_id}. Alert will still be processed but may lack latest agent details.")

    return enriched_alert

# --- Main function to run the simulation ---
def main():
    log.info("--- Starting Alert Enrichment Script (Simulation Mode) ---")

    # Initial authentication attempt
    global WAZUH_JWT_TOKEN
    if not WAZUH_JWT_TOKEN:
        WAZUH_JWT_TOKEN = authenticate_wazuh_api(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWD)
        if not WAZUH_JWT_TOKEN:
            log.critical("Initial Wazuh API authentication failed. Exiting.")
            sys.exit(1)
    else:
        log.info("Using existing JWT token from environment variable.")

    # Test database connection immediately
    try:
        conn_test = psycopg2.connect(AGENTS_PG_DSN, connect_timeout=5)
        conn_test.close()
        log.info("Successfully connected to PostgreSQL database.")
    except psycopg2.Error as e:
        log.critical(f"ERROR: Could not connect to PostgreSQL database. Please check AGENTS_PG_DSN environment variable. Error: {e}")
        sys.exit(1) # Exit if DB connection fails at startup

    log.info("--- Simulating New Alert Arrivals ---")

    # Example 1: New alert for an existing agent (ID 001)
    sample_alert_1 = {
        "id": 12345,
        "alert_hash": "somehash1",
        "agent_id": "001", # Corresponds to "cybermonkey-net" in your curl output
        "rule_id": 500,
        "rule_level": 7,
        "rule_desc": "Login failed",
        "raw": {"full_log": "authentication failed for user root from 192.168.1.5"},
        "ingest_timestamp": datetime.now(timezone.utc).isoformat(),
        "state": "new"
    }
    log.info(f"\nIncoming Alert (ID: {sample_alert_1['id']}, Agent: {sample_alert_1['agent_id']}):")
    enriched_alert_1 = process_new_alert(sample_alert_1)
    if enriched_alert_1:
        log.info(f"Enriched Alert for LLM/Email (excerpt, agent_details present: {'agent_details' in enriched_alert_1})")
        # log.debug(json.dumps(enriched_alert_1, indent=2)) # Uncomment to see full enriched alert

    time.sleep(2) # Simulate a delay

    # Example 2: New alert for another existing agent (ID 008)
    sample_alert_2 = {
        "id": 12346,
        "alert_hash": "somehash2",
        "agent_id": "008", # Corresponds to "vhost3" in your curl output
        "rule_id": 550,
        "rule_level": 9,
        "rule_desc": "Unauthorized access attempt",
        "raw": {"full_log": "attempted access to /etc/shadow by unauthorized user"},
        "ingest_timestamp": datetime.now(timezone.utc).isoformat(),
        "state": "new"
    }
    log.info(f"\nIncoming Alert (ID: {sample_alert_2['id']}, Agent: {sample_alert_2['agent_id']}):")
    enriched_alert_2 = process_new_alert(sample_alert_2)
    if enriched_alert_2:
        log.info(f"Enriched Alert for LLM/Email (excerpt, agent_details present: {'agent_details' in enriched_alert_2})")

    time.sleep(2)

    # Example 3: New alert for a non-existent agent (e.g., "999")
    sample_alert_3 = {
        "id": 12347,
        "alert_hash": "somehash3",
        "agent_id": "999", # Non-existent agent
        "rule_id": 600,
        "rule_level": 5,
        "rule_desc": "Unknown event",
        "raw": {"full_log": "malformed log received from unknown source"},
        "ingest_timestamp": datetime.now(timezone.utc).isoformat(),
        "state": "new"
    }
    log.info(f"\nIncoming Alert (ID: {sample_alert_3['id']}, Agent: {sample_alert_3['agent_id']}):")
    enriched_alert_3 = process_new_alert(sample_alert_3)
    if enriched_alert_3:
        log.info(f"Enriched Alert for LLM/Email (excerpt, agent_details present: {'agent_details' in enriched_alert_3})")

    log.info("--- Simulation Complete ---")

if __name__ == "__main__":
    main()
```