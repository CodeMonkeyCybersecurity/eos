#!/usr/bin/env python3
# /usr/local/bin/delphi-agent-enricher.py
"""
Delphi Agent Enricher - Phase 2 of Alert Processing Pipeline

This worker enriches new alerts with agent context from Wazuh API.
It listens for 'new_alert' notifications and transitions alerts to 'enriched' state.
"""

import os
import sys
import json
import time
import select
import logging
import psycopg2
import requests
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass
from functools import lru_cache

# Import environment variables
try:
    from dotenv import load_dotenv
    load_dotenv("/opt/stackstorm/packs/delphi/.env")
except ImportError:
    pass  # Optional dependency

# Configuration
PG_DSN = os.getenv("PG_DSN")
if not PG_DSN:
    raise ValueError("PG_DSN environment variable not set")

WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://delphi.cybermonkey.net.au:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER")
WAZUH_API_PASSWD = os.getenv("WAZUH_API_PASSWD")

# Circuit breaker configuration
MAX_API_FAILURES = 5
FAILURE_RESET_TIME = 300  # 5 minutes

@dataclass
class CircuitBreaker:
    """Simple circuit breaker for API calls"""
    failure_count: int = 0
    last_failure_time: Optional[float] = None
    is_open: bool = False
    
    def record_success(self):
        """Reset the circuit breaker on success"""
        self.failure_count = 0
        self.is_open = False
        
    def record_failure(self):
        """Record a failure and potentially open the circuit"""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= MAX_API_FAILURES:
            self.is_open = True
            
    def can_attempt(self) -> bool:
        """Check if we can attempt an API call"""
        if not self.is_open:
            return True
            
        # Check if enough time has passed to reset
        if self.last_failure_time and (time.time() - self.last_failure_time) > FAILURE_RESET_TIME:
            self.is_open = False
            self.failure_count = 0
            return True
            
        return False


class AgentEnricher:
    """Handles alert enrichment with agent context"""
    
    def __init__(self):
        self.logger = self._setup_logging()
        self.jwt_token: Optional[str] = None
        self.jwt_expiry: Optional[float] = None
        self.circuit_breaker = CircuitBreaker()
        
    def _setup_logging(self) -> logging.Logger:
        """Configure logging with rotation"""
        logger = logging.getLogger("delphi-agent-enricher")
        logger.setLevel(logging.INFO)
        
        # Ensure log directory exists
        log_dir = "/var/log/stackstorm"
        os.makedirs(log_dir, exist_ok=True)
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "delphi-agent-enricher.log"),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        
        # Console handler for development
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s",
            "%Y-%m-%d %H:%M:%S"
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
        
    def _get_jwt_token(self) -> Optional[str]:
        """Get JWT token, refreshing if necessary"""
        # Check if we have a valid token
        if self.jwt_token and self.jwt_expiry and time.time() < self.jwt_expiry:
            return self.jwt_token
            
        # Need to authenticate
        if not WAZUH_API_USER or not WAZUH_API_PASSWD:
            self.logger.error("Wazuh API credentials not configured")
            return None
            
        try:
            # Prepare authentication request
            import base64
            auth_string = f"{WAZUH_API_USER}:{WAZUH_API_PASSWD}"
            auth_bytes = auth_string.encode('utf-8')
            auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
            
            response = requests.post(
                f"{WAZUH_API_URL}/security/user/authenticate",
                headers={
                    "Authorization": f"Basic {auth_b64}",
                    "Content-Type": "application/json"
                },
                timeout=10,
                verify=True  # Enable SSL verification
            )
            response.raise_for_status()
            
            data = response.json()
            self.jwt_token = data.get('data', {}).get('token')
            
            if self.jwt_token:
                # JWT tokens typically expire in 900 seconds (15 minutes)
                # Set expiry to 14 minutes to be safe
                self.jwt_expiry = time.time() + 840
                self.logger.info("Successfully authenticated with Wazuh API")
                return self.jwt_token
            else:
                self.logger.error("No token in Wazuh API response")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to authenticate with Wazuh API: {e}")
            return None
            
    def fetch_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Fetch specific agent information from Wazuh API"""
        if not self.circuit_breaker.can_attempt():
            self.logger.warning(f"Circuit breaker open for Wazuh API, skipping agent {agent_id}")
            return None
            
        token = self._get_jwt_token()
        if not token:
            self.circuit_breaker.record_failure()
            return None
            
        try:
            # Use the specific agent endpoint for efficiency
            response = requests.get(
                f"{WAZUH_API_URL}/agents/{agent_id}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=10
            )
            
            if response.status_code == 404:
                self.logger.warning(f"Agent {agent_id} not found in Wazuh")
                self.circuit_breaker.record_success()  # Not an API failure
                return None
                
            response.raise_for_status()
            
            data = response.json()
            if data.get('error') == 0 and data.get('data'):
                agent_info = data['data']['affected_items'][0]
                self.logger.debug(f"Successfully fetched info for agent {agent_id}")
                self.circuit_breaker.record_success()
                return agent_info
            else:
                self.logger.error(f"Unexpected response structure from Wazuh API: {data}")
                self.circuit_breaker.record_failure()
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching agent {agent_id} from Wazuh API: {e}")
            self.circuit_breaker.record_failure()
            
            # Clear token on auth errors
            if hasattr(e, 'response') and e.response and e.response.status_code in [401, 403]:
                self.jwt_token = None
                self.jwt_expiry = None
                
            return None
            
    def enrich_alert(self, alert_id: int) -> bool:
        """Enrich a single alert with agent information"""
        conn = None
        try:
            conn = psycopg2.connect(PG_DSN)
            with conn.cursor() as cur:
                # Fetch the alert
                cur.execute("""
                    SELECT id, agent_id, state
                    FROM alerts
                    WHERE id = %s
                    FOR UPDATE
                """, (alert_id,))
                
                alert = cur.fetchone()
                if not alert:
                    self.logger.error(f"Alert {alert_id} not found")
                    return False
                    
                alert_id, agent_id, state = alert
                
                # Check if already processed
                if state != 'new':
                    self.logger.info(f"Alert {alert_id} already in state '{state}', skipping")
                    return True  # Not an error, just already processed
                    
                # Fetch agent information
                agent_info = self.fetch_agent_info(agent_id)
                
                # Prepare enriched data
                enriched_data = {
                    'fetch_timestamp': datetime.now(timezone.utc).isoformat(),
                    'fetch_success': agent_info is not None
                }
                
                if agent_info:
                    # Extract key fields for easy access
                    enriched_data.update({
                        'id': agent_info.get('id'),
                        'name': agent_info.get('name'),
                        'ip': agent_info.get('ip'),
                        'status': agent_info.get('status'),
                        'os': agent_info.get('os', {}),
                        'version': agent_info.get('version'),
                        'manager': agent_info.get('manager'),
                        'group': agent_info.get('group', []),
                        'lastKeepAlive': agent_info.get('lastKeepAlive'),
                        'node_name': agent_info.get('node_name')
                    })
                    self.logger.info(f"Enriched alert {alert_id} with agent {agent_id} data")
                else:
                    self.logger.warning(f"Could not fetch agent {agent_id} data for alert {alert_id}")
                    # Still proceed with enrichment to not block the pipeline
                    enriched_data['fetch_error'] = 'Agent information unavailable'
                
                # Update the alert with enriched data
                cur.execute("""
                    UPDATE alerts
                    SET 
                        agent_data = %s,
                        enriched_at = CURRENT_TIMESTAMP,
                        state = 'enriched'
                    WHERE id = %s
                    AND state = 'new'
                """, (json.dumps(enriched_data), alert_id))
                
                if cur.rowcount == 0:
                    self.logger.warning(f"Alert {alert_id} state changed during processing")
                    conn.rollback()
                    return False
                    
                conn.commit()
                
                # The database trigger will automatically send the notification
                self.logger.info(f"Alert {alert_id} enriched and transitioned to 'enriched' state")
                return True
                
        except Exception as e:
            self.logger.error(f"Error enriching alert {alert_id}: {e}", exc_info=True)
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                conn.close()
                
    def run(self):
        """Main loop listening for new alerts"""
        self.logger.info("Starting agent enricher service")
        
        # Test database connection
        try:
            test_conn = psycopg2.connect(PG_DSN)
            test_conn.close()
            self.logger.info("Database connection successful")
        except Exception as e:
            self.logger.critical(f"Cannot connect to database: {e}")
            sys.exit(1)
            
        # Main listening loop
        conn = None
        try:
            conn = psycopg2.connect(PG_DSN)
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            
            with conn.cursor() as cur:
                cur.execute("LISTEN new_alert")
                self.logger.info("Listening for new_alert notifications...")
                
                while True:
                    # Wait for notifications with timeout
                    if select.select([conn], [], [], 5) == ([], [], []):
                        continue  # Timeout, check again
                        
                    conn.poll()
                    while conn.notifies:
                        notify = conn.notifies.pop(0)
                        try:
                            alert_id = int(notify.payload)
                            self.logger.info(f"Processing new alert {alert_id}")
                            
                            success = self.enrich_alert(alert_id)
                            if not success:
                                self.logger.error(f"Failed to enrich alert {alert_id}")
                                
                        except ValueError:
                            self.logger.error(f"Invalid alert ID in notification: {notify.payload}")
                        except Exception as e:
                            self.logger.error(f"Error processing notification: {e}", exc_info=True)
                            
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal, shutting down")
        except Exception as e:
            self.logger.critical(f"Fatal error in main loop: {e}", exc_info=True)
            sys.exit(1)
        finally:
            if conn:
                conn.close()
            self.logger.info("Agent enricher stopped")


def main():
    """Entry point"""
    enricher = AgentEnricher()
    enricher.run()


if __name__ == "__main__":
    main()