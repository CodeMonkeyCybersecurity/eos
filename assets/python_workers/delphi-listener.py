#!/usr/bin/env python3
# /usr/local/bin/delphi-listener.py
"""
Production-ready HTTP webhook listener for Wazuh alerts.

This service acts as the entry point for the Delphi security alert pipeline,
receiving webhooks from Wazuh and initiating alert processing.

Features:
- Secure request authentication via X-Auth-Token
- Request size and timeout limits
- Proper error handling with appropriate HTTP status codes
- Structured logging with request correlation
- Health check endpoint for monitoring
- Graceful shutdown handling
- Metrics collection ready
"""

import json
import logging
import subprocess
import os
import sys
import signal
import time
import uuid
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from contextlib import contextmanager
from functools import wraps

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(*args, **kwargs):
        pass

# Configuration
ENV_PATH = Path("/opt/stackstorm/packs/delphi/.env")
load_dotenv(ENV_PATH)

# Paths and settings
LOG_PATH = "/var/log/stackstorm/delphi-listener.log"
RAW_LOG_PATH = "/var/log/stackstorm/delphi-alerts.log"
ALERT_LOADER = "/usr/local/bin/alert-to-db.py"
PORT = int(os.getenv("WEBHOOK_PORT", "9101"))
BIND_ADDRESS = os.getenv("WEBHOOK_BIND_ADDRESS", "0.0.0.0")

# Security settings
WEBHOOK_AUTH_TOKEN = os.getenv("WEBHOOK_AUTH_TOKEN")
MAX_REQUEST_SIZE = int(os.getenv("WEBHOOK_MAX_REQUEST_SIZE", str(10 * 1024 * 1024)))  # 10MB default
REQUEST_TIMEOUT = int(os.getenv("WEBHOOK_REQUEST_TIMEOUT", "30"))  # 30 seconds default
MIN_ALERT_LEVEL = int(os.getenv("WEBHOOK_MIN_ALERT_LEVEL", "3"))  # Minimum level to process

# Subprocess settings
SUBPROCESS_TIMEOUT = int(os.getenv("ALERT_PROCESSOR_TIMEOUT", "10"))  # 10 seconds default

# Global state for graceful shutdown
shutdown_event = threading.Event()
active_requests = threading.Semaphore(100)  # Limit concurrent requests


class StructuredLogger:
    """Provides structured logging with request correlation"""
    
    def __init__(self, name: str, log_file: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create formatter with structured output
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Also log to stdout for container environments
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)
        self.logger.addHandler(stdout_handler)
    
    def get_adapter(self, request_id: str) -> logging.LoggerAdapter:
        """Get a logger adapter with request ID context"""
        return logging.LoggerAdapter(self.logger, {'request_id': request_id})


# Initialize logger
structured_logger = StructuredLogger("delphi-listener", LOG_PATH)
log = structured_logger.get_adapter("startup")


class RequestMetrics:
    """Collects metrics for monitoring and alerting"""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.requests_total = 0
        self.requests_success = 0
        self.requests_failed = 0
        self.requests_rejected = 0
        self.processing_times = []
        self.last_reset = time.time()
    
    def record_request(self, success: bool, rejected: bool = False, duration: float = 0):
        """Record metrics for a request"""
        with self.lock:
            self.requests_total += 1
            if rejected:
                self.requests_rejected += 1
            elif success:
                self.requests_success += 1
            else:
                self.requests_failed += 1
            
            if duration > 0:
                self.processing_times.append(duration)
                # Keep only last 1000 measurements to prevent memory growth
                if len(self.processing_times) > 1000:
                    self.processing_times.pop(0)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics"""
        with self.lock:
            uptime = time.time() - self.last_reset
            avg_duration = sum(self.processing_times) / len(self.processing_times) if self.processing_times else 0
            
            return {
                "uptime_seconds": uptime,
                "requests_total": self.requests_total,
                "requests_success": self.requests_success,
                "requests_failed": self.requests_failed,
                "requests_rejected": self.requests_rejected,
                "success_rate": self.requests_success / self.requests_total if self.requests_total > 0 else 0,
                "avg_processing_time": avg_duration,
                "active_requests": 100 - active_requests._value  # Semaphore tracking
            }


# Global metrics instance
metrics = RequestMetrics()


def validate_alert_structure(alert: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Validate that the alert has the expected structure.
    
    This provides an early validation layer before passing to alert-to-db.py,
    helping catch malformed requests quickly.
    """
    if not isinstance(alert, dict):
        return False, "Alert must be a JSON object"
    
    # Check required top-level fields
    if "rule" not in alert:
        return False, "Missing required field: rule"
    
    if "agent" not in alert:
        return False, "Missing required field: agent"
    
    # Validate rule structure
    rule = alert.get("rule", {})
    if not isinstance(rule, dict):
        return False, "Field 'rule' must be an object"
    
    if "level" not in rule:
        return False, "Missing required field: rule.level"
    
    if "id" not in rule:
        return False, "Missing required field: rule.id"
    
    # Validate agent structure
    agent = alert.get("agent", {})
    if not isinstance(agent, dict):
        return False, "Field 'agent' must be an object"
    
    if "id" not in agent:
        return False, "Missing required field: agent.id"
    
    return True, None


class AlertHandler(BaseHTTPRequestHandler):
    """Handles incoming webhook requests"""
    
    def __init__(self, *args, **kwargs):
        # Generate unique request ID for tracking
        self.request_id = str(uuid.uuid4())[:8]
        self.logger = structured_logger.get_adapter(self.request_id)
        self.start_time = time.time()
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle POST requests to /wazuh_alert endpoint"""
        if not active_requests.acquire(blocking=False):
            self.logger.warning("Server overloaded - rejecting request")
            self.send_error(503, "Service temporarily unavailable")
            metrics.record_request(success=False, rejected=True)
            return
        
        try:
            self._handle_alert_post()
        finally:
            active_requests.release()
    
    def _handle_alert_post(self):
        """Core logic for handling alert posts"""
        # Check if we're shutting down
        if shutdown_event.is_set():
            self.send_error(503, "Service shutting down")
            metrics.record_request(success=False, rejected=True)
            return
        
        # Validate endpoint
        if self.path != "/wazuh_alert":
            self.logger.info(f"404 Not Found: {self.path}")
            self.send_error(404, "Not Found")
            metrics.record_request(success=False, rejected=True)
            return
        
        # Validate authentication
        if not self._validate_auth():
            metrics.record_request(success=False, rejected=True)
            return
        
        # Read and validate request body
        alert_data = self._read_request_body()
        if alert_data is None:
            metrics.record_request(success=False, rejected=True)
            return
        
        # Process the alert
        success = self._process_alert(alert_data)
        
        # Record metrics
        duration = time.time() - self.start_time
        metrics.record_request(success=success, duration=duration)
        
        # Send appropriate response
        if success:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK\n")
        else:
            self.send_error(500, "Internal server error - alert processing failed")
    
    def do_GET(self):
        """Handle GET requests for health checks"""
        if self.path == "/health":
            self._handle_health_check()
        elif self.path == "/metrics":
            self._handle_metrics()
        else:
            self.send_error(404, "Not Found")
    
    def _validate_auth(self) -> bool:
        """Validate request authentication"""
        provided_token = self.headers.get("X-Auth-Token")
        
        if not provided_token:
            self.logger.warning(f"Missing X-Auth-Token from {self.client_address[0]}")
            self.send_error(401, "Missing authentication token")
            return False
        
        if provided_token != WEBHOOK_AUTH_TOKEN:
            self.logger.warning(f"Invalid X-Auth-Token from {self.client_address[0]}")
            self.send_error(401, "Invalid authentication token")
            return False
        
        return True
    
    def _read_request_body(self) -> Optional[Dict[str, Any]]:
        """Read and parse request body with size limits"""
        # Check content length
        content_length = int(self.headers.get("Content-Length", 0))
        
        if content_length == 0:
            self.logger.warning("Empty request body")
            self.send_error(400, "Empty request body")
            return None
        
        if content_length > MAX_REQUEST_SIZE:
            self.logger.warning(f"Request too large: {content_length} bytes")
            self.send_error(413, f"Request too large (max {MAX_REQUEST_SIZE} bytes)")
            return None
        
        # Read body
        try:
            body_bytes = self.rfile.read(content_length)
            alert_data = json.loads(body_bytes)
        except json.JSONDecodeError as e:
            self.logger.warning(f"Invalid JSON: {e}")
            self.send_error(400, "Invalid JSON")
            return None
        except Exception as e:
            self.logger.error(f"Error reading request: {e}")
            self.send_error(400, "Error reading request")
            return None
        
        return alert_data
    
    def _process_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Process a valid alert through the pipeline"""
        # Validate alert structure
        is_valid, error_msg = validate_alert_structure(alert_data)
        if not is_valid:
            self.logger.warning(f"Invalid alert structure: {error_msg}")
            self.send_error(400, f"Invalid alert: {error_msg}")
            return False
        
        # Check alert level
        rule_level = alert_data.get("rule", {}).get("level", 0)
        try:
            rule_level = int(rule_level)
        except (ValueError, TypeError):
            self.logger.warning(f"Invalid rule level: {rule_level}")
            self.send_error(400, "Invalid rule level")
            return False
        
        if rule_level < MIN_ALERT_LEVEL:
            self.logger.info(f"Ignoring low-level alert (level {rule_level})")
            # Return success but don't process - this is intentional filtering
            return True
        
        # Log alert details
        agent_id = alert_data.get("agent", {}).get("id", "unknown")
        rule_id = alert_data.get("rule", {}).get("id", "unknown")
        self.logger.info(f"Processing alert: agent={agent_id}, rule={rule_id}, level={rule_level}")
        
        # Store raw alert
        if not self._store_raw_alert(alert_data):
            # Log but don't fail the request if raw storage fails
            self.logger.error("Failed to store raw alert")
        
        # Process through pipeline
        return self._execute_alert_processor(alert_data)
    
    def _store_raw_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Store raw alert to log file for audit trail"""
        try:
            with open(RAW_LOG_PATH, "a", encoding="utf-8") as f:
                # Add metadata to the raw log
                log_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "request_id": self.request_id,
                    "source_ip": self.client_address[0],
                    "alert": alert_data
                }
                f.write(json.dumps(log_entry, separators=(",", ":")) + "\n")
            return True
        except Exception as e:
            self.logger.error(f"Failed to write raw alert log: {e}")
            return False
    
    def _execute_alert_processor(self, alert_data: Dict[str, Any]) -> bool:
        """Execute alert-to-db.py subprocess with timeout and error handling"""
        try:
            # Serialize alert data
            alert_json = json.dumps(alert_data)
            
            # Run subprocess with timeout
            result = subprocess.run(
                [ALERT_LOADER],
                input=alert_json,
                text=True,
                capture_output=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=True
            )
            
            self.logger.info(f"Alert successfully processed by {ALERT_LOADER}")
            return True
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Alert processor timed out after {SUBPROCESS_TIMEOUT}s")
            return False
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Alert processor failed with code {e.returncode}: {e.stderr}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error running alert processor: {e}")
            return False
    
    def _handle_health_check(self):
        """Handle health check endpoint"""
        # Basic health check - could be enhanced to check dependencies
        health_status = {
            "status": "healthy" if not shutdown_event.is_set() else "shutting_down",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "1.0.0"
        }
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(health_status).encode())
    
    def _handle_metrics(self):
        """Handle metrics endpoint"""
        stats = metrics.get_stats()
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(stats, indent=2).encode())
    
    def log_message(self, format, *args):
        """Override to suppress default access logging"""
        # We do our own structured logging
        return


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP server for handling concurrent requests"""
    daemon_threads = True
    
    def handle_error(self, request, client_address):
        """Override to log errors properly"""
        log.error(f"Exception handling request from {client_address}", exc_info=True)


def handle_shutdown(signum, frame):
    """Handle graceful shutdown on SIGTERM/SIGINT"""
    log.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()
    
    # Wait for active requests to complete (with timeout)
    wait_time = 0
    while active_requests._value < 100 and wait_time < 30:
        time.sleep(0.5)
        wait_time += 0.5
    
    log.info("Shutdown complete")
    sys.exit(0)


def main():
    """Main entry point"""
    # Validate configuration
    if not WEBHOOK_AUTH_TOKEN:
        log.error("WEBHOOK_AUTH_TOKEN not set - authentication is REQUIRED")
        sys.exit(1)
    
    # Ensure required directories exist
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(RAW_LOG_PATH), exist_ok=True)
    
    # Verify alert processor exists and is executable
    if not os.path.isfile(ALERT_LOADER):
        log.error(f"Alert processor not found: {ALERT_LOADER}")
        sys.exit(1)
    
    if not os.access(ALERT_LOADER, os.X_OK):
        log.error(f"Alert processor not executable: {ALERT_LOADER}")
        sys.exit(1)
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)
    
    # Start server
    log.info(f"Starting Delphi webhook listener on {BIND_ADDRESS}:{PORT}")
    log.info(f"Configuration: min_level={MIN_ALERT_LEVEL}, max_size={MAX_REQUEST_SIZE}, timeout={REQUEST_TIMEOUT}s")
    
    try:
        server = ThreadedHTTPServer((BIND_ADDRESS, PORT), AlertHandler)
        server.serve_forever()
    except Exception as e:
        log.error(f"Server failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()