// pkg/bootstrap/setup_salt_api.go

package bootstrap

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// SetupSaltAPI configures and starts the Salt API service for cluster management
func SetupSaltAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Setting up Salt API service")

	// Check if API is already set up and running
	if isAPIAlreadySetup(rc) {
		logger.Info("Salt API is already configured and running")
		return nil
	}

	// ASSESS - Ensure Salt master is running (required for API)
	// For single-node deployments, we may need to start it
	if err := ensureSaltMasterRunning(rc); err != nil {
		return fmt.Errorf("failed to ensure Salt master is running: %w", err)
	}

	// Install Flask and dependencies
	if err := installPythonDependencies(rc); err != nil {
		return fmt.Errorf("failed to install Python dependencies: %w", err)
	}

	// INTERVENE - Create API directories and copy service files
	if err := createAPIDirectories(rc); err != nil {
		return fmt.Errorf("failed to create API directories: %w", err)
	}

	// Create the API script if it doesn't exist
	if err := createAPIScript(rc); err != nil {
		return fmt.Errorf("failed to create API script: %w", err)
	}

	if err := installAPIService(rc); err != nil {
		return fmt.Errorf("failed to install API service: %w", err)
	}

	// Start the API service
	if err := startAPIService(rc); err != nil {
		return fmt.Errorf("failed to start API service: %w", err)
	}

	// EVALUATE - Verify API is responding
	if err := verifyAPIService(rc); err != nil {
		return fmt.Errorf("API service verification failed: %w", err)
	}

	logger.Info("Salt API service setup completed successfully")
	return nil
}


// installPythonDependencies installs required Python packages
func installPythonDependencies(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Python dependencies for Salt API")

	packages := []string{
		"python3-flask",
		"python3-yaml",
		"python3-salt",
	}

	// Install packages using common utility for idempotency
	for _, pkg := range packages {
		if err := InstallPackageIfMissing(rc, pkg); err != nil {
			return fmt.Errorf("failed to install %s: %w", pkg, err)
		}
	}

	logger.Info("Python dependencies installed successfully")
	return nil
}

// createAPIDirectories creates necessary directories for the API service
func createAPIDirectories(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Creating API directories")

	directories := []string{
		"/opt/eos/salt/api",
		"/var/lib/eos",
		"/var/log/eos",
	}

	for _, dir := range directories {
		if err := CreateDirectoryIfMissing(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		logger.Debug("Ensured directory exists", zap.String("directory", dir))
	}

	return nil
}

// installAPIService installs the systemd service for Salt API
func installAPIService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Installing Salt API systemd service")

	// Copy service file to systemd directory
	srcPath := "/opt/eos/salt/api/eos-salt-api.service"
	destPath := "/etc/systemd/system/eos-salt-api.service"

	// Read service file
	content, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read service file: %w", err)
	}

	// Write to systemd directory
	if err := os.WriteFile(destPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// Reload systemd daemon
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"daemon-reload"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	logger.Debug("Salt API service installed")
	return nil
}

// startAPIService starts and enables the Salt API service
func startAPIService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Starting Salt API service")

	// Enable the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"enable", "eos-salt-api.service"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to enable API service: %w", err)
	}

	// Start the service
	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"start", "eos-salt-api.service"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to start API service: %w", err)
	}

	// Wait a moment for service to start
	time.Sleep(3 * time.Second)

	logger.Info("Salt API service started")
	return nil
}

// verifyAPIService verifies the API service is responding
func verifyAPIService(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Verifying Salt API service")

	// First check if the service is active
	status, err := CheckService(rc, "eos-salt-api")
	if err != nil || status != ServiceStatusActive {
		return fmt.Errorf("eos-salt-api service is not active (status: %s)", status)
	}

	// Create API client and test health check with retry
	apiClient := NewSaltAPIClient(rc, "localhost")

	// Use retry logic for API availability
	retryConfig := RetryConfig{
		MaxAttempts:       6,
		InitialDelay:      5 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 1.5,
	}

	err = WithRetry(rc, retryConfig, func() error {
		// Wait for API to respond
		if err := apiClient.WaitForAPI(rc.Ctx, 10*time.Second); err != nil {
			return fmt.Errorf("API not responding: %w", err)
		}

		// Test a simple API call
		_, err := apiClient.GetClusterInfo()
		if err != nil {
			logger.Debug("Cluster info call failed (expected during bootstrap)", zap.Error(err))
			// This is OK - cluster might not be fully configured yet
			// We just need to know the API is responding
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("API verification failed: %w", err)
	}

	logger.Info("Salt API service verification completed")
	return nil
}

// RestartSaltAPI restarts the Salt API service
func RestartSaltAPI(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Restarting Salt API service")

	if _, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"restart", "eos-salt-api.service"},
		Capture: false,
	}); err != nil {
		return fmt.Errorf("failed to restart API service: %w", err)
	}

	// Wait for service to restart
	time.Sleep(3 * time.Second)

	// Verify it's working
	return verifyAPIService(rc)
}

// GetSaltAPIStatus returns the status of the Salt API service
func GetSaltAPIStatus(rc *eos_io.RuntimeContext) (string, error) {
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "systemctl",
		Args:    []string{"is-active", "eos-salt-api.service"},
		Capture: true,
	})

	if err != nil {
		return "unknown", err
	}

	return output, nil
}

// isAPIAlreadySetup checks if the API is already configured and running
func isAPIAlreadySetup(rc *eos_io.RuntimeContext) bool {
	logger := otelzap.Ctx(rc.Ctx)
	
	// Check if service exists
	status, err := CheckService(rc, "eos-salt-api")
	if err != nil || status != ServiceStatusActive {
		logger.Debug("Salt API service not active", zap.String("status", string(status)))
		return false
	}
	
	// Check if API script exists
	if _, err := os.Stat("/opt/eos/salt/api/cluster_api.py"); os.IsNotExist(err) {
		logger.Debug("Salt API script not found")
		return false
	}
	
	// Check if API responds
	output, err := execute.Run(rc.Ctx, execute.Options{
		Command: "curl",
		Args:    []string{"-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:5000/health"},
		Capture: true,
		Timeout: 5 * time.Second,
	})
	
	if err == nil && strings.TrimSpace(output) == "200" {
		logger.Debug("Salt API is responding")
		return true
	}
	
	return false
}

// createAPIScript creates the Salt API Python script if it doesn't exist
func createAPIScript(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	scriptPath := "/opt/eos/salt/api/cluster_api.py"
	
	// Check if script already exists
	if _, err := os.Stat(scriptPath); err == nil {
		logger.Debug("API script already exists", zap.String("path", scriptPath))
		return nil
	}
	
	// Ensure /etc/eos directory exists for API key storage
	if err := CreateDirectoryIfMissing("/etc/eos", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/eos directory: %w", err)
	}
	
	logger.Info("Creating production-grade Salt API script")
	
	// Create a production-grade API with enhanced security
	productionAPI := `#!/usr/bin/env python3
"""Production-grade Salt API with enhanced security features"""

import os
import sys
import time
import hashlib
import secrets
import logging
import jwt
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict
from flask import Flask, jsonify, request, Response, g

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/eos/salt-api.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('eos-salt-api')

app = Flask(__name__)

# Security configuration
API_KEY = os.environ.get('EOS_SALT_API_KEY', secrets.token_urlsafe(32))
JWT_SECRET = os.environ.get('EOS_JWT_SECRET', secrets.token_urlsafe(64))
RATE_LIMIT = int(os.environ.get('EOS_API_RATE_LIMIT', '100'))  # requests per minute
TOKEN_EXPIRY = int(os.environ.get('EOS_TOKEN_EXPIRY_HOURS', '24'))

# Rate limiting storage
request_counts = defaultdict(list)
failed_auth_attempts = defaultdict(list)

# Write API key and JWT secret to secure files
try:
    os.makedirs('/etc/eos', exist_ok=True)
    
    with open('/etc/eos/salt-api.key', 'w') as f:
        f.write(API_KEY)
    os.chmod('/etc/eos/salt-api.key', 0o600)
    
    with open('/etc/eos/salt-api.jwt', 'w') as f:
        f.write(JWT_SECRET)
    os.chmod('/etc/eos/salt-api.jwt', 0o600)
    
    logger.info("API security files created successfully")
except Exception as e:
    logger.error(f"Failed to create security files: {e}")
    sys.exit(1)

def get_client_ip():
    """Get the real client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def check_rate_limit(client_ip, limit=RATE_LIMIT):
    """Check if client is within rate limits"""
    now = time.time()
    minute_ago = now - 60
    
    # Clean old entries
    request_counts[client_ip] = [req_time for req_time in request_counts[client_ip] if req_time > minute_ago]
    
    # Check limit
    if len(request_counts[client_ip]) >= limit:
        return False
    
    # Record this request
    request_counts[client_ip].append(now)
    return True

def check_failed_attempts(client_ip, max_attempts=5):
    """Check if client has too many failed auth attempts"""
    now = time.time()
    hour_ago = now - 3600
    
    # Clean old entries
    failed_auth_attempts[client_ip] = [attempt_time for attempt_time in failed_auth_attempts[client_ip] if attempt_time > hour_ago]
    
    return len(failed_auth_attempts[client_ip]) < max_attempts

def record_failed_attempt(client_ip):
    """Record a failed authentication attempt"""
    failed_auth_attempts[client_ip].append(time.time())

def validate_api_key(provided_key):
    """Validate API key with timing attack protection"""
    if not provided_key:
        return False
    
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(provided_key, API_KEY)

def validate_jwt_token(token):
    """Validate JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid JWT token")
        return None

def require_authentication(f):
    """Enhanced authentication decorator with multiple auth methods"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        g.client_ip = client_ip
        
        # Rate limiting
        if not check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return Response('Rate limit exceeded', 429)
        
        # Check failed attempts
        if not check_failed_attempts(client_ip):
            logger.warning(f"Too many failed attempts from {client_ip}")
            return Response('Too many failed attempts', 429)
        
        # Try JWT token first
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            payload = validate_jwt_token(token)
            if payload:
                g.user_id = payload.get('user_id')
                g.auth_method = 'jwt'
                logger.info(f"Authenticated request from {client_ip} via JWT")
                return f(*args, **kwargs)
        
        # Fall back to API key
        api_key = request.headers.get('X-API-Key')
        if validate_api_key(api_key):
            g.user_id = 'api_key_user'
            g.auth_method = 'api_key'
            logger.info(f"Authenticated request from {client_ip} via API key")
            return f(*args, **kwargs)
        
        # Authentication failed
        record_failed_attempt(client_ip)
        logger.warning(f"Authentication failed for {client_ip}")
        return Response('Unauthorized', 401)
    
    return decorated_function

@app.before_request
def before_request():
    """Log all requests"""
    client_ip = get_client_ip()
    logger.info(f"Request: {request.method} {request.path} from {client_ip}")

@app.after_request
def after_request(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Server'] = 'EOS-Salt-API'
    return response

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint - no auth required"""
    return jsonify({
        'status': 'healthy', 
        'service': 'eos-salt-api',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/auth/token', methods=['POST'])
def get_token():
    """Get JWT token using API key"""
    client_ip = get_client_ip()
    
    if not check_rate_limit(client_ip, limit=10):  # Stricter limit for auth endpoint
        return Response('Rate limit exceeded', 429)
    
    if not check_failed_attempts(client_ip):
        return Response('Too many failed attempts', 429)
    
    api_key = request.headers.get('X-API-Key')
    if not validate_api_key(api_key):
        record_failed_attempt(client_ip)
        return Response('Invalid API key', 401)
    
    # Generate JWT token
    payload = {
        'user_id': 'eos_user',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY)
    }
    
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    logger.info(f"JWT token issued to {client_ip}")
    return jsonify({
        'token': token,
        'expires_in': TOKEN_EXPIRY * 3600,
        'token_type': 'Bearer'
    })

@app.route('/cluster/info', methods=['GET'])
@require_authentication
def cluster_info():
    """Basic cluster info endpoint - requires authentication"""
    return jsonify({
        'cluster_id': 'standalone',
        'nodes': 1,
        'status': 'active',
        'authenticated_as': g.get('user_id'),
        'auth_method': g.get('auth_method')
    })

@app.route('/cluster/nodes', methods=['GET'])
@require_authentication
def cluster_nodes():
    """Get cluster nodes - requires authentication"""
    return jsonify({
        'nodes': [],
        'total': 0,
        'timestamp': datetime.utcnow().isoformat()
    })

if __name__ == '__main__':
    logger.info(f"Starting EOS Salt API with enhanced security")
    logger.info(f"Rate limit: {RATE_LIMIT} requests/minute")
    logger.info(f"Token expiry: {TOKEN_EXPIRY} hours")
    
    # Don't print API key in production logs
    if os.environ.get('EOS_DEBUG') == 'true':
        print(f"API Key: {API_KEY}")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
`
	
	if err := os.WriteFile(scriptPath, []byte(productionAPI), 0755); err != nil {
		return fmt.Errorf("failed to create API script: %w", err)
	}
	
	return nil
}

// ensureSaltMasterRunning ensures Salt master service is running, starting it if necessary
func ensureSaltMasterRunning(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info("Ensuring Salt master service is running")

	// Use common utility to check and ensure service is running
	status, err := CheckService(rc, "salt-master")
	if err == nil && status == ServiceStatusActive {
		logger.Debug("Salt master is already running")
		return nil
	}

	// Check if salt-master package is installed
	installed, err := CheckPackageInstalled(rc, "salt-master")
	if err != nil {
		return fmt.Errorf("failed to check salt-master package: %w", err)
	}

	if !installed {
		logger.Info("Salt master not installed, installing it")
		if err := InstallPackageIfMissing(rc, "salt-master"); err != nil {
			return fmt.Errorf("failed to install salt-master: %w", err)
		}
	}

	// Use common utility to ensure service is running with retry
	return EnsureService(rc, "salt-master")
}
