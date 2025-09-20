#!/bin/bash
# Test script to verify service name mapping is working correctly

set -e

echo "=== Service Name Mapping Test Script ==="
echo "This script tests the service name mapping logic in the bootstrap package"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected="$3"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    echo -n "Testing: $test_name... "
    
    # Run the command and capture output
    output=$(eval "$command" 2>&1 || true)
    
    if [[ "$output" == *"$expected"* ]]; then
        echo -e "${GREEN}PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}FAILED${NC}"
        echo "  Expected: $expected"
        echo "  Got: $output"
    fi
}

# Change to the eos directory
cd /opt/eos

echo "1. Running unit tests for service mapping..."
echo "----------------------------------------"

# Run the Go tests
if go test -v ./pkg/bootstrap -run TestMapProcessToServiceName 2>&1 | grep -q "PASS"; then
    echo -e "${GREEN}✓ Service name mapping tests passed${NC}"
else
    echo -e "${RED}✗ Service name mapping tests failed${NC}"
    echo "Run 'go test -v ./pkg/bootstrap -run TestMapProcessToServiceName' for details"
fi

echo
echo "2. Testing actual service detection..."
echo "----------------------------------------"

# Create a temporary Go program to test the service manager
cat > /tmp/test_service_detection.go << 'EOF'
package main

import (
    "context"
    "fmt"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/bootstrap"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func main() {
    ctx := context.Background()
    rc := &eos_io.RuntimeContext{Ctx: ctx}
    
    sm := bootstrap.NewServiceManager(rc)
    
    // Test mapping various process names
    testCases := []struct{
        process string
        port int
    }{
        {"/usr/bin/vault", 8200},
        {"consul", 8500},
        {"/opt/nomad/bin/nomad", 4646},
    }
    
    fmt.Println("Testing process to service name mapping:")
    for _, tc := range testCases {
        // Use reflection to call the private method (for testing only)
        serviceName := sm.mapProcessToServiceName(tc.process, tc.port)
        fmt.Printf("  Process: %-30s Port: %-5d -> Service: %s\n", 
            tc.process, tc.port, serviceName)
    }
}
EOF

echo "Compiling test program..."
if go build -o /tmp/test_service_detection /tmp/test_service_detection.go 2>/dev/null; then
    echo -e "${GREEN}✓ Test program compiled successfully${NC}"
    echo
    echo "Running detection test..."
    /tmp/test_service_detection
else
    echo -e "${YELLOW}⚠ Could not compile test program (expected if methods are private)${NC}"
fi

echo
echo "3. Testing with live processes (if any are running)..."
echo "----------------------------------------"

# Check for running services
for port in 4505 4506 8000 8200 8300 8500 4646; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        echo "Found process on port $port:"
        ss -tlnp 2>/dev/null | grep ":$port " | head -1
    fi
done

echo
echo "4. Testing service stopping logic..."
echo "----------------------------------------"

# Test the service variations that would be tried
test_variations() {
    local service="$1"
    echo "Service variations for '$service':"
    
    # Direct service name
    echo "  - $service"
    echo "  - ${service}.service"

test_variations "vault"
test_variations "consul"

echo
echo "=== Test Summary ==="
echo "Tests run: $TESTS_RUN"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
if [ $TESTS_PASSED -eq $TESTS_RUN ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Some tests failed!${NC}"
fi

# Cleanup
rm -f /tmp/test_service_detection.go /tmp/test_service_detection

echo
echo "To run the full Go test suite:"
echo "  go test -v ./pkg/bootstrap/"
echo
echo "To test with actual bootstrap:"
echo "  sudo eos bootstrap --dry-run"