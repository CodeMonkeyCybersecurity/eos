package hecate

import (
	"context"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hashicorp/consul/api"
	"github.com/stretchr/testify/assert"
)

func TestDNSErrorHandling(t *testing.T) {
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create a mock client for testing
	client := &HecateClient{rc: rc}
	dnsManager := NewDNSManager(client)

	t.Run("InputValidation", func(t *testing.T) {
		// Test invalid domain validation
		err := dnsManager.CreateDNSRecord(context.Background(), "", "1.2.3.4")
		assert.Error(t, err, "Empty domain should fail validation")
		assert.Contains(t, err.Error(), "invalid domain")

		// Test invalid IP validation
		err = dnsManager.CreateDNSRecord(context.Background(), "test.example.com", "256.256.256.256")
		assert.Error(t, err, "Invalid IP should fail validation")
		assert.Contains(t, err.Error(), "invalid target IP")

		// Test invalid domain in delete
		err = dnsManager.DeleteDNSRecord(context.Background(), "invalid..domain")
		assert.Error(t, err, "Invalid domain should fail validation")
		assert.Contains(t, err.Error(), "invalid domain")
	})

	t.Run("PreconditionValidation", func(t *testing.T) {
		// Test with nil clients (simulating unavailable services)
		emptyClient := &HecateClient{rc: rc} // No  or consul clients
		emptyDNSManager := NewDNSManager(emptyClient)

		err := emptyDNSManager.validateDNSOperationPreconditions(context.Background())
		assert.Error(t, err, "Missing clients should fail preconditions")
		assert.Contains(t, err.Error(), "client not available")

		// Test with cancelled context using a client that has the required services
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		// Create a client with minimal required services for this test
		clientWithServices := &HecateClient{
			rc:     rc,
			consul: &api.Client{}, // Minimal mock
		}
		dnsManagerWithServices := NewDNSManager(clientWithServices)

		err = dnsManagerWithServices.validateDNSOperationPreconditions(cancelledCtx)
		assert.Error(t, err, "Cancelled context should fail preconditions")
		assert.Contains(t, err.Error(), "context cancelled")
	})

	t.Run("RetryMechanism", func(t *testing.T) {
		// Test retry operation structure
		retryCount := 0
		maxRetries := 3

		err := dnsManager.retryDNSOperation(context.Background(), "test", func() error {
			retryCount++
			if retryCount < maxRetries {
				return assert.AnError // Simulate failure
			}
			return nil // Success on final attempt
		})

		assert.NoError(t, err, "Operation should succeed on final retry")
		assert.Equal(t, maxRetries, retryCount, "Should have retried the expected number of times")
	})

	t.Run("RetryWithFailure", func(t *testing.T) {
		// Test retry operation that always fails
		retryCount := 0

		err := dnsManager.retryDNSOperation(context.Background(), "test", func() error {
			retryCount++
			return assert.AnError // Always fail
		})

		assert.Error(t, err, "Operation should fail after all retries")
		assert.Equal(t, 3, retryCount, "Should have attempted all retries")
		assert.Contains(t, err.Error(), "failed after 3 attempts")
	})

	t.Run("RetryWithCancellation", func(t *testing.T) {
		// Test retry operation with context cancellation
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		err := dnsManager.retryDNSOperation(ctx, "test", func() error {
			time.Sleep(20 * time.Millisecond) // Sleep longer than context timeout
			return assert.AnError
		})

		assert.Error(t, err, "Operation should fail due to context cancellation")
		assert.Equal(t, context.DeadlineExceeded, err)
	})

	t.Run("ValidationFunctions", func(t *testing.T) {
		// Test all validation functions work properly
		validDomains := []string{
			"example.com",
			"sub.example.com",
			"test-domain.example.org",
		}

		invalidDomains := []string{
			"",
			"invalid..domain",
			"domain-with-;-semicolon.com",
			"domain.with.spaces .com",
		}

		for _, domain := range validDomains {
			err := ValidateDomain(domain)
			assert.NoError(t, err, "Valid domain should pass: %s", domain)
		}

		for _, domain := range invalidDomains {
			err := ValidateDomain(domain)
			assert.Error(t, err, "Invalid domain should fail: %s", domain)
		}

		validIPs := []string{
			"1.2.3.4",
			"192.168.1.1",
			"10.0.0.1",
		}

		invalidIPs := []string{
			"",
			"256.256.256.256",
			"not.an.ip",
			"1.2.3.4; rm -rf /",
		}

		for _, ip := range validIPs {
			err := ValidateIPAddress(ip)
			assert.NoError(t, err, "Valid IP should pass: %s", ip)
		}

		for _, ip := range invalidIPs {
			err := ValidateIPAddress(ip)
			assert.Error(t, err, "Invalid IP should fail: %s", ip)
		}
	})
}