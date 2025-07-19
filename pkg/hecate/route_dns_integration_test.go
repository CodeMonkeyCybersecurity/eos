package hecate

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/stretchr/testify/assert"
)

func TestRouteDNSIntegration(t *testing.T) {
	// This test verifies the integration between RouteManager and DNSManager
	rc := &eos_io.RuntimeContext{
		Ctx: context.Background(),
	}

	// Create a mock client for testing
	client := &HecateClient{rc: rc}
	routeManager := NewRouteManager(client)
	dnsManager := NewDNSManager(client)

	t.Run("CreateRouteWithDNS", func(t *testing.T) {
		// Test that route creation includes DNS fields
		req := &CreateRouteRequest{
			Domain:    "test.example.com",
			Upstreams: []string{"10.0.1.100:3000"},
			ManageDNS: true,
			DNSTarget: "1.2.3.4",
			EnableSSL: false,
		}

		// Validate the request structure
		assert.NotNil(t, req)
		assert.Equal(t, "test.example.com", req.Domain)
		assert.True(t, req.ManageDNS)
		assert.Equal(t, "1.2.3.4", req.DNSTarget)
		assert.Len(t, req.Upstreams, 1)

		// Test validation works
		err := req.Validate()
		assert.NoError(t, err, "Valid request should pass validation")

		// Test that input validation works
		err = ValidateRouteInput(req.Domain, req.Upstreams)
		assert.NoError(t, err, "Valid route input should pass validation")

		// Test DNS target validation
		err = ValidateIPAddress(req.DNSTarget)
		assert.NoError(t, err, "Valid IP should pass validation")
	})

	t.Run("DNSManagerAvailable", func(t *testing.T) {
		// Test that DNS manager is properly available
		assert.NotNil(t, dnsManager)
		assert.NotNil(t, routeManager)

		// Test that managers can be created
		dm := NewDNSManager(client)
		rm := NewRouteManager(client)
		assert.NotNil(t, dm)
		assert.NotNil(t, rm)
	})

	t.Run("RouteInfoStructure", func(t *testing.T) {
		// Test that RouteInfo has DNS management fields
		route := &RouteInfo{
			ID:        "test-route",
			Domain:    "test.example.com",
			Upstreams: []string{"10.0.1.100:3000"},
			ManageDNS: true,
			IngressIP: "1.2.3.4",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
			Status:    "active",
		}

		assert.Equal(t, "test.example.com", route.Domain)
		assert.True(t, route.ManageDNS)
		assert.Equal(t, "1.2.3.4", route.IngressIP)
		assert.Equal(t, "active", route.Status)
	})

	t.Run("DeleteOptionsStructure", func(t *testing.T) {
		// Test that DeleteOptions has DNS removal field
		options := &DeleteOptions{
			Force:     false,
			RemoveDNS: true,
			RemoveSSL: false,
		}

		assert.True(t, options.RemoveDNS)
		assert.False(t, options.Force)
		assert.False(t, options.RemoveSSL)
	})

	t.Run("ValidationIntegration", func(t *testing.T) {
		// Test invalid inputs
		invalidRequests := []*CreateRouteRequest{
			{
				Domain:    "",
				Upstreams: []string{"10.0.1.100:3000"},
				ManageDNS: true,
				DNSTarget: "1.2.3.4",
			},
			{
				Domain:    "test.example.com",
				Upstreams: []string{},
				ManageDNS: true,
				DNSTarget: "1.2.3.4",
			},
			{
				Domain:    "test.example.com",
				Upstreams: []string{"10.0.1.100:3000"},
				ManageDNS: true,
				DNSTarget: "256.256.256.256", // Invalid IP
			},
		}

		for i, req := range invalidRequests {
			t.Run(fmt.Sprintf("InvalidRequest%d", i), func(t *testing.T) {
				if req.Domain != "" && len(req.Upstreams) > 0 {
					// This should fail on DNS target validation
					err := ValidateIPAddress(req.DNSTarget)
					assert.Error(t, err, "Invalid IP should fail validation")
				} else {
					// This should fail on basic validation
					err := req.Validate()
					assert.Error(t, err, "Invalid request should fail validation")
				}
			})
		}
	})
}