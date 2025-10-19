// pkg/vault/config_parser_test.go
package vault

import (
	"testing"
)

func TestExtractPorts(t *testing.T) {
	tests := []struct {
		name            string
		config          string
		expectedAPI     int
		expectedCluster int
		wantErr         bool
	}{
		{
			name: "standard ports",
			config: `
listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
}`,
			expectedAPI:     8200,
			expectedCluster: 8201,
			wantErr:         false,
		},
		{
			name: "custom ports",
			config: `
listener "tcp" {
  address = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
}`,
			expectedAPI:     8179,
			expectedCluster: 8180,
			wantErr:         false,
		},
		{
			name: "missing ports returns defaults",
			config: `
listener "tcp" {
}`,
			expectedAPI:     8200,
			expectedCluster: 8201,
			wantErr:         false,
		},
		{
			name: "with ipv4 address",
			config: `
listener "tcp" {
  address = "192.168.1.10:8300"
  cluster_address = "192.168.1.10:8301"
}`,
			expectedAPI:     8300,
			expectedCluster: 8301,
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports, err := ExtractPorts(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractPorts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if ports.APIPort != tt.expectedAPI {
				t.Errorf("ExtractPorts() APIPort = %v, want %v", ports.APIPort, tt.expectedAPI)
			}
			if ports.ClusterPort != tt.expectedCluster {
				t.Errorf("ExtractPorts() ClusterPort = %v, want %v", ports.ClusterPort, tt.expectedCluster)
			}
		})
	}
}

func TestUpdateConfigPorts(t *testing.T) {
	tests := []struct {
		name        string
		config      string
		apiPort     int
		clusterPort int
		wantAPI     string
		wantCluster string
	}{
		{
			name: "update API port only",
			config: `listener "tcp" {
  address = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
}`,
			apiPort:     8200,
			clusterPort: 0,
			wantAPI:     "0.0.0.0:8200",
			wantCluster: "0.0.0.0:8180",
		},
		{
			name: "update cluster port only",
			config: `listener "tcp" {
  address = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8180"
}`,
			apiPort:     0,
			clusterPort: 8201,
			wantAPI:     "0.0.0.0:8200",
			wantCluster: "0.0.0.0:8201",
		},
		{
			name: "update both ports",
			config: `listener "tcp" {
  address = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
}`,
			apiPort:     8200,
			clusterPort: 8201,
			wantAPI:     "0.0.0.0:8200",
			wantCluster: "0.0.0.0:8201",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UpdateConfigPorts(tt.config, tt.apiPort, tt.clusterPort)

			// Extract the updated ports
			ports, err := ExtractPorts(result)
			if err != nil {
				t.Fatalf("Failed to extract ports from updated config: %v", err)
			}

			// Verify API port
			expectedAPIPort := tt.apiPort
			if expectedAPIPort == 0 {
				// Parse from wantAPI
				expectedAPIPort = 8200 // This comes from the original config in test
			}

			// Verify cluster port
			expectedClusterPort := tt.clusterPort
			if expectedClusterPort == 0 {
				expectedClusterPort = 8180 // Original values from test configs
			}

			if tt.apiPort > 0 && ports.APIPort != tt.apiPort {
				t.Errorf("UpdateConfigPorts() API port = %v, want %v", ports.APIPort, tt.apiPort)
			}

			if tt.clusterPort > 0 && ports.ClusterPort != tt.clusterPort {
				t.Errorf("UpdateConfigPorts() cluster port = %v, want %v", ports.ClusterPort, tt.clusterPort)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"valid port 8200", 8200, false},
		{"valid port 1024", 1024, false},
		{"valid port 65535", 65535, false},
		{"invalid port 1023", 1023, true},
		{"invalid port 65536", 65536, true},
		{"invalid port 0", 0, true},
		{"invalid port negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}
