package saltstack

import (
	"context"
	"testing"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
)

func TestValidateSaltPingOutput(t *testing.T) {
	logger := otelzap.Ctx(context.Background())

	tests := []struct {
		name    string
		output  string
		wantErr bool
	}{
		{
			name:    "YAML format success",
			output:  "local:\n    True",
			wantErr: false,
		},
		{
			name:    "JSON format success",
			output:  `{"local": true}`,
			wantErr: false,
		},
		{
			name:    "Simple format success",
			output:  "True",
			wantErr: false,
		},
		{
			name:    "Empty output",
			output:  "",
			wantErr: true,
		},
		{
			name:    "False result",
			output:  "local:\n    False",
			wantErr: true,
		},
		{
			name:    "Invalid JSON",
			output:  `{"local": false}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSaltPingOutput(tt.output, logger)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSaltPingOutput() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}