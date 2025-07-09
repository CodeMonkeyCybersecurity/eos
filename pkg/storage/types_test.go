package storage

import (
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int64
		wantErr bool
	}{
		{
			name:    "parse 10GB",
			input:   "10G",
			want:    10 * 1024 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "parse 100MB - should fail (below minimum)",
			input:   "100M",
			want:    0,
			wantErr: true,
		},
		{
			name:    "parse 1TB",
			input:   "1T",
			want:    1024 * 1024 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "parse with lowercase",
			input:   "5g",
			want:    5 * 1024 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "parse with spaces",
			input:   " 10 G ",
			want:    10 * 1024 * 1024 * 1024,
			wantErr: false,
		},
		{
			name:    "invalid format",
			input:   "abc",
			want:    0,
			wantErr: true,
		},
		{
			name:    "too small",
			input:   "1B",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHealthStatusFromUsage(t *testing.T) {
	tests := []struct {
		name  string
		usage float64
		want  HealthStatus
	}{
		{
			name:  "good usage",
			usage: 50.0,
			want:  HealthGood,
		},
		{
			name:  "warning threshold",
			usage: 75.0,
			want:  HealthDegraded,
		},
		{
			name:  "critical threshold",
			usage: 90.0,
			want:  HealthCritical,
		},
		{
			name:  "edge case warning",
			usage: WarningThreshold,
			want:  HealthDegraded,
		},
		{
			name:  "edge case critical",
			usage: CriticalThreshold,
			want:  HealthCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HealthStatusFromUsage(tt.usage); got != tt.want {
				t.Errorf("HealthStatusFromUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{
			name:  "format bytes",
			bytes: 512,
			want:  "512 bytes",
		},
		{
			name:  "format KB",
			bytes: 1024,
			want:  "1.00 KB",
		},
		{
			name:  "format MB",
			bytes: 1024 * 1024,
			want:  "1.00 MB",
		},
		{
			name:  "format GB",
			bytes: 10 * 1024 * 1024 * 1024,
			want:  "10.00 GB",
		},
		{
			name:  "format TB",
			bytes: 1024 * 1024 * 1024 * 1024,
			want:  "1.00 TB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatSize(tt.bytes); got != tt.want {
				t.Errorf("FormatSize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidFilesystem(t *testing.T) {
	tests := []struct {
		name string
		fs   FilesystemType
		want bool
	}{
		{
			name: "valid ext4",
			fs:   FilesystemExt4,
			want: true,
		},
		{
			name: "valid xfs",
			fs:   FilesystemXFS,
			want: true,
		},
		{
			name: "valid btrfs",
			fs:   FilesystemBTRFS,
			want: true,
		},
		{
			name: "valid zfs",
			fs:   FilesystemZFS,
			want: true,
		},
		{
			name: "invalid filesystem",
			fs:   FilesystemType("invalid"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidFilesystem(tt.fs); got != tt.want {
				t.Errorf("IsValidFilesystem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateMountPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "valid absolute path",
			path:    "/mnt/storage",
			wantErr: false,
		},
		{
			name:    "valid root path",
			path:    "/",
			wantErr: false,
		},
		{
			name:    "empty path is valid",
			path:    "",
			wantErr: false,
		},
		{
			name:    "relative path invalid",
			path:    "mnt/storage",
			wantErr: true,
		},
		{
			name:    "path with spaces invalid",
			path:    "/mnt/my storage",
			wantErr: true,
		},
		{
			name:    "path with double slash invalid",
			path:    "/mnt//storage",
			wantErr: true,
		},
		{
			name:    "path with parent directory invalid",
			path:    "/mnt/../storage",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMountPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMountPath() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateLabel(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		wantErr bool
	}{
		{
			name:    "valid label",
			label:   "my-volume",
			wantErr: false,
		},
		{
			name:    "valid label with underscore",
			label:   "my_volume_1",
			wantErr: false,
		},
		{
			name:    "empty label is valid",
			label:   "",
			wantErr: false,
		},
		{
			name:    "label with spaces invalid",
			label:   "my volume",
			wantErr: true,
		},
		{
			name:    "label with special chars invalid",
			label:   "my@volume",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLabel(tt.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLabel() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}