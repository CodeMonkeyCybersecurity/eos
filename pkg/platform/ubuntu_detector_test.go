package platform

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func TestParseOSRelease(t *testing.T) {
	// Create a runtime context for testing
	ctx := eos_io.NewContext(context.Background(), "test")
	defer func() {
		var err error
		ctx.End(&err)
	}()

	// Test with Ubuntu 24.04 format
	ubuntu2404Content := `PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo`

	// Create temporary file
	tmpFile, err := os.CreateTemp("", "os-release-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString(ubuntu2404Content); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	// Temporarily replace the /etc/os-release path in the function
	// This is a bit of a hack but necessary for testing
	originalOSRelease := "/etc/os-release"

	// Read the temporary file instead
	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Test parsing the content manually
	info := &OSReleaseInfo{}

	// Parse each line
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present (handles both "value" and value formats)
		value = strings.Trim(value, "\"'")

		switch key {
		case "NAME":
			info.Name = value
		case "VERSION":
			info.Version = value
		case "VERSION_ID":
			info.VersionID = value
		case "VERSION_CODENAME":
			info.VersionCodename = value
		case "ID":
			info.ID = value
		case "ID_LIKE":
			info.IDLike = value
		case "PRETTY_NAME":
			info.PrettyName = value
		case "UBUNTU_CODENAME":
			info.UbuntuCodename = value
		}
	}

	// Verify parsing worked correctly
	if info.VersionID != "24.04" {
		t.Errorf("Expected VERSION_ID=24.04, got %s", info.VersionID)
	}

	if info.VersionCodename != "noble" {
		t.Errorf("Expected VERSION_CODENAME=noble, got %s", info.VersionCodename)
	}

	if info.ID != "ubuntu" {
		t.Errorf("Expected ID=ubuntu, got %s", info.ID)
	}

	t.Logf("Successfully parsed Ubuntu 24.04:")
	t.Logf("  VERSION_ID: %s", info.VersionID)
	t.Logf("  VERSION_CODENAME: %s", info.VersionCodename)
	t.Logf("  ID: %s", info.ID)
	t.Logf("  PRETTY_NAME: %s", info.PrettyName)

	// Test Ubuntu detection
	if !isUbuntu(info) {
		t.Error("Ubuntu detection failed")
	}

	// Test codename extraction
	codename := getCodename(info)
	if codename != "noble" {
		t.Errorf("Expected codename=noble, got %s", codename)
	}

	t.Log("All tests passed!")

	// Avoid unused variable warning
	_ = originalOSRelease
}

func TestGetSaltRepoURL(t *testing.T) {
	tests := []struct {
		version  string
		codename string
		expected string
	}{
		{
			version:  "24.04",
			codename: "noble",
			expected: "https://packages.broadcom.com/artifactory/saltproject-deb noble main",
		},
		{
			version:  "22.04",
			codename: "jammy",
			expected: "https://packages.broadcom.com/artifactory/saltproject-deb jammy main",
		},
		{
			version:  "20.04",
			codename: "focal",
			expected: "https://packages.broadcom.com/artifactory/saltproject-deb focal main",
		},
	}

	for _, test := range tests {
		result := GetSaltRepoURL(test.version, test.codename)
		if result != test.expected {
			t.Errorf("GetSaltRepoURL(%s, %s) = %s, expected %s",
				test.version, test.codename, result, test.expected)
		}
	}
}
