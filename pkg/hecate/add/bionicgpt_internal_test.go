package add

import (
	"testing"
)

func TestDeriveCookieDomain(t *testing.T) {
	tests := map[string]string{
		"chat.example.com":   ".example.com",
		"app.codemonkey.net": ".codemonkey.net",
		"example.com":        ".example.com",
		"localhost":          "",
		"":                   "",
	}

	for input, expected := range tests {
		if got := deriveCookieDomain(input); got != expected {
			t.Fatalf("deriveCookieDomain(%q) = %q, expected %q", input, got, expected)
		}
	}
}

func TestNormalizeInternalHost(t *testing.T) {
	tests := map[string]string{
		"100.64.0.10":             "http://100.64.0.10:8513",
		"100.64.0.10:9000":        "http://100.64.0.10:9000",
		"http://100.64.0.10":      "http://100.64.0.10:8513",
		"http://100.64.0.10:9000": "http://100.64.0.10:9000",
		"":                        "http://127.0.0.1:8513",
	}

	for input, expected := range tests {
		got, err := normalizeInternalHost(input)
		if err != nil {
			t.Fatalf("normalizeInternalHost(%q) returned error: %v", input, err)
		}
		if got != expected {
			t.Fatalf("normalizeInternalHost(%q) = %q, expected %q", input, got, expected)
		}
	}
}

func TestBuildBionicGPTProxySettings(t *testing.T) {
	opts := &ServiceOptions{
		DNS:     "chat.example.com",
		Backend: "100.64.0.10",
	}

	settings, err := buildBionicGPTProxySettings(opts)
	if err != nil {
		t.Fatalf("buildBionicGPTProxySettings returned error: %v", err)
	}

	if settings.ExternalHost != "https://chat.example.com" {
		t.Fatalf("unexpected external host: %s", settings.ExternalHost)
	}
	if settings.InternalHost != "http://100.64.0.10:8513" {
		t.Fatalf("unexpected internal host: %s", settings.InternalHost)
	}
	if settings.CookieDomain != ".example.com" {
		t.Fatalf("unexpected cookie domain: %s", settings.CookieDomain)
	}
	if settings.LaunchURL != "https://chat.example.com" {
		t.Fatalf("unexpected launch URL: %s", settings.LaunchURL)
	}
}
