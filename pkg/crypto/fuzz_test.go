package crypto

import (
	"bufio"
	"context"
	"strings"
	"testing"
)

func FuzzValidateStrongPassword(f *testing.F) {
	f.Add("")
	f.Add("123456")
	f.Add("    ")
	f.Add("pässwörd")
	f.Add("!@#$%^&*()_+")
	f.Add("' OR 1=1 --")
	f.Add("👾🔑")
	f.Add("pass\u200Bword")
	f.Add("../")
	f.Add("\x00\xff\xfe")                       // odd byte values
	f.Add("a very very very long password ...") // really long one
	f.Add("password")
	f.Add("superS3cr3t!!")
	f.Add(strings.Repeat("A", 10_000)) // <-- FIX: pass as f.Add, not stand-alone
	f.Fuzz(func(t *testing.T, pw string) {
		_ = ValidateStrongPassword(context.Background(), pw)
	})
}

func FuzzHashString(f *testing.F) {
	f.Add("test")
	f.Add("")
	f.Add("123456")
	f.Add("🐒🔑")
	f.Add("\x00\xFF\xFE")
	f.Fuzz(func(t *testing.T, s string) {
		_ = HashString(s)
	})
}

func FuzzHashStrings(f *testing.F) {
	f.Add("a,b,c")
	f.Add("")
	f.Add("duplicate,duplicate")
	f.Add("🐒,🔑")
	f.Fuzz(func(t *testing.T, s string) {
		var items []string
		if s != "" {
			items = strings.Split(s, ",")
		}
		_ = HashStrings(items)
	})
}

func FuzzAllUnique(f *testing.F) {
	f.Add("a,b,c")
	f.Add("a,a")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		var items []string
		if s != "" {
			items = strings.Split(s, ",")
		}
		_ = AllUnique(items)
	})
}

func FuzzAllHashesPresent(f *testing.F) {
	f.Add("a,b", "a,b")
	f.Add("a", "b")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, hashesCsv, knownCsv string) {
		var hashes, known []string
		if hashesCsv != "" {
			hashes = strings.Split(hashesCsv, ",")
		}
		if knownCsv != "" {
			known = strings.Split(knownCsv, ",")
		}
		_ = AllHashesPresent(hashes, known)
	})
}

func FuzzRedact(f *testing.F) {
	f.Add("")
	f.Add("password")
	f.Add("secret stuff")
	f.Fuzz(func(t *testing.T, s string) {
		_ = Redact(s)
	})
}

func FuzzInjectSecretsFromPlaceholders(f *testing.F) {
	f.Add([]byte("changeme"))
	f.Add([]byte("changeme0 changeme1 changeme2"))
	f.Add([]byte("no placeholders here"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = InjectSecretsFromPlaceholders(data)
	})
}

func FuzzSecureZero(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		SecureZero(b)
	})
}

func TestGeneratePassword(t *testing.T) {
	pw, err := GeneratePassword(16)
	if err != nil {
		t.Fatalf("GeneratePassword failed: %v", err)
	}
	if len(pw) < 16 {
		t.Errorf("password too short: got %d, want >=16", len(pw))
	}
}

func TestValidateStrongPassword(t *testing.T) {
	valid := "Astrong!Pass123"
	if err := ValidateStrongPassword(nil, valid); err != nil {
		t.Errorf("ValidateStrongPassword rejected valid password: %v", err)
	}

	invalid := "weakpass"
	if err := ValidateStrongPassword(nil, invalid); err == nil {
		t.Error("ValidateStrongPassword accepted weak password, expected error")
	}
}

func TestReadPassword(t *testing.T) {
	input := "testpassword\n"
	reader := bufio.NewReader(strings.NewReader(input))
	pw, err := ReadPassword(reader)
	if err != nil {
		t.Fatalf("ReadPassword failed: %v", err)
	}
	if pw != "testpassword" {
		t.Errorf("ReadPassword incorrect: got %q, want %q", pw, "testpassword")
	}
}
