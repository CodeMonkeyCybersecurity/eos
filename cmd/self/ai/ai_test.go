package ai

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPromptDataSharingConsent(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("y\n"))
	require.NoError(t, promptDataSharingConsent(reader, "demo"))
	reader = bufio.NewReader(strings.NewReader("n\n"))
	require.Error(t, promptDataSharingConsent(reader, "demo"))
}

func TestLoadAutoFixPolicy(t *testing.T) {
	secrets := [][]byte{[]byte("secret-key")}
	doc := autoFixPolicyDocument{
		Name:         "test",
		AllowAutoFix: true,
		Scope:        "*",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Format(time.RFC3339),
	}
	payload := doc
	payload.Signature = ""
	payloadBytes, err := json.Marshal(payload)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, secrets[0])
	mac.Write(payloadBytes)
	doc.Signature = hex.EncodeToString(mac.Sum(nil))
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	file, err := os.CreateTemp(t.TempDir(), "policy-*.json")
	require.NoError(t, err)
	_, err = file.Write(data)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	loaded, err := loadAutoFixPolicy(file.Name(), secrets)
	require.NoError(t, err)
	require.True(t, loaded.AllowsAutoFix())
}
