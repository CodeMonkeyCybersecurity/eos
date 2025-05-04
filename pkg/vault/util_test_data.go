// pkg/vault/util_test.go

package vault

// generateTestData returns a realistic in-memory test dataset for validation workflows.
func GenerateTestData() map[string]interface{} {
	return map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"username": "alice",
				"fullname": "Alice Wonderland",
				"email":    "alice@example.com",
				"groups":   []string{"users", "nextcloud", "keycloak"},
				"password": "S3cr3tP@ssw0rd!",
			},
			{
				"username": "bob",
				"fullname": "Bob Builder",
				"email":    "bob@example.com",
				"groups":   []string{"admins", "ldap", "scim"},
				"password": "CanWeFixItYesWeCan!",
			},
		},
		"groups": []string{"users", "admins", "nextcloud", "keycloak", "ldap", "scim"},
		"services": map[string]string{
			"wazuh_api_url": "https://wazuh.example.com",
			"keycloak_url":  "https://keycloak.example.com",
			"nextcloud_url": "https://nextcloud.example.com",
		},
	}
}
