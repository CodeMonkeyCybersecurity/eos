// pkg/shared/test_data.go

package shared

// generateTestData returns a realistic in-memory test dataset for validation workflows.
func GenerateTestData() map[string]interface{} {
	return map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"username": "alice",
				"fullname": "Alice Wonderland",
				"email":    "alice@cybermonkey.dev",
				"groups":   []string{"users", "nextcloud", "hera"},
				"password": "S3cr3tP@ssw0rd!",
			},
			{
				"username": "bob",
				"fullname": "Bob Builder",
				"email":    "bob@cybermonkey.dev",
				"groups":   []string{"admins", "ldap", "scim"},
				"password": "CanWeFixIt?YesWeCan!",
			},
		},
		"groups": []string{"users", "admins", "nextcloud", "hera", "ldap", "scim"},
		"services": map[string]string{
			"wazuh_api_url": "https://wazuh.cybermonkey.dev",
			"hera_url":  "https://hera.cybermonkey.dev",
			"nextcloud_url": "https://nextcloud.cybermonkey.dev",
		},
	}
}

func GenerateUpdatedTestData() map[string]interface{} {
	return map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"username": "alice",
				"fullname": "Alice Wonderland (Updated)",
				"email":    "alice@wonderland.com",
				"groups":   []string{"users", "nextcloud"},
				"password": "UpdatedS3cretP@ss!",
			},
			{
				"username": "bob",
				"fullname": "Bob the Builder (Updated)",
				"email":    "bob@builder.com",
				"groups":   []string{"admins"},
				"password": "YesWeStillCan!",
			},
		},
		"groups": []string{"users", "admins", "nextcloud"},
		"services": map[string]string{
			"wazuh_api_url": "https://new-wazuh.cybermonkey.dev",
		},
	}
}
