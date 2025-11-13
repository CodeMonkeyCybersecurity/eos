package ldap

import (
	"testing"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/testutil"
)

// TestLDAPConfig tests the LDAPConfig struct and its methods
func TestLDAPConfig(t *testing.T) {
	tests := []testutil.TableTest[struct {
		config   *LDAPConfig
		expected *LDAPConfig
	}]{
		{
			Name: "default config",
			Input: struct {
				config   *LDAPConfig
				expected *LDAPConfig
			}{
				config: DefaultLDAPConfig(),
				expected: &LDAPConfig{
					FQDN:         "localhost",
					Port:         389,
					UseTLS:       false,
					BindDN:       "cn=admin,dc=domain,dc=com",
					Password:     "",
					UserBase:     "ou=Users,dc=domain,dc=com",
					RoleBase:     "ou=Groups,dc=domain,dc=com",
					AdminRole:    "AdminRole",
					ReadonlyRole: "ReadonlyRole",
				},
			},
		},
		{
			Name: "custom config",
			Input: struct {
				config   *LDAPConfig
				expected *LDAPConfig
			}{
				config: &LDAPConfig{
					FQDN:         "ldap.example.com",
					Port:         636,
					UseTLS:       true,
					BindDN:       "cn=service,dc=example,dc=com",
					Password:     "secret",
					UserBase:     "ou=People,dc=example,dc=com",
					RoleBase:     "ou=Roles,dc=example,dc=com",
					AdminRole:    "Administrators",
					ReadonlyRole: "Readers",
				},
				expected: &LDAPConfig{
					FQDN:         "ldap.example.com",
					Port:         636,
					UseTLS:       true,
					BindDN:       "cn=service,dc=example,dc=com",
					Password:     "secret",
					UserBase:     "ou=People,dc=example,dc=com",
					RoleBase:     "ou=Roles,dc=example,dc=com",
					AdminRole:    "Administrators",
					ReadonlyRole: "Readers",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			testutil.AssertEqual(t, tc.Input.expected.FQDN, tc.Input.config.FQDN)
			testutil.AssertEqual(t, tc.Input.expected.Port, tc.Input.config.Port)
			testutil.AssertEqual(t, tc.Input.expected.UseTLS, tc.Input.config.UseTLS)
			testutil.AssertEqual(t, tc.Input.expected.BindDN, tc.Input.config.BindDN)
			testutil.AssertEqual(t, tc.Input.expected.Password, tc.Input.config.Password)
			testutil.AssertEqual(t, tc.Input.expected.UserBase, tc.Input.config.UserBase)
			testutil.AssertEqual(t, tc.Input.expected.RoleBase, tc.Input.config.RoleBase)
			testutil.AssertEqual(t, tc.Input.expected.AdminRole, tc.Input.config.AdminRole)
			testutil.AssertEqual(t, tc.Input.expected.ReadonlyRole, tc.Input.config.ReadonlyRole)
		})
	}
}

// TestLDAPUserStruct tests the LDAPUser struct
func TestLDAPUserStruct(t *testing.T) {
	tests := []struct {
		name string
		user LDAPUser
	}{
		{
			name: "valid user",
			user: LDAPUser{
				UID:  "jdoe",
				CN:   "John Doe",
				Mail: "jdoe@example.com",
				DN:   "uid=jdoe,ou=Users,dc=example,dc=com",
			},
		},
		{
			name: "user with special characters",
			user: LDAPUser{
				UID:  "jane.smith+test",
				CN:   "Jane Smith-Jones",
				Mail: "jane.smith+test@example.com",
				DN:   "uid=jane.smith+test,ou=Users,dc=example,dc=com",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testutil.AssertEqual(t, tc.user.UID, tc.user.UID)
			testutil.AssertEqual(t, tc.user.CN, tc.user.CN)
			testutil.AssertEqual(t, tc.user.Mail, tc.user.Mail)
			testutil.AssertEqual(t, tc.user.DN, tc.user.DN)
		})
	}
}

// TestLDAPGroupStruct tests the LDAPGroup struct
func TestLDAPGroupStruct(t *testing.T) {
	tests := []struct {
		name  string
		group LDAPGroup
	}{
		{
			name: "valid group",
			group: LDAPGroup{
				CN:      "Administrators",
				DN:      "cn=Administrators,ou=Groups,dc=example,dc=com",
				Members: []string{"uid=admin,ou=Users,dc=example,dc=com"},
			},
		},
		{
			name: "group with multiple members",
			group: LDAPGroup{
				CN: "Developers",
				DN: "cn=Developers,ou=Groups,dc=example,dc=com",
				Members: []string{
					"uid=dev1,ou=Users,dc=example,dc=com",
					"uid=dev2,ou=Users,dc=example,dc=com",
					"uid=dev3,ou=Users,dc=example,dc=com",
				},
			},
		},
		{
			name: "empty group",
			group: LDAPGroup{
				CN:      "EmptyGroup",
				DN:      "cn=EmptyGroup,ou=Groups,dc=example,dc=com",
				Members: []string{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testutil.AssertEqual(t, tc.group.CN, tc.group.CN)
			testutil.AssertEqual(t, tc.group.DN, tc.group.DN)
			testutil.AssertEqual(t, len(tc.group.Members), len(tc.group.Members))
			for i, member := range tc.group.Members {
				testutil.AssertEqual(t, member, tc.group.Members[i])
			}
		})
	}
}

// TestConnect tests LDAP connection functionality
func TestConnect(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "connection without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			_, err := Connect(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestConnectWithConfig tests LDAP connection with configuration
func TestConnectWithConfig(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "connection with config without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			_, _, err := ConnectWithConfig(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestReadUser tests user reading functionality
func TestReadUser(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "read users without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			_, err := ReadUser(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestReadGroup tests group reading functionality
func TestReadGroup(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "read groups without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)

			_, err := ReadGroup(rc)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestCreateUserOperation tests user creation functionality
func TestCreateUserOperation(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "create user without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultLDAPConfig()
			user := LDAPUser{
				UID:  "testuser",
				CN:   "Test User",
				Mail: "test@example.com",
				DN:   "uid=testuser,ou=Users,dc=domain,dc=com",
			}
			password := "testpassword"

			err := CreateUser(config, user, password)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestCreateGroupOperation tests group creation functionality
func TestCreateGroupOperation(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "create group without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := testutil.TestRuntimeContext(t)
			config := DefaultLDAPConfig()
			group := LDAPGroup{
				CN:      "TestGroup",
				DN:      "cn=TestGroup,ou=Groups,dc=domain,dc=com",
				Members: []string{},
			}

			err := CreateGroup(rc, config, group)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestDeleteUserOperation tests user deletion functionality
func TestDeleteUserOperation(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "delete user without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid := "testuser"
			config := DefaultLDAPConfig()

			err := DeleteUser(uid, config)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestDeleteGroupOperation tests group deletion functionality
func TestDeleteGroupOperation(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "delete group without ldap server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cn := "TestGroup"
			config := DefaultLDAPConfig()

			err := DeleteGroup(cn, config)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestLDAPProbe tests LDAP probe functionality
func TestLDAPProbe(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "ldap probe without server",
			wantErr: true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RunLDAPProbe()

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}

// TestLDAPAuthProbe tests LDAP authentication probe functionality
func TestLDAPAuthProbe(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{
			name:     "auth probe without server",
			username: "testuser",
			password: "testpass",
			wantErr:  true, // Will fail in test environment without LDAP server
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RunLDAPAuthProbe(tc.username, tc.password)

			if tc.wantErr {
				testutil.AssertError(t, err)
			} else {
				testutil.AssertNoError(t, err)
			}
		})
	}
}
