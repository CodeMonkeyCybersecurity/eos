package privilege_check

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestPrivilegeLevelConstants tests the privilege level constants
func TestPrivilegeLevelConstants(t *testing.T) {
	// Verify constants have expected values
	if PrivilegeLevelRoot != "root" {
		t.Errorf("PrivilegeLevelRoot = %q, want %q", PrivilegeLevelRoot, "root")
	}
	if PrivilegeLevelSudo != "sudo" {
		t.Errorf("PrivilegeLevelSudo = %q, want %q", PrivilegeLevelSudo, "sudo")
	}
	if PrivilegeLevelRegular != "regular" {
		t.Errorf("PrivilegeLevelRegular = %q, want %q", PrivilegeLevelRegular, "regular")
	}

	// Verify they are distinct
	levels := []PrivilegeLevel{PrivilegeLevelRoot, PrivilegeLevelSudo, PrivilegeLevelRegular}
	seen := make(map[PrivilegeLevel]bool)
	for _, level := range levels {
		if seen[level] {
			t.Errorf("Duplicate privilege level: %s", level)
		}
		seen[level] = true
	}
}

// TestSudoRequirementConstants tests the sudo requirement constants
func TestSudoRequirementConstants(t *testing.T) {
	// Verify constants have expected values
	if SudoNotRequired != "not_required" {
		t.Errorf("SudoNotRequired = %q, want %q", SudoNotRequired, "not_required")
	}
	if SudoPreferred != "preferred" {
		t.Errorf("SudoPreferred = %q, want %q", SudoPreferred, "preferred")
	}
	if SudoRequired != "required" {
		t.Errorf("SudoRequired = %q, want %q", SudoRequired, "required")
	}

	// Verify they are distinct
	requirements := []SudoRequirement{SudoNotRequired, SudoPreferred, SudoRequired}
	seen := make(map[SudoRequirement]bool)
	for _, req := range requirements {
		if seen[req] {
			t.Errorf("Duplicate sudo requirement: %s", req)
		}
		seen[req] = true
	}
}

// TestDefaultPrivilegeConfig tests the default configuration
func TestDefaultPrivilegeConfig(t *testing.T) {
	config := DefaultPrivilegeConfig()

	if config == nil {
		t.Fatal("DefaultPrivilegeConfig returned nil")
	}

	// Check default values
	if !config.RequireRoot {
		t.Error("RequireRoot should be true by default")
	}
	if !config.AllowSudo {
		t.Error("AllowSudo should be true by default")
	}
	if !config.ExitOnFailure {
		t.Error("ExitOnFailure should be true by default")
	}
	if !config.ShowColorOutput {
		t.Error("ShowColorOutput should be true by default")
	}
}

// TestPrivilegeCheckStruct tests the PrivilegeCheck structure
func TestPrivilegeCheckStruct(t *testing.T) {
	now := time.Now()
	check := PrivilegeCheck{
		UserID:    1000,
		Username:  "testuser",
		GroupID:   1000,
		Groupname: "testgroup",
		Level:     PrivilegeLevelRegular,
		IsRoot:    false,
		HasSudo:   true,
		Timestamp: now,
		Error:     "",
	}

	// Test JSON marshaling
	data, err := json.Marshal(check)
	if err != nil {
		t.Fatalf("Failed to marshal PrivilegeCheck: %v", err)
	}

	// Test JSON unmarshaling
	var decoded PrivilegeCheck
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal PrivilegeCheck: %v", err)
	}

	// Verify fields match
	if decoded.UserID != check.UserID {
		t.Errorf("UserID mismatch: got %d, want %d", decoded.UserID, check.UserID)
	}
	if decoded.Username != check.Username {
		t.Errorf("Username mismatch: got %q, want %q", decoded.Username, check.Username)
	}
	if decoded.Level != check.Level {
		t.Errorf("Level mismatch: got %q, want %q", decoded.Level, check.Level)
	}
	if decoded.IsRoot != check.IsRoot {
		t.Errorf("IsRoot mismatch: got %v, want %v", decoded.IsRoot, check.IsRoot)
	}
	if decoded.HasSudo != check.HasSudo {
		t.Errorf("HasSudo mismatch: got %v, want %v", decoded.HasSudo, check.HasSudo)
	}

	// JSON should include all fields with proper tags
	jsonStr := string(data)
	expectedFields := []string{
		`"user_id"`, `"username"`, `"group_id"`, `"groupname"`,
		`"level"`, `"is_root"`, `"has_sudo"`, `"timestamp"`,
	}
	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON missing field: %s", field)
		}
	}
}

// TestSudoCheckResultStruct tests the SudoCheckResult structure
func TestSudoCheckResultStruct(t *testing.T) {
	now := time.Now()
	result := SudoCheckResult{
		Required: true,
		Check: PrivilegeCheck{
			UserID:   0,
			Username: "root",
			Level:    PrivilegeLevelRoot,
			IsRoot:   true,
			HasSudo:  true,
		},
		Message:   "Running as root",
		Success:   true,
		Timestamp: now,
	}

	// Test JSON marshaling
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Failed to marshal SudoCheckResult: %v", err)
	}

	// Test JSON unmarshaling
	var decoded SudoCheckResult
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal SudoCheckResult: %v", err)
	}

	// Verify fields match
	if decoded.Required != result.Required {
		t.Errorf("Required mismatch: got %v, want %v", decoded.Required, result.Required)
	}
	if decoded.Message != result.Message {
		t.Errorf("Message mismatch: got %q, want %q", decoded.Message, result.Message)
	}
	if decoded.Success != result.Success {
		t.Errorf("Success mismatch: got %v, want %v", decoded.Success, result.Success)
	}
	if decoded.Check.Username != result.Check.Username {
		t.Errorf("Check.Username mismatch: got %q, want %q", decoded.Check.Username, result.Check.Username)
	}
}

// TestPrivilegeConfigStruct tests the PrivilegeConfig structure
func TestPrivilegeConfigStruct(t *testing.T) {
	config := PrivilegeConfig{
		RequireRoot:     true,
		AllowSudo:       false,
		ExitOnFailure:   true,
		ShowColorOutput: false,
	}

	// Test JSON marshaling
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal PrivilegeConfig: %v", err)
	}

	// Test JSON unmarshaling
	var decoded PrivilegeConfig
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal PrivilegeConfig: %v", err)
	}

	// Verify fields match
	if !reflect.DeepEqual(decoded, config) {
		t.Errorf("PrivilegeConfig mismatch: got %+v, want %+v", decoded, config)
	}

	// Verify JSON tags
	jsonStr := string(data)
	expectedFields := []string{
		`"require_root"`, `"allow_sudo"`, `"exit_on_failure"`, `"show_color_output"`,
	}
	for _, field := range expectedFields {
		if !contains(jsonStr, field) {
			t.Errorf("JSON missing field: %s", field)
		}
	}
}

// TestCheckOptionsStruct tests the CheckOptions structure
func TestCheckOptionsStruct(t *testing.T) {
	options := CheckOptions{
		Requirement:   SudoRequired,
		CustomMessage: "Custom error message",
		SilentMode:    true,
	}

	// Test JSON marshaling
	data, err := json.Marshal(options)
	if err != nil {
		t.Fatalf("Failed to marshal CheckOptions: %v", err)
	}

	// Test JSON unmarshaling
	var decoded CheckOptions
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal CheckOptions: %v", err)
	}

	// Verify fields match
	if decoded.Requirement != options.Requirement {
		t.Errorf("Requirement mismatch: got %q, want %q", decoded.Requirement, options.Requirement)
	}
	if decoded.CustomMessage != options.CustomMessage {
		t.Errorf("CustomMessage mismatch: got %q, want %q", decoded.CustomMessage, options.CustomMessage)
	}
	if decoded.SilentMode != options.SilentMode {
		t.Errorf("SilentMode mismatch: got %v, want %v", decoded.SilentMode, options.SilentMode)
	}
}

// TestPrivilegeCheckWithError tests PrivilegeCheck with error field
func TestPrivilegeCheckWithError(t *testing.T) {
	check := PrivilegeCheck{
		UserID:    -1,
		Username:  "",
		Error:     "Failed to get user information",
		Timestamp: time.Now(),
	}

	// Test JSON marshaling with error
	data, err := json.Marshal(check)
	if err != nil {
		t.Fatalf("Failed to marshal PrivilegeCheck with error: %v", err)
	}

	// Error field should be omitted if empty due to omitempty tag
	check2 := PrivilegeCheck{
		UserID:    1000,
		Username:  "user",
		Error:     "",
		Timestamp: time.Now(),
	}

	data2, err := json.Marshal(check2)
	if err != nil {
		t.Fatalf("Failed to marshal PrivilegeCheck without error: %v", err)
	}

	// When error is empty, it should not appear in JSON
	if contains(string(data2), `"error"`) {
		t.Error("Empty error field should be omitted from JSON")
	}

	// When error is set, it should appear in JSON
	if !contains(string(data), `"error"`) {
		t.Error("Non-empty error field should appear in JSON")
	}
}

// TestZeroValues tests zero value behavior of types
func TestZeroValues(t *testing.T) {
	// Test zero value of PrivilegeCheck
	var check PrivilegeCheck
	if check.UserID != 0 {
		t.Error("Zero value UserID should be 0")
	}
	if check.Username != "" {
		t.Error("Zero value Username should be empty")
	}
	if check.Level != "" {
		t.Error("Zero value Level should be empty")
	}
	if check.IsRoot {
		t.Error("Zero value IsRoot should be false")
	}
	if check.HasSudo {
		t.Error("Zero value HasSudo should be false")
	}
	if !check.Timestamp.IsZero() {
		t.Error("Zero value Timestamp should be zero")
	}

	// Test zero value of SudoCheckResult
	var result SudoCheckResult
	if result.Required {
		t.Error("Zero value Required should be false")
	}
	if result.Success {
		t.Error("Zero value Success should be false")
	}
	if result.Message != "" {
		t.Error("Zero value Message should be empty")
	}

	// Test zero value of PrivilegeConfig
	var config PrivilegeConfig
	if config.RequireRoot {
		t.Error("Zero value RequireRoot should be false")
	}
	if config.AllowSudo {
		t.Error("Zero value AllowSudo should be false")
	}
	if config.ExitOnFailure {
		t.Error("Zero value ExitOnFailure should be false")
	}
	if config.ShowColorOutput {
		t.Error("Zero value ShowColorOutput should be false")
	}

	// Test zero value of CheckOptions
	var options CheckOptions
	if options.Requirement != "" {
		t.Error("Zero value Requirement should be empty")
	}
	if options.CustomMessage != "" {
		t.Error("Zero value CustomMessage should be empty")
	}
	if options.SilentMode {
		t.Error("Zero value SilentMode should be false")
	}
}

// TestPrivilegeLevelValidation tests validation of privilege levels
func TestPrivilegeLevelValidation(t *testing.T) {
	validLevels := []PrivilegeLevel{
		PrivilegeLevelRoot,
		PrivilegeLevelSudo,
		PrivilegeLevelRegular,
	}

	// Test that valid levels are recognized
	for _, level := range validLevels {
		// In a real implementation, you might have an IsValid method
		switch level {
		case PrivilegeLevelRoot, PrivilegeLevelSudo, PrivilegeLevelRegular:
			// Valid
		default:
			t.Errorf("Valid level %q not recognized", level)
		}
	}

	// Test invalid levels
	invalidLevels := []PrivilegeLevel{
		"admin",
		"superuser",
		"",
		"ROOT",
		"Sudo",
	}

	for _, level := range invalidLevels {
		switch level {
		case PrivilegeLevelRoot, PrivilegeLevelSudo, PrivilegeLevelRegular:
			t.Errorf("Invalid level %q incorrectly recognized as valid", level)
		default:
			// Correctly identified as invalid
		}
	}
}

// TestSudoRequirementValidation tests validation of sudo requirements
func TestSudoRequirementValidation(t *testing.T) {
	validRequirements := []SudoRequirement{
		SudoNotRequired,
		SudoPreferred,
		SudoRequired,
	}

	// Test that valid requirements are recognized
	for _, req := range validRequirements {
		switch req {
		case SudoNotRequired, SudoPreferred, SudoRequired:
			// Valid
		default:
			t.Errorf("Valid requirement %q not recognized", req)
		}
	}

	// Test invalid requirements
	invalidRequirements := []SudoRequirement{
		"optional",
		"mandatory",
		"",
		"REQUIRED",
		"NotRequired",
	}

	for _, req := range invalidRequirements {
		switch req {
		case SudoNotRequired, SudoPreferred, SudoRequired:
			t.Errorf("Invalid requirement %q incorrectly recognized as valid", req)
		default:
			// Correctly identified as invalid
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
