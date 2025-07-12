package apps

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApp_Structure(t *testing.T) {
	tests := []struct {
		name     string
		app      App
		validate func(t *testing.T, app App)
	}{
		{
			name: "complete app configuration",
			app: App{
				Option:   "1",
				Name:     "Static website",
				ConfFile: "base.conf",
				Markers:  []string{"80", "443"},
			},
			validate: func(t *testing.T, app App) {
				assert.Equal(t, "1", app.Option)
				assert.Equal(t, "Static website", app.Name)
				assert.Equal(t, "base.conf", app.ConfFile)
				assert.Len(t, app.Markers, 2)
				assert.Contains(t, app.Markers, "80")
				assert.Contains(t, app.Markers, "443")
			},
		},
		{
			name: "app with service markers",
			app: App{
				Option:   "2",
				Name:     "Wazuh",
				ConfFile: "delphi.conf",
				Markers:  []string{"1515", "1514", "55000"},
			},
			validate: func(t *testing.T, app App) {
				assert.Equal(t, "2", app.Option)
				assert.Equal(t, "Wazuh", app.Name)
				assert.Equal(t, "delphi.conf", app.ConfFile)
				assert.Len(t, app.Markers, 3)
			},
		},
		{
			name: "minimal app",
			app: App{
				Option:   "99",
				Name:     "Custom App",
				ConfFile: "custom.conf",
				Markers:  []string{},
			},
			validate: func(t *testing.T, app App) {
				assert.Equal(t, "99", app.Option)
				assert.Equal(t, "Custom App", app.Name)
				assert.Equal(t, "custom.conf", app.ConfFile)
				assert.Empty(t, app.Markers)
			},
		},
		{
			name: "app with empty fields",
			app: App{
				Option:   "",
				Name:     "",
				ConfFile: "",
				Markers:  nil,
			},
			validate: func(t *testing.T, app App) {
				assert.Empty(t, app.Option)
				assert.Empty(t, app.Name)
				assert.Empty(t, app.ConfFile)
				assert.Nil(t, app.Markers)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.validate(t, tt.app)
		})
	}
}

func TestApps_DefaultConfiguration(t *testing.T) {
	// Test the default Apps configuration
	assert.Len(t, Apps, 13, "Should have 13 predefined apps")

	// Verify each app has required fields
	for i, app := range Apps {
		assert.NotEmpty(t, app.Option, "App at index %d should have option", i)
		assert.NotEmpty(t, app.Name, "App at index %d should have name", i)
		assert.NotEmpty(t, app.ConfFile, "App at index %d should have config file", i)
		assert.True(t, strings.HasSuffix(app.ConfFile, ".conf"), "Config file should end with .conf")
		assert.NotNil(t, app.Markers, "App at index %d should have markers", i)
	}

	// Test specific apps
	app1, found := GetAppByOption("1")
	require.True(t, found)
	assert.Equal(t, "Static website", app1.Name)
	assert.Equal(t, "base.conf", app1.ConfFile)

	app5, found := GetAppByOption("5")
	require.True(t, found)
	assert.Equal(t, "Mailcow", app5.Name)
	assert.Contains(t, app5.Markers, "25")
	assert.Contains(t, app5.Markers, "587")
}

func TestGetSupportedAppNames(t *testing.T) {
	// Store original Apps
	originalApps := Apps
	defer func() { Apps = originalApps }()

	tests := []struct {
		name     string
		apps     []App
		expected []string
	}{
		{
			name: "standard apps",
			apps: []App{
				{Option: "1", Name: "Static Website", ConfFile: "static.conf"},
				{Option: "2", Name: "Wazuh", ConfFile: "wazuh.conf"},
				{Option: "3", Name: "Mattermost", ConfFile: "matter.conf"},
			},
			expected: []string{"static website", "wazuh", "mattermost"},
		},
		{
			name: "apps with mixed case",
			apps: []App{
				{Option: "1", Name: "CamelCase", ConfFile: "camel.conf"},
				{Option: "2", Name: "UPPERCASE", ConfFile: "upper.conf"},
				{Option: "3", Name: "lowercase", ConfFile: "lower.conf"},
			},
			expected: []string{"camelcase", "uppercase", "lowercase"},
		},
		{
			name:     "empty apps list",
			apps:     []App{},
			expected: []string{},
		},
		{
			name: "apps with special characters",
			apps: []App{
				{Option: "1", Name: "App-With-Dashes", ConfFile: "dash.conf"},
				{Option: "2", Name: "App.With.Dots", ConfFile: "dot.conf"},
				{Option: "3", Name: "App With Spaces", ConfFile: "space.conf"},
			},
			expected: []string{"app-with-dashes", "app.with.dots", "app with spaces"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Apps = tt.apps
			names := GetSupportedAppNames()
			assert.Equal(t, tt.expected, names)
		})
	}
}

func TestGetAppByOption(t *testing.T) {
	// Store original Apps
	originalApps := Apps
	defer func() { Apps = originalApps }()

	Apps = []App{
		{Option: "1", Name: "App One", ConfFile: "one.conf"},
		{Option: "2", Name: "App Two", ConfFile: "two.conf"},
		{Option: "10", Name: "App Ten", ConfFile: "ten.conf"},
	}

	tests := []struct {
		name        string
		option      string
		expectFound bool
		expectName  string
	}{
		{
			name:        "existing option 1",
			option:      "1",
			expectFound: true,
			expectName:  "App One",
		},
		{
			name:        "existing option 2",
			option:      "2",
			expectFound: true,
			expectName:  "App Two",
		},
		{
			name:        "existing option 10",
			option:      "10",
			expectFound: true,
			expectName:  "App Ten",
		},
		{
			name:        "non-existent option",
			option:      "99",
			expectFound: false,
		},
		{
			name:        "empty option",
			option:      "",
			expectFound: false,
		},
		{
			name:        "negative option",
			option:      "-1",
			expectFound: false,
		},
		{
			name:        "option with leading zero",
			option:      "01",
			expectFound: false,
		},
		{
			name:        "non-numeric option",
			option:      "abc",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, found := GetAppByOption(tt.option)
			assert.Equal(t, tt.expectFound, found)
			if tt.expectFound {
				assert.Equal(t, tt.expectName, app.Name)
				assert.Equal(t, tt.option, app.Option)
			} else {
				assert.Empty(t, app.Option)
				assert.Empty(t, app.Name)
			}
		})
	}
}

func TestDisplayOptions(t *testing.T) {
	// Store original Apps and stdout
	originalApps := Apps
	originalStdout := os.Stdout
	defer func() { 
		Apps = originalApps
		os.Stdout = originalStdout
	}()

	tests := []struct {
		name           string
		apps           []App
		expectedOutput []string
		notExpected    []string
	}{
		{
			name: "sorted numeric options",
			apps: []App{
				{Option: "3", Name: "Third App", ConfFile: "third.conf"},
				{Option: "1", Name: "First App", ConfFile: "first.conf"},
				{Option: "2", Name: "Second App", ConfFile: "second.conf"},
			},
			expectedOutput: []string{
				"Available Hecate backend web apps:",
				"1. First App -> first.conf",
				"2. Second App -> second.conf",
				"3. Third App -> third.conf",
			},
		},
		{
			name: "mixed numeric options",
			apps: []App{
				{Option: "10", Name: "Tenth App", ConfFile: "tenth.conf"},
				{Option: "2", Name: "Second App", ConfFile: "second.conf"},
				{Option: "1", Name: "First App", ConfFile: "first.conf"},
			},
			expectedOutput: []string{
				"1. First App",
				"2. Second App",
				"10. Tenth App",
			},
		},
		{
			name: "non-numeric options excluded",
			apps: []App{
				{Option: "1", Name: "Valid App", ConfFile: "valid.conf"},
				{Option: "abc", Name: "Invalid App", ConfFile: "invalid.conf"},
				{Option: "2", Name: "Another Valid", ConfFile: "another.conf"},
			},
			expectedOutput: []string{
				"1. Valid App",
				"2. Another Valid",
			},
			notExpected: []string{
				"abc. Invalid App",
			},
		},
		{
			name:           "empty apps list",
			apps:           []App{},
			expectedOutput: []string{"Available Hecate backend web apps:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Apps = tt.apps

			// Capture output
			r, w, _ := os.Pipe()
			os.Stdout = w

			DisplayOptions()

			_ = w.Close() // Test output, error not critical
			os.Stdout = originalStdout

			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check expected output
			for _, expected := range tt.expectedOutput {
				assert.Contains(t, output, expected)
			}

			// Check not expected output
			for _, notExpected := range tt.notExpected {
				assert.NotContains(t, output, notExpected)
			}
		})
	}
}

func TestGetUserSelection_ValidInput(t *testing.T) {
	// Store original stdin
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	tests := []struct {
		name             string
		userInput        string
		defaultSelection string
		expectedCount    int
		expectedSelection string
		expectedApps     []string
	}{
		{
			name:             "single selection",
			userInput:        "1\n",
			defaultSelection: "",
			expectedCount:    1,
			expectedSelection: "1",
			expectedApps:     []string{"static website"},
		},
		{
			name:             "multiple selections",
			userInput:        "1,2,3\n",
			defaultSelection: "",
			expectedCount:    3,
			expectedSelection: "1,2,3",
			expectedApps:     []string{"static website", "wazuh", "mattermost"},
		},
		{
			name:             "all selection",
			userInput:        "all\n",
			defaultSelection: "",
			expectedCount:    len(Apps),
			expectedSelection: "all",
		},
		{
			name:             "default selection used",
			userInput:        "\n",
			defaultSelection: "1,2",
			expectedCount:    2,
			expectedSelection: "1,2",
			expectedApps:     []string{"static website", "wazuh"},
		},
		{
			name:             "spaces in input",
			userInput:        " 1 , 2 , 3 \n",
			defaultSelection: "",
			expectedCount:    3,
			expectedSelection: "1 , 2 , 3",
			expectedApps:     []string{"static website", "wazuh", "mattermost"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipe for mocking stdin
			r, w, _ := os.Pipe()
			os.Stdin = r

			// Write test input
			go func() {
				defer func() { _ = w.Close() }() // Test output, error not critical
				io.WriteString(w, tt.userInput)
			}()

			selectedApps, selection := GetUserSelection(tt.defaultSelection)

			assert.Equal(t, tt.expectedCount, len(selectedApps))
			assert.Equal(t, tt.expectedSelection, selection)

			if tt.expectedApps != nil {
				for _, appName := range tt.expectedApps {
					assert.Contains(t, selectedApps, appName)
				}
			}

			r.Close()
		})
	}
}

func TestGetUserSelection_InvalidInput(t *testing.T) {
	// Store original stdin and stdout
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	defer func() { 
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	tests := []struct {
		name        string
		userInputs  []string // Multiple inputs for retry scenarios
		expectedMsg string
	}{
		{
			name:        "invalid option then valid",
			userInputs:  []string{"99\n", "1\n"},
			expectedMsg: "Invalid option: 99",
		},
		{
			name:        "empty input then valid",
			userInputs:  []string{"\n", "1\n"},
			expectedMsg: "",
		},
		{
			name:        "mixed valid and invalid",
			userInputs:  []string{"1,99,2\n", "1\n"},
			expectedMsg: "Invalid option: 99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipes
			r, w, _ := os.Pipe()
			os.Stdin = r
			
			outR, outW, _ := os.Pipe()
			os.Stdout = outW

			// Write test inputs
			go func() {
				defer func() { _ = w.Close() }() // Test output, error not critical
				for _, input := range tt.userInputs {
					io.WriteString(w, input)
				}
			}()

			selectedApps, _ := GetUserSelection("")

			// Should eventually get valid selection
			assert.Greater(t, len(selectedApps), 0)

			_ = w.Close() // Test output, error not critical
			outW.Close()
			os.Stdout = oldStdout

			// Check output for error message
			var buf bytes.Buffer
			io.Copy(&buf, outR)
			output := buf.String()

			if tt.expectedMsg != "" {
				assert.Contains(t, output, tt.expectedMsg)
			}

			r.Close()
		})
	}
}

func TestMarkerHandling(t *testing.T) {
	tests := []struct {
		name     string
		markers  []string
		validate func(t *testing.T, markers []string)
	}{
		{
			name:    "standard port markers",
			markers: []string{"80", "443"},
			validate: func(t *testing.T, markers []string) {
				assert.Len(t, markers, 2)
				assert.Contains(t, markers, "80")
				assert.Contains(t, markers, "443")
			},
		},
		{
			name:    "service markers with names",
			markers: []string{"3478", "coturn:"},
			validate: func(t *testing.T, markers []string) {
				assert.Len(t, markers, 2)
				assert.Contains(t, markers, "3478")
				assert.Contains(t, markers, "coturn:")
			},
		},
		{
			name:    "empty markers",
			markers: []string{},
			validate: func(t *testing.T, markers []string) {
				assert.Empty(t, markers)
			},
		},
		{
			name:    "nil markers",
			markers: nil,
			validate: func(t *testing.T, markers []string) {
				assert.Nil(t, markers)
			},
		},
		{
			name:    "many port markers",
			markers: []string{"25", "587", "465", "110", "995", "143", "993"},
			validate: func(t *testing.T, markers []string) {
				assert.Len(t, markers, 7)
				assert.Contains(t, markers, "25")
				assert.Contains(t, markers, "993")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := App{
				Option:   "1",
				Name:     "Test App",
				ConfFile: "test.conf",
				Markers:  tt.markers,
			}
			tt.validate(t, app.Markers)
		})
	}
}

func TestEdgeCases(t *testing.T) {
	t.Run("GetAppByOption with duplicate options", func(t *testing.T) {
		// This shouldn't happen in practice but test the behavior
		originalApps := Apps
		Apps = []App{
			{Option: "1", Name: "First", ConfFile: "first.conf"},
			{Option: "1", Name: "Duplicate", ConfFile: "dup.conf"},
		}
		defer func() { Apps = originalApps }()

		app, found := GetAppByOption("1")
		assert.True(t, found)
		// Should return the first match
		assert.Equal(t, "First", app.Name)
	})

	t.Run("GetSupportedAppNames with Unicode", func(t *testing.T) {
		originalApps := Apps
		Apps = []App{
			{Option: "1", Name: "App™", ConfFile: "tm.conf"},
			{Option: "2", Name: "应用程序", ConfFile: "chinese.conf"},
			{Option: "3", Name: "Ελληνικά", ConfFile: "greek.conf"},
		}
		defer func() { Apps = originalApps }()

		names := GetSupportedAppNames()
		assert.Len(t, names, 3)
		assert.Equal(t, "app™", names[0])
		assert.Equal(t, "应用程序", names[1])
		assert.Equal(t, "ελληνικά", names[2])
	})

	t.Run("DisplayOptions with very long names", func(t *testing.T) {
		originalApps := Apps
		originalStdout := os.Stdout
		Apps = []App{
			{Option: "1", Name: strings.Repeat("A", 200), ConfFile: "long.conf"},
		}
		defer func() { 
			Apps = originalApps
			os.Stdout = originalStdout
		}()

		// Capture output
		r, w, _ := os.Pipe()
		os.Stdout = w

		// Should not panic
		DisplayOptions()

		_ = w.Close() // Test output, error not critical
		os.Stdout = originalStdout

		var buf bytes.Buffer
		io.Copy(&buf, r)
		output := buf.String()

		// Should contain at least part of the long name
		assert.Contains(t, output, "AAAA")
	})
}