package vault

import "testing"

func TestIsAffirmativeConsent(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{input: "yes", want: true},
		{input: "YES", want: true},
		{input: "y", want: true},
		{input: " Y ", want: true},
		{input: "no", want: false},
		{input: "n", want: false},
		{input: "", want: false},
		{input: "yep", want: false},
	}

	for _, tt := range tests {
		if got := isAffirmativeConsent(tt.input); got != tt.want {
			t.Fatalf("isAffirmativeConsent(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
