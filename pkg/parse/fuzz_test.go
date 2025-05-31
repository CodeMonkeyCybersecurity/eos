// pkg/parse/fuzz_test.go

package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzSplitAndTrim(f *testing.F) {
	f.Add("")                   // empty
	f.Add("a,b,c")              // normal CSV
	f.Add("   a   ,   b  ,c  ") // lots of whitespace
	f.Add(", , ,")              // just commas and spaces
	f.Add("one,two,three,four") // multi-token
	f.Add(" a , ,b ,  , c  ,")  // empty tokens
	f.Add("a")                  // single
	f.Add("a,,b")               // double comma
	f.Add(",,")                 // all empty
	f.Add("🦄,   🚀,   🍕")        // unicode
	f.Fuzz(func(t *testing.T, s string) {
		_ = SplitAndTrim(s)
	})
}

func TestAppendIfMissing(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "test.txt")

	// Test adding a line to a new file
	if err := AppendIfMissing(file, "line1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Test idempotence (should not duplicate line)
	if err := AppendIfMissing(file, "line1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(file)
	count := strings.Count(string(data), "line1")
	if count != 1 {
		t.Errorf("expected line1 once, got %d times", count)
	}
}
