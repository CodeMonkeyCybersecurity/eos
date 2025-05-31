package interaction

import "testing"

func FuzzNormalizeYesNoInput(f *testing.F) {
	// Seed with a few common answers
	f.Add("yes")
	f.Add("no")
	f.Add("Y")
	f.Add("n")
	f.Add("  yEs ")
	f.Add("  ")
	f.Add("not-a-valid-answer")

	f.Fuzz(func(t *testing.T, input string) {
		_, _ = NormalizeYesNoInput(input)
		// You can add more checks if you want,
		// but fuzzing will mainly reveal panics or logic bugs.
	})
}

func FuzzValidateNonEmpty(f *testing.F) {
	f.Add("")
	f.Add("   ")
	f.Add("hello")
	f.Add("\n\t")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateNonEmpty(s)
	})
}

func FuzzValidateUsername(f *testing.F) {
	f.Add("")
	f.Add("root")
	f.Add("user_1")
	f.Add("Auser")
	f.Add("bad-user-!")
	f.Add("verylongusername_morethan32characterslong")
	f.Add("_underscore")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateUsername(s)
	})
}

func FuzzValidateEmail(f *testing.F) {
	f.Add("")
	f.Add("notanemail")
	f.Add("foo@bar.com")
	f.Add("foo@bar")
	f.Add("foo@bar.com.au")
	f.Add("foo@bar..com")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateEmail(s)
	})
}

func FuzzValidateURL(f *testing.F) {
	f.Add("")
	f.Add("http://example.com")
	f.Add("https://example.com/path")
	f.Add("ftp://foo")
	f.Add("not a url")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateURL(s)
	})
}

func FuzzValidateIP(f *testing.F) {
	f.Add("")
	f.Add("127.0.0.1")
	f.Add("256.256.256.256")
	f.Add("::1")
	f.Add("abcd")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateIP(s)
	})
}

func FuzzValidateNoShellMeta(f *testing.F) {
	f.Add("hello")
	f.Add("rm -rf /")
	f.Add("safe_input")
	f.Add("`cat /etc/passwd`")
	f.Add("user$name")
	f.Add("nothing_special")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ValidateNoShellMeta(s)
	})
}
