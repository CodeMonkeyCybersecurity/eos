package testutil

// TestError implements error interface for testing purposes
type TestError struct {
	message string
}

func (e *TestError) Error() string {
	return e.message
}

// NewTestError creates a new test error with the given message
func NewTestError(message string) error {
	return &TestError{message: message}
}
