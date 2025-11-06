// pkg/utils/utils.go
package utils

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func DownloadFile(filepath string, url string) error {
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to close output file: %v\n", cerr)
		}
	}()

	// Create HTTP client with timeout to prevent indefinite hangs
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // Allow longer timeout for large downloads
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Minute, // Match context timeout
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http get: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to close HTTP response body: %v\n", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("copy body: %w", err)
	}

	return nil
}
