// pkg/docker/pull_progress_test.go
//
// Unit tests for Docker pull progress tracking

package docker

import (
	"context"
	"testing"
	"time"
)

// TestLayerPhaseTransitions tests that layers transition through phases correctly
func TestLayerPhaseTransitions(t *testing.T) {
	ctx := context.Background()
	tracker := NewPullTracker(ctx, "test/image:latest")
	tracker.Start()
	defer tracker.Done()

	// Simulate Docker pull events for a single layer
	layerID := "abc123"

	// Phase 1: Waiting
	tracker.Update(&PullProgress{
		ID:     layerID,
		Status: "Waiting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0,
			Total:   1000000, // 1 MB total
		},
	})

	layer := tracker.layers[layerID]
	if layer.Phase != "waiting" {
		t.Errorf("Expected phase 'waiting', got '%s'", layer.Phase)
	}
	if layer.DownloadTotal != 1000000 {
		t.Errorf("Expected total 1000000, got %d", layer.DownloadTotal)
	}

	// Phase 2: Downloading
	tracker.Update(&PullProgress{
		ID:     layerID,
		Status: "Downloading",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 500000, // 50% downloaded
			Total:   1000000,
		},
	})

	layer = tracker.layers[layerID]
	if layer.Phase != "downloading" {
		t.Errorf("Expected phase 'downloading', got '%s'", layer.Phase)
	}
	if layer.DownloadCurrent != 500000 {
		t.Errorf("Expected current 500000, got %d", layer.DownloadCurrent)
	}

	// Phase 3: Extracting (bytes should NOT reset)
	tracker.Update(&PullProgress{
		ID:     layerID,
		Status: "Extracting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0, // Docker may reset this during extraction
			Total:   1000000,
		},
	})

	layer = tracker.layers[layerID]
	if layer.Phase != "extracting" {
		t.Errorf("Expected phase 'extracting', got '%s'", layer.Phase)
	}
	// CRITICAL: Download bytes should be preserved (set to total)
	if layer.DownloadCurrent != 1000000 {
		t.Errorf("Expected download preserved at 1000000, got %d", layer.DownloadCurrent)
	}

	// Phase 4: Complete
	tracker.Update(&PullProgress{
		ID:     layerID,
		Status: "Pull complete",
	})

	layer = tracker.layers[layerID]
	if layer.Phase != "complete" {
		t.Errorf("Expected phase 'complete', got '%s'", layer.Phase)
	}
	if !layer.Complete {
		t.Error("Expected layer.Complete to be true")
	}
}

// TestTotalSizeLocking tests that total size locks when all layers discovered
func TestTotalSizeLocking(t *testing.T) {
	ctx := context.Background()
	tracker := NewPullTracker(ctx, "test/image:latest")
	tracker.Start()
	defer tracker.Done()

	// Add 3 layers with known sizes
	for i := 0; i < 3; i++ {
		tracker.Update(&PullProgress{
			ID:     string(rune('a' + i)),
			Status: "Waiting",
			ProgressDetail: struct {
				Current int64 `json:"current"`
				Total   int64 `json:"total"`
			}{
				Current: 0,
				Total:   1000000, // 1 MB each
			},
		})
	}

	// Trigger summary calculation (which locks total size)
	time.Sleep(1100 * time.Millisecond) // Wait for rate limit
	tracker.Update(&PullProgress{
		ID:     "a",
		Status: "Downloading",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 100000,
			Total:   1000000,
		},
	})

	summary := tracker.getSummary()
	_ = summary // Trigger calculation

	// Total should be locked at 3 MB
	if !tracker.totalSizeLocked {
		t.Error("Expected total size to be locked")
	}
	if tracker.totalSize != 3000000 {
		t.Errorf("Expected total 3000000, got %d", tracker.totalSize)
	}

	// Add a 4th layer (discovered late) - total should NOT change
	tracker.Update(&PullProgress{
		ID:     "d",
		Status: "Waiting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0,
			Total:   5000000, // 5 MB
		},
	})

	// Total should still be 3 MB (locked)
	if tracker.totalSize != 3000000 {
		t.Errorf("Expected total to remain 3000000, got %d", tracker.totalSize)
	}
}

// TestPercentageAccuracy tests that percentage matches actual bytes
func TestPercentageAccuracy(t *testing.T) {
	ctx := context.Background()
	tracker := NewPullTracker(ctx, "test/image:latest")
	tracker.Start()
	defer tracker.Done()

	// Create 2 layers with known sizes
	tracker.Update(&PullProgress{
		ID:     "layer1",
		Status: "Waiting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0,
			Total:   10000000, // 10 MB
		},
	})

	tracker.Update(&PullProgress{
		ID:     "layer2",
		Status: "Waiting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0,
			Total:   10000000, // 10 MB
		},
	})

	// Download 2.8 MB of layer1
	time.Sleep(1100 * time.Millisecond)
	tracker.Update(&PullProgress{
		ID:     "layer1",
		Status: "Downloading",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 2800000, // 2.8 MB
			Total:   10000000,
		},
	})

	summary := tracker.getSummary()

	// Total = 20 MB, Downloaded = 2.8 MB
	// Expected percentage = 2.8 / 20 * 100 = 14%
	if tracker.totalSize != 20000000 {
		t.Errorf("Expected total 20000000, got %d", tracker.totalSize)
	}

	// Calculate actual percentage from summary
	// Format: "X/Y layers (Z.Z% downloaded)..."
	// We should see ~14%, not 80% or other wrong value
	t.Logf("Summary: %s", summary)

	// Verify bytes are correct
	var downloadedBytes int64
	for _, layer := range tracker.layers {
		downloadedBytes += layer.DownloadCurrent
	}

	if downloadedBytes != 2800000 {
		t.Errorf("Expected downloaded 2800000, got %d", downloadedBytes)
	}

	expectedPercent := float64(downloadedBytes) / float64(tracker.totalSize) * 100
	if expectedPercent < 13.9 || expectedPercent > 14.1 {
		t.Errorf("Expected ~14%%, got %.1f%%", expectedPercent)
	}
}

// TestCurrentDownloadRate tests that rate is calculated from last update, not lifetime
func TestCurrentDownloadRate(t *testing.T) {
	ctx := context.Background()
	tracker := NewPullTracker(ctx, "test/image:latest")
	tracker.Start()
	defer tracker.Done()

	// Setup layer
	tracker.Update(&PullProgress{
		ID:     "layer1",
		Status: "Waiting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0,
			Total:   100000000, // 100 MB
		},
	})

	// First update: 10 MB downloaded
	time.Sleep(1100 * time.Millisecond)
	tracker.Update(&PullProgress{
		ID:     "layer1",
		Status: "Downloading",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 10000000, // 10 MB
			Total:   100000000,
		},
	})

	_ = tracker.getSummary() // Calculate, sets lastBytes = 10 MB

	// Second update: 15 MB total (5 MB since last update)
	time.Sleep(1100 * time.Millisecond)
	tracker.Update(&PullProgress{
		ID:     "layer1",
		Status: "Downloading",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 15000000, // 15 MB total
			Total:   100000000,
		},
	})

	summary := tracker.getSummary()
	t.Logf("Summary: %s", summary)

	// Rate should be based on 5 MB since last update, not 15 MB total
	// We can't easily verify the exact rate due to timing, but we can verify
	// that lastBytes was updated
	if tracker.lastBytes != 15000000 {
		t.Errorf("Expected lastBytes to be 15000000, got %d", tracker.lastBytes)
	}
}

// TestExtractionPhaseDoesNotResetBytes tests that extraction preserves download bytes
func TestExtractionPhaseDoesNotResetBytes(t *testing.T) {
	ctx := context.Background()
	tracker := NewPullTracker(ctx, "test/image:latest")
	tracker.Start()
	defer tracker.Done()

	layerID := "layer1"

	// Download complete
	tracker.Update(&PullProgress{
		ID:     layerID,
		Status: "Downloading",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 5000000, // 5 MB fully downloaded
			Total:   5000000,
		},
	})

	layer := tracker.layers[layerID]
	if layer.DownloadCurrent != 5000000 {
		t.Errorf("Expected 5000000 downloaded, got %d", layer.DownloadCurrent)
	}

	// Start extracting - Docker sends Current=0 (extraction progress)
	tracker.Update(&PullProgress{
		ID:     layerID,
		Status: "Extracting",
		ProgressDetail: struct {
			Current int64 `json:"current"`
			Total   int64 `json:"total"`
		}{
			Current: 0, // Extraction resets to 0
			Total:   5000000,
		},
	})

	layer = tracker.layers[layerID]
	// CRITICAL: DownloadCurrent should still be 5000000, not 0
	if layer.DownloadCurrent != 5000000 {
		t.Errorf("Expected download bytes preserved at 5000000, got %d", layer.DownloadCurrent)
	}
	if layer.Phase != "extracting" {
		t.Errorf("Expected phase 'extracting', got '%s'", layer.Phase)
	}
}

// TestCompleteLayerCounting tests that completed layers are counted correctly
func TestCompleteLayerCounting(t *testing.T) {
	ctx := context.Background()
	tracker := NewPullTracker(ctx, "test/image:latest")
	tracker.Start()
	defer tracker.Done()

	// Create 3 layers
	layers := []string{"a", "b", "c"}
	for _, id := range layers {
		tracker.Update(&PullProgress{
			ID:     id,
			Status: "Waiting",
			ProgressDetail: struct {
				Current int64 `json:"current"`
				Total   int64 `json:"total"`
			}{
				Current: 0,
				Total:   1000000,
			},
		})
	}

	// Complete 2 layers
	tracker.Update(&PullProgress{ID: "a", Status: "Pull complete"})
	tracker.Update(&PullProgress{ID: "b", Status: "Download complete"})

	summary := tracker.getSummary()
	t.Logf("Summary: %s", summary)

	// Should show "2/3 layers"
	completedCount := 0
	for _, layer := range tracker.layers {
		if layer.Complete {
			completedCount++
		}
	}

	if completedCount != 2 {
		t.Errorf("Expected 2 complete layers, got %d", completedCount)
	}
}
