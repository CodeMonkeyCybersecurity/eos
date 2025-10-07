package disk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TransactionLog manages transaction records for rollback capability
type TransactionLog struct {
	logDir       string
	transactions map[string]*Transaction
	mu           sync.RWMutex
}

// NewTransactionLog creates a new transaction log
func NewTransactionLog() *TransactionLog {
	logDir := "/var/log/eos/kvm-disk-transactions"
	os.MkdirAll(logDir, 0755)

	return &TransactionLog{
		logDir:       logDir,
		transactions: make(map[string]*Transaction),
	}
}

// Begin starts a new transaction
func (tl *TransactionLog) Begin(vmName string, changeBytes int64) *Transaction {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	tx := &Transaction{
		ID:          fmt.Sprintf("resize-%s-%d", vmName, time.Now().Unix()),
		VMName:      vmName,
		StartTime:   time.Now(),
		ChangeBytes: changeBytes,
		Steps:       make(map[string]StepResult),
	}

	tl.transactions[tx.ID] = tx
	tl.Save(tx) // Save initial state

	return tx
}

// RecordStep records a step in the transaction
func (tx *Transaction) RecordStep(name string, result StepResult) {
	tx.Steps[name] = result
}

// Save persists a transaction to disk
func (tl *TransactionLog) Save(tx *Transaction) error {
	path := filepath.Join(tl.logDir, tx.ID+".json")

	data, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// GetLatest retrieves the most recent transaction for a VM
func (tl *TransactionLog) GetLatest(vmName string) *Transaction {
	tl.mu.RLock()
	defer tl.mu.RUnlock()

	var latest *Transaction
	var latestTime time.Time

	for _, tx := range tl.transactions {
		if tx.VMName == vmName && tx.StartTime.After(latestTime) {
			latest = tx
			latestTime = tx.StartTime
		}
	}

	// If not in memory, check disk
	if latest == nil {
		pattern := filepath.Join(tl.logDir, fmt.Sprintf("resize-%s-*.json", vmName))
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			return nil
		}

		// Load the most recent one
		for _, match := range matches {
			data, err := os.ReadFile(match)
			if err != nil {
				continue
			}

			var tx Transaction
			if err := json.Unmarshal(data, &tx); err != nil {
				continue
			}

			if tx.StartTime.After(latestTime) {
				latest = &tx
				latestTime = tx.StartTime
			}
		}
	}

	return latest
}
