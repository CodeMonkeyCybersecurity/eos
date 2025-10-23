//go:build darwin
// +build darwin

// pkg/kvm/disk_stub_darwin.go
// macOS stub for disk management operations

package kvm

import (
	"context"
	"fmt"
)

// NewManager stub
func NewManager() *Manager {
	return &Manager{}
}

// Manager.Resize stub
func (m *Manager) Resize(ctx context.Context, req *ResizeRequest) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// Manager.Rollback stub
func (m *Manager) Rollback(ctx context.Context, vmName string) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// Assess stub
func Assess(ctx context.Context, vmName string, change *SizeChange) (*Assessment, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// DisplayAssessment stub
func DisplayAssessment(ctx context.Context, a *Assessment) {
	// No-op on macOS
}

// DisplayPlan stub
func DisplayPlan(ctx context.Context, a *Assessment) {
	// No-op on macOS
}

// DisplayPostResizeInstructions stub
func DisplayPostResizeInstructions(ctx context.Context, a *Assessment) {
	// No-op on macOS
}

// ConfirmResize stub
func ConfirmResize(a *Assessment) bool {
	return false
}

// CountHighRisks stub
func CountHighRisks(risks []Risk) int {
	return 0
}

// ParseSizeChange stub
func ParseSizeChange(spec string) (*SizeChange, error) {
	return nil, fmt.Errorf(errLibvirtMacOS)
}

// FormatBytes stub
func FormatBytes(bytes int64) string {
	return "0 B"
}

// CalculateTargetSize stub
func CalculateTargetSize(currentBytes int64, change *SizeChange) (int64, error) {
	return 0, fmt.Errorf(errLibvirtMacOS)
}

// CalculateRequiredSpace stub
func CalculateRequiredSpace(currentBytes int64, targetBytes int64) int64 {
	return 0
}

// NewTransactionLog stub
func NewTransactionLog() *TransactionLog {
	return &TransactionLog{}
}

// TransactionLog.Begin stub
func (tl *TransactionLog) Begin(vmName string, changeBytes int64) *Transaction {
	return &Transaction{}
}

// Transaction.RecordStep stub
func (tx *Transaction) RecordStep(name string, result StepResult) {
	// No-op on macOS
}

// TransactionLog.Save stub
func (tl *TransactionLog) Save(tx *Transaction) error {
	return fmt.Errorf(errLibvirtMacOS)
}

// TransactionLog.GetLatest stub
func (tl *TransactionLog) GetLatest(vmName string) *Transaction {
	return nil
}

// GuestManager.ResizeFilesystem stub
func (gm *GuestManager) ResizeFilesystem(ctx context.Context, assessment *Assessment) error {
	return fmt.Errorf(errLibvirtMacOS)
}
