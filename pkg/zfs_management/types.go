package zfs_management

import (
	"time"
)

// ZFSPool represents a ZFS storage pool
type ZFSPool struct {
	Name     string `json:"name"`
	Size     string `json:"size"`
	Alloc    string `json:"alloc"`
	Free     string `json:"free"`
	Frag     string `json:"frag"`
	Cap      string `json:"cap"`
	Dedup    string `json:"dedup"`
	Health   string `json:"health"`
	AltRoot  string `json:"altroot"`
}

// ZFSFilesystem represents a ZFS filesystem or dataset
type ZFSFilesystem struct {
	Name       string `json:"name"`
	Used       string `json:"used"`
	Available  string `json:"available"`
	Refer      string `json:"refer"`
	Mountpoint string `json:"mountpoint"`
	Type       string `json:"type"`
}

// ZFSOperationResult represents the result of a ZFS operation
type ZFSOperationResult struct {
	Timestamp   time.Time `json:"timestamp"`
	Operation   string    `json:"operation"`
	Target      string    `json:"target"`
	Success     bool      `json:"success"`
	Output      string    `json:"output"`
	Error       string    `json:"error,omitempty"`
	DryRun      bool      `json:"dry_run"`
}

// ZFSListResult contains the results of listing ZFS resources
type ZFSListResult struct {
	Timestamp   time.Time       `json:"timestamp"`
	Pools       []ZFSPool       `json:"pools,omitempty"`
	Filesystems []ZFSFilesystem `json:"filesystems,omitempty"`
	Count       int             `json:"count"`
}

// ZFSConfig contains configuration for ZFS management operations
type ZFSConfig struct {
	DryRun       bool     `json:"dry_run" mapstructure:"dry_run"`
	Verbose      bool     `json:"verbose" mapstructure:"verbose"`
	Force        bool     `json:"force" mapstructure:"force"`
	Recursive    bool     `json:"recursive" mapstructure:"recursive"`
	ConfirmDestructive bool `json:"confirm_destructive" mapstructure:"confirm_destructive"`
}

// DefaultZFSConfig returns a configuration with sensible defaults
func DefaultZFSConfig() *ZFSConfig {
	return &ZFSConfig{
		DryRun:             false,
		Verbose:            true,
		Force:              false,
		Recursive:          false,
		ConfirmDestructive: true,
	}
}

// ZFSMenuOption represents a menu option for the interactive TUI
type ZFSMenuOption struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Destructive bool   `json:"destructive"`
}

// ZFSMenuOptions defines the available menu options
var ZFSMenuOptions = []ZFSMenuOption{
	{
		Key:         "1",
		Label:       "List ZFS Pools",
		Description: "Display all ZFS storage pools and their status",
		Destructive: false,
	},
	{
		Key:         "2",
		Label:       "List ZFS Filesystems",
		Description: "Display all ZFS filesystems and datasets",
		Destructive: false,
	},
	{
		Key:         "3",
		Label:       "Expand Pool",
		Description: "Add a device to an existing ZFS pool",
		Destructive: false,
	},
	{
		Key:         "4",
		Label:       "Destroy Pool",
		Description: "Permanently destroy a ZFS pool and all its data",
		Destructive: true,
	},
	{
		Key:         "5",
		Label:       "Destroy Filesystem",
		Description: "Permanently destroy a ZFS filesystem or dataset",
		Destructive: true,
	},
	{
		Key:         "q",
		Label:       "Quit",
		Description: "Exit the ZFS management interface",
		Destructive: false,
	},
}