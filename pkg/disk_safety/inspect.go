package disk_safety

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// DiskInspector provides comprehensive disk analysis and visualization
type DiskInspector struct {
	includeIOMetrics bool
	includeSMART     bool
	focusVG          string
}

// NewDiskInspector creates a new disk inspector
func NewDiskInspector() *DiskInspector {
	return &DiskInspector{
		includeIOMetrics: false,
		includeSMART:     true,
	}
}

// SetOptions configures the inspector behavior
func (di *DiskInspector) SetOptions(includeIO, includeSMART bool, focusVG string) {
	di.includeIOMetrics = includeIO
	di.includeSMART = includeSMART
	di.focusVG = focusVG
}

// InspectionReport contains comprehensive disk analysis
type InspectionReport struct {
	Timestamp         time.Time              `json:"timestamp"`
	PhysicalDisks     []PhysicalDisk         `json:"physical_disks"`
	LVMHierarchy      *LVMHierarchy          `json:"lvm_hierarchy"`
	Filesystems       []FilesystemInfo       `json:"filesystems"`
	MountPoints       []MountState           `json:"mount_points"`
	ExpansionOps      []ExpansionOpportunity `json:"expansion_opportunities"`
	HealthAlerts      []HealthAlert          `json:"health_alerts"`
	SystemOverview    SystemOverview         `json:"system_overview"`
	Recommendations   []string               `json:"recommendations"`
}


// ExpansionOpportunity suggests possible disk expansions
type ExpansionOpportunity struct {
	Type           string `json:"type"` // extend_lv, add_pv, provision_disk
	Target         string `json:"target"`
	AvailableSpace uint64 `json:"available_space"`
	Description    string `json:"description"`
	Commands       []string `json:"commands"`
	Complexity     string `json:"complexity"` // easy, medium, hard
	Risk           string `json:"risk"`       // low, medium, high
}

// HealthAlert represents a system health concern
type HealthAlert struct {
	Level       string `json:"level"` // info, warning, critical
	Component   string `json:"component"`
	Message     string `json:"message"`
	Action      string `json:"action"`
	Urgency     string `json:"urgency"`
}

// SystemOverview provides high-level statistics
type SystemOverview struct {
	TotalDisks         int     `json:"total_disks"`
	TotalCapacity      uint64  `json:"total_capacity"`
	UsedCapacity       uint64  `json:"used_capacity"`
	AvailableCapacity  uint64  `json:"available_capacity"`
	UtilizationPercent float64 `json:"utilization_percent"`
	LVMUtilization     float64 `json:"lvm_utilization"`
	UnusedDisks        int     `json:"unused_disks"`
	HealthScore        int     `json:"health_score"` // 0-100
}

// Inspect performs comprehensive disk analysis
func (di *DiskInspector) Inspect(ctx context.Context) (*InspectionReport, error) {
	logger := otelzap.Ctx(ctx)
	logger.Info("Starting comprehensive disk inspection")

	report := &InspectionReport{
		Timestamp: time.Now(),
	}

	// Gather physical disk information
	physicalDisks, err := di.gatherPhysicalDisks(ctx)
	if err != nil {
		logger.Warn("Failed to gather physical disk info", zap.Error(err))
	} else {
		report.PhysicalDisks = physicalDisks
	}

	// Gather LVM hierarchy
	lvmHierarchy, err := di.gatherLVMHierarchy(ctx)
	if err != nil {
		logger.Warn("Failed to gather LVM hierarchy", zap.Error(err))
	} else {
		report.LVMHierarchy = lvmHierarchy
	}

	// Gather filesystem information
	filesystems, err := di.gatherFilesystems(ctx)
	if err != nil {
		logger.Warn("Failed to gather filesystem info", zap.Error(err))
	} else {
		report.Filesystems = filesystems
	}

	// Gather mount points
	mounts, err := di.gatherMountPoints(ctx)
	if err != nil {
		logger.Warn("Failed to gather mount points", zap.Error(err))
	} else {
		report.MountPoints = mounts
	}

	// Analyze expansion opportunities
	report.ExpansionOps = di.analyzeExpansionOpportunities(report)

	// Generate health alerts
	report.HealthAlerts = di.generateHealthAlerts(report)

	// Calculate system overview
	report.SystemOverview = di.calculateSystemOverview(report)

	// Generate recommendations
	report.Recommendations = di.generateRecommendations(report)

	logger.Info("Disk inspection completed",
		zap.Int("physical_disks", len(report.PhysicalDisks)),
		zap.Int("volume_groups", len(report.LVMHierarchy.VolumeGroups)),
		zap.Int("expansion_ops", len(report.ExpansionOps)),
		zap.Int("health_alerts", len(report.HealthAlerts)))

	return report, nil
}

// GenerateASCIIDiagram creates a visual representation of the disk hierarchy
func (di *DiskInspector) GenerateASCIIDiagram(report *InspectionReport) string {
	var diagram strings.Builder

	diagram.WriteString("=== DISK HIERARCHY OVERVIEW ===\n\n")

	// Physical disks section
	diagram.WriteString("📀 Physical Disks\n")
	diagram.WriteString("┌─────────────────────────────────────────────────────────────┐\n")
	
	for _, disk := range report.PhysicalDisks {
		sizeGB := disk.Size / (1024 * 1024 * 1024)
		usage := disk.UsageType
		if usage == "" {
			usage = "UNUSED ⚡"
		}
		
		diagram.WriteString(fmt.Sprintf("│ ▶ %s (%dGB) - %s - %s%s\n",
			disk.Device, sizeGB, disk.Type, usage, strings.Repeat(" ", 20)))
	}
	diagram.WriteString("└─────────────────────────────────────────────────────────────┘\n\n")

	// LVM hierarchy
	if report.LVMHierarchy != nil && len(report.LVMHierarchy.VolumeGroups) > 0 {
		diagram.WriteString("🗂️  LVM Volume Groups\n")
		
		for _, vg := range report.LVMHierarchy.VolumeGroups {
			if di.focusVG != "" && vg.Name != di.focusVG {
				continue
			}
			
			diagram.WriteString(fmt.Sprintf("┌─ %s (%.1fGB total) ───────────────────────────\n",
				vg.Name, float64(vg.Size)/(1024*1024*1024)))
			
			// Usage bar
			usedPercent := float64(vg.Size-vg.Free) / float64(vg.Size) * 100
			barLength := 40
			usedBars := int(usedPercent * float64(barLength) / 100)
			freeBars := barLength - usedBars
			
			diagram.WriteString("│ Usage: ")
			diagram.WriteString(strings.Repeat("█", usedBars))
			diagram.WriteString(strings.Repeat("░", freeBars))
			diagram.WriteString(fmt.Sprintf(" %.1f%%\n", usedPercent))
			
			diagram.WriteString(fmt.Sprintf("│ Free:  %.1fGB (%.1f%%)\n",
				float64(vg.Free)/(1024*1024*1024),
				float64(vg.Free)/float64(vg.Size)*100))
			
			// Logical volumes
			for _, lv := range report.LVMHierarchy.LogicalVolumes {
				if lv.VGName == vg.Name {
					diagram.WriteString(fmt.Sprintf("│ └─ %s: %.1fGB → %s\n",
						lv.Name,
						float64(lv.Size)/(1024*1024*1024),
						lv.Mountpoint))
				}
			}
			diagram.WriteString("└───────────────────────────────────────────────────\n\n")
		}
	}

	// Expansion opportunities
	if len(report.ExpansionOps) > 0 {
		diagram.WriteString("⚡ Expansion Opportunities\n")
		for i, op := range report.ExpansionOps {
			if i >= 3 { // Limit to top 3 opportunities
				break
			}
			
			spaceGB := op.AvailableSpace / (1024 * 1024 * 1024)
			diagram.WriteString(fmt.Sprintf("   %d. %s (+%.1fGB) - %s risk\n",
				i+1, op.Description, float64(spaceGB), op.Risk))
		}
		diagram.WriteString("\n")
	}

	// Health alerts
	if len(report.HealthAlerts) > 0 {
		diagram.WriteString("🚨 Health Alerts\n")
		for _, alert := range report.HealthAlerts {
			icon := "ℹ️"
			if alert.Level == "warning" {
				icon = "⚠️"
			} else if alert.Level == "critical" {
				icon = "🔴"
			}
			
			diagram.WriteString(fmt.Sprintf("   %s %s: %s\n", icon, alert.Component, alert.Message))
		}
	}

	return diagram.String()
}

// OutputFormat represents different output formats
type OutputFormat string

const (
	FormatTable OutputFormat = "table"
	FormatJSON  OutputFormat = "json"
	FormatYAML  OutputFormat = "yaml"
)

// FormatReport formats the inspection report in the specified format
func (di *DiskInspector) FormatReport(report *InspectionReport, format OutputFormat) (string, error) {
	switch format {
	case FormatJSON:
		data, err := json.MarshalIndent(report, "", "  ")
		return string(data), err
		
	case FormatYAML:
		// Simple YAML formatting (in production, use gopkg.in/yaml.v2)
		return di.formatYAML(report), nil
		
	case FormatTable:
		fallthrough
	default:
		return di.formatTable(report), nil
	}
}

// formatTable creates a human-readable table format
func (di *DiskInspector) formatTable(report *InspectionReport) string {
	var output strings.Builder

	output.WriteString("=== DISK INSPECTION REPORT ===\n")
	output.WriteString(fmt.Sprintf("Generated: %s\n\n", report.Timestamp.Format(time.RFC3339)))

	// System overview
	output.WriteString("SYSTEM OVERVIEW\n")
	output.WriteString(fmt.Sprintf("Total Disks: %d | Total Capacity: %.1fGB | Health Score: %d/100\n",
		report.SystemOverview.TotalDisks,
		float64(report.SystemOverview.TotalCapacity)/(1024*1024*1024),
		report.SystemOverview.HealthScore))
	output.WriteString(fmt.Sprintf("Used: %.1fGB (%.1f%%) | Available: %.1fGB\n\n",
		float64(report.SystemOverview.UsedCapacity)/(1024*1024*1024),
		report.SystemOverview.UtilizationPercent,
		float64(report.SystemOverview.AvailableCapacity)/(1024*1024*1024)))

	// ASCII diagram
	output.WriteString(di.GenerateASCIIDiagram(report))

	// Detailed tables
	if len(report.PhysicalDisks) > 0 {
		output.WriteString("\nPHYSICAL DISKS\n")
		output.WriteString("Device      Size      Type    Health    Usage\n")
		output.WriteString("──────────────────────────────────────────────\n")
		for _, disk := range report.PhysicalDisks {
			output.WriteString(fmt.Sprintf("%-10s  %-8s  %-6s  %-8s  %s\n",
				disk.Device,
				formatSize(uint64(disk.Size)),
				disk.Type,
				disk.SmartStatus,
				disk.UsageType))
		}
		output.WriteString("\n")
	}

	// Expansion opportunities
	if len(report.ExpansionOps) > 0 {
		output.WriteString("EXPANSION OPPORTUNITIES\n")
		output.WriteString("Type           Target                Space     Risk      Description\n")
		output.WriteString("─────────────────────────────────────────────────────────────────\n")
		for _, op := range report.ExpansionOps {
			output.WriteString(fmt.Sprintf("%-13s  %-18s  %-8s  %-8s  %s\n",
				op.Type,
				op.Target,
				formatSize(op.AvailableSpace),
				op.Risk,
				op.Description))
		}
		output.WriteString("\n")
	}

	// Recommendations
	if len(report.Recommendations) > 0 {
		output.WriteString("RECOMMENDATIONS\n")
		for i, rec := range report.Recommendations {
			output.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

	return output.String()
}

// formatYAML creates a simple YAML representation
func (di *DiskInspector) formatYAML(report *InspectionReport) string {
	var output strings.Builder
	
	output.WriteString("disk_inspection:\n")
	output.WriteString(fmt.Sprintf("  timestamp: %s\n", report.Timestamp.Format(time.RFC3339)))
	output.WriteString("  system_overview:\n")
	output.WriteString(fmt.Sprintf("    total_disks: %d\n", report.SystemOverview.TotalDisks))
	output.WriteString(fmt.Sprintf("    health_score: %d\n", report.SystemOverview.HealthScore))
	
	if len(report.ExpansionOps) > 0 {
		output.WriteString("  expansion_opportunities:\n")
		for _, op := range report.ExpansionOps {
			output.WriteString(fmt.Sprintf("    - type: %s\n", op.Type))
			output.WriteString(fmt.Sprintf("      target: %s\n", op.Target))
			output.WriteString(fmt.Sprintf("      available_space_gb: %.1f\n", float64(op.AvailableSpace)/(1024*1024*1024)))
			output.WriteString(fmt.Sprintf("      risk: %s\n", op.Risk))
		}
	}
	
	return output.String()
}

// Helper function to format byte sizes
func formatSize(bytes uint64) string {
	if bytes >= 1024*1024*1024*1024 {
		return fmt.Sprintf("%.1fTB", float64(bytes)/(1024*1024*1024*1024))
	} else if bytes >= 1024*1024*1024 {
		return fmt.Sprintf("%.1fGB", float64(bytes)/(1024*1024*1024))
	} else if bytes >= 1024*1024 {
		return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%dB", bytes)
}

// Implementation of data gathering methods would continue here...
// For brevity, I'll include a few key methods:

func (di *DiskInspector) gatherPhysicalDisks(ctx context.Context) ([]PhysicalDisk, error) {
	cmd := exec.CommandContext(ctx, "lsblk", "-J", "-o", "NAME,SIZE,TYPE,MODEL,MOUNTPOINT")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run lsblk: %w", err)
	}

	// Parse JSON output from lsblk
	var lsblkData struct {
		BlockDevices []struct {
			Name       string `json:"name"`
			Size       string `json:"size"`
			Type       string `json:"type"`
			Model      string `json:"model"`
			Mountpoint string `json:"mountpoint"`
		} `json:"blockdevices"`
	}

	if err := json.Unmarshal(output, &lsblkData); err != nil {
		return nil, fmt.Errorf("failed to parse lsblk output: %w", err)
	}

	var disks []PhysicalDisk
	for _, dev := range lsblkData.BlockDevices {
		if dev.Type == "disk" {
			size := parseSize(dev.Size)
			disk := PhysicalDisk{
				Device:      "/dev/" + dev.Name,
				Model:       dev.Model,
				Size:        int64(size),
				Type:        "HDD", // Default, would need more logic to detect SSD/NVMe
				SmartStatus: "unknown",
				UsageType:   "unknown",
			}
			disks = append(disks, disk)
		}
	}

	return disks, nil
}

// parseSize converts human-readable size to bytes
func parseSize(sizeStr string) uint64 {
	// Simple size parser - in production would be more robust
	re := regexp.MustCompile(`([0-9.]+)([KMGTPE]?)`)
	matches := re.FindStringSubmatch(sizeStr)
	if len(matches) != 3 {
		return 0
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0
	}

	multiplier := uint64(1)
	switch matches[2] {
	case "K":
		multiplier = 1024
	case "M":
		multiplier = 1024 * 1024
	case "G":
		multiplier = 1024 * 1024 * 1024
	case "T":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return uint64(value * float64(multiplier))
}


// Placeholder implementations for remaining methods
func (di *DiskInspector) gatherLVMHierarchy(ctx context.Context) (*LVMHierarchy, error) {
	// Implementation would gather PV, VG, LV information
	return &LVMHierarchy{}, nil
}

func (di *DiskInspector) gatherFilesystems(ctx context.Context) ([]FilesystemInfo, error) {
	// Implementation would use df command to gather filesystem info
	return []FilesystemInfo{}, nil
}

func (di *DiskInspector) gatherMountPoints(ctx context.Context) ([]MountState, error) {
	// Implementation would parse /proc/mounts
	return []MountState{}, nil
}

func (di *DiskInspector) analyzeExpansionOpportunities(report *InspectionReport) []ExpansionOpportunity {
	var opportunities []ExpansionOpportunity
	
	// Analyze VG free space for LV extensions
	if report.LVMHierarchy != nil {
		for _, vg := range report.LVMHierarchy.VolumeGroups {
			if vg.Free > 1024*1024*1024 { // > 1GB free
				opportunities = append(opportunities, ExpansionOpportunity{
					Type:           "extend_lv",
					Target:         vg.Name,
					AvailableSpace: uint64(vg.Free),
					Description:    fmt.Sprintf("Extend LV in %s using %s free space", vg.Name, formatSize(uint64(vg.Free))),
					Risk:           "low",
					Complexity:     "easy",
				})
			}
		}
	}
	
	// Sort by available space
	sort.Slice(opportunities, func(i, j int) bool {
		return opportunities[i].AvailableSpace > opportunities[j].AvailableSpace
	})
	
	return opportunities
}

func (di *DiskInspector) generateHealthAlerts(report *InspectionReport) []HealthAlert {
	var alerts []HealthAlert
	
	// Check for low disk space
	for _, fs := range report.Filesystems {
		if fs.UsePercent > 90 {
			alerts = append(alerts, HealthAlert{
				Level:     "critical",
				Component: fs.Mountpoint,
				Message:   fmt.Sprintf("Filesystem %s is %.1f%% full", fs.Mountpoint, fs.UsePercent),
				Action:    "Free up space or extend filesystem",
				Urgency:   "high",
			})
		} else if fs.UsePercent > 80 {
			alerts = append(alerts, HealthAlert{
				Level:     "warning",
				Component: fs.Mountpoint,
				Message:   fmt.Sprintf("Filesystem %s is %.1f%% full", fs.Mountpoint, fs.UsePercent),
				Action:    "Consider freeing up space",
				Urgency:   "medium",
			})
		}
	}
	
	return alerts
}

func (di *DiskInspector) calculateSystemOverview(report *InspectionReport) SystemOverview {
	overview := SystemOverview{
		TotalDisks:  len(report.PhysicalDisks),
		HealthScore: 100, // Start with perfect score
	}
	
	// Calculate totals
	for _, disk := range report.PhysicalDisks {
		overview.TotalCapacity += uint64(disk.Size)
		if disk.UsageType == "" || disk.UsageType == "UNUSED" {
			overview.UnusedDisks++
		}
	}
	
	for _, fs := range report.Filesystems {
		overview.UsedCapacity += uint64(fs.UsedSize)
		overview.AvailableCapacity += uint64(fs.FreeSize)
	}
	
	if overview.TotalCapacity > 0 {
		overview.UtilizationPercent = float64(overview.UsedCapacity) / float64(overview.TotalCapacity) * 100
	}
	
	// Reduce health score for issues
	for _, alert := range report.HealthAlerts {
		switch alert.Level {
		case "critical":
			overview.HealthScore -= 20
		case "warning":
			overview.HealthScore -= 10
		}
	}
	
	if overview.HealthScore < 0 {
		overview.HealthScore = 0
	}
	
	return overview
}

func (di *DiskInspector) generateRecommendations(report *InspectionReport) []string {
	var recommendations []string
	
	if len(report.ExpansionOps) > 0 {
		recommendations = append(recommendations, 
			fmt.Sprintf("Consider expanding storage - %d expansion opportunities available", len(report.ExpansionOps)))
	}
	
	if report.SystemOverview.UnusedDisks > 0 {
		recommendations = append(recommendations,
			fmt.Sprintf("You have %d unused disks that could be added to your storage pool", report.SystemOverview.UnusedDisks))
	}
	
	if report.SystemOverview.UtilizationPercent > 80 {
		recommendations = append(recommendations, "Storage utilization is high - consider adding more capacity")
	}
	
	return recommendations
}