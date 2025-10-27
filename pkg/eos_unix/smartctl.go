// pkg/eos_unix/smartctl.go

package eos_unix

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_opa"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/telemetry"
	cerr "github.com/cockroachdb/errors"
	"github.com/go-playground/validator/v10"
	"go.opentelemetry.io/otel/attribute"
)

var validate = validator.New()

type SmartReport struct {
	Device               string `validate:"required"`
	DevType              string
	HealthStatus         string `validate:"required"`
	PercentLifeRemaining int    `validate:"gte=0,lte=100"`
	ReallocatedSectors   int    `validate:"gte=0"`
	UncorrectableErrors  int    `validate:"gte=0"`
	Warnings             []string
}

func DiscoverDevices(ctx context.Context) ([][2]string, error) {
	ctx, span := telemetry.Start(ctx, "eos_unix.DiscoverDevices")
	defer span.End()

	out, err := exec.CommandContext(ctx, "smartctl", "--scan").Output()
	if err != nil {
		return nil, cerr.Wrap(err, "failed to scan for devices")
	}

	var devices [][2]string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	re := regexp.MustCompile(`(/dev/\S+)(?:\s+-d\s+(\S+))?`)

	for scanner.Scan() {
		match := re.FindStringSubmatch(scanner.Text())
		if len(match) >= 2 {
			dev := match[1]
			typ := ""
			if len(match) == 3 {
				typ = match[2]
			}
			devices = append(devices, [2]string{dev, typ})
		}
	}
	return devices, nil
}

func CheckSMART(ctx context.Context, device, devType string) (*SmartReport, error) {
	ctx, span := telemetry.Start(ctx, "eos_unix.CheckSMART",
		attribute.String("device", device),
		attribute.String("type", devType),
	)
	defer span.End()

	args := []string{"-a"}
	if devType != "" {
		args = append(args, "-d", devType)
	}
	args = append(args, device)

	out, err := exec.CommandContext(ctx, "smartctl", args...).Output()
	if err != nil {
		return nil, cerr.Wrapf(err, "smartctl failed on %q", device)
	}

	report := &SmartReport{Device: device, DevType: devType}
	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.Contains(line, "SMART overall-health"):
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				report.HealthStatus = strings.TrimSpace(parts[1])
			}
		case strings.Contains(line, "Percent_Lifetime_Remain"):
			extractInt(line, &report.PercentLifeRemaining, &report.Warnings, "<10%", 10)
		case strings.Contains(line, "Reallocated_Sector_Ct"), strings.Contains(line, "Reallocated_Event_Count"):
			extractInt(line, &report.ReallocatedSectors, &report.Warnings, ">0 sectors", 1)
		case strings.Contains(line, "Offline_Uncorrectable"):
			extractInt(line, &report.UncorrectableErrors, &report.Warnings, ">0 errors", 1)
		}
	}

	if err := validate.Struct(report); err != nil {
		return nil, cerr.Wrap(err, "invalid SMART report structure")
	}

	// Optional policy gate
	if err := eos_opa.Enforce(ctx, "smart", report); err != nil {
		return nil, cerr.Wrap(err, "SMART policy rejected")
	}

	return report, nil
}

func extractInt(line string, target *int, warnings *[]string, message string, threshold int) {
	fields := strings.Fields(line)
	if len(fields) >= 10 {
		if val, err := strconv.Atoi(fields[9]); err == nil {
			*target = val
			if (threshold < 10 && val < threshold) || (threshold >= 10 && val >= threshold) {
				*warnings = append(*warnings, message)
			}
		}
	}
}
