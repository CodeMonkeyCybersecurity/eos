// Package output provides output formatting utilities
package output

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/system_services"
)

// ServiceListToStdout outputs a service list result to stdout
func ServiceListToStdout(result *system_services.ServiceListResult, asJSON bool) error {
	if asJSON {
		return JSONToStdout(result)
	}

	// Text output
	tw := NewTable().
		WithHeaders("NAME", "LOAD", "ACTIVE", "SUB", "DESCRIPTION")
	
	fmt.Printf("Systemd Services (found %d):\n", result.Count)
	
	for _, service := range result.Services {
		// Truncate description if too long
		desc := service.Description
		if len(desc) > 35 {
			desc = desc[:32] + "..."
		}
		
		tw.AddRow(service.Name, service.LoadState, service.ActiveState,
			service.SubState, desc)
	}
	
	return tw.Render()
}

// ServiceOperationToStdout outputs a service operation result to stdout
func ServiceOperationToStdout(result *system_services.ServiceOperation, asJSON bool) error {
	if asJSON {
		return JSONToStdout(result)
	}

	// Text output
	fmt.Printf("Service Operation: %s\n", result.Operation)
	fmt.Printf("Service: %s\n", result.Service)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Println(strings.Repeat("=", 50))

	if result.Success {
		fmt.Println("Operation completed successfully!")
	} else {
		fmt.Println("❌ Operation failed!")
	}

	fmt.Printf("\nMessage: %s\n", result.Message)

	if result.DryRun {
		fmt.Println("\n🔍 This was a dry run - no actual changes were made.")
	}

	return nil
}

// ServiceStatusToStdout outputs a service status to stdout  
func ServiceStatusToStdout(result *system_services.ServiceInfo, asJSON bool) error {
	if asJSON {
		return JSONToStdout(result)
	}

	// Text output
	fmt.Printf("Service Status: %s\n", result.Name)
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Description: %s\n", result.Description)
	fmt.Printf("Load State: %s\n", result.LoadState)
	fmt.Printf("Active State: %s\n", result.ActiveState)
	fmt.Printf("Sub State: %s\n", result.SubState)

	if result.Running {
		fmt.Println("Status: RUNNING")
	} else {
		fmt.Println("Status: ❌ NOT RUNNING")
	}

	return nil
}

// ServiceWriter provides methods for formatting service-related output
type ServiceWriter struct {
	writer io.Writer
}

// NewServiceWriter creates a new service writer
func NewServiceWriter() *ServiceWriter {
	return &ServiceWriter{writer: os.Stdout}
}

// NewServiceWriterTo creates a new service writer that writes to the specified writer
func NewServiceWriterTo(w io.Writer) *ServiceWriter {
	return &ServiceWriter{writer: w}
}
