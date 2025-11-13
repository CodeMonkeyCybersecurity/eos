// pkg/hecate/backend/display.go

package backend

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate/hybrid"
	"gopkg.in/yaml.v3"
)

// DisplayBackendsTable displays backends in table format
func DisplayBackendsTable(backends []BackendSummary, verbose bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if verbose {
		_, _ = fmt.Fprintln(w, "ID\tNAME\tPUBLIC DOMAIN\tLOCAL ADDRESS\tDATACENTER\tSTATUS\tCREATED\tLAST SEEN")
		_, _ = fmt.Fprintln(w, "--\t----\t-------------\t-------------\t----------\t------\t-------\t---------")
	} else {
		_, _ = fmt.Fprintln(w, "ID\tNAME\tPUBLIC DOMAIN\tSTATUS\tLAST SEEN")
		_, _ = fmt.Fprintln(w, "--\t----\t-------------\t------\t---------")
	}

	for _, backend := range backends {
		if verbose {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				backend.ID,
				backend.Name,
				backend.PublicDomain,
				backend.LocalAddress,
				backend.Datacenter,
				backend.Status,
				backend.Created.Format("2006-01-02 15:04"),
				backend.LastSeen.Format("2006-01-02 15:04"))
		} else {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				backend.ID,
				backend.Name,
				backend.PublicDomain,
				backend.Status,
				backend.LastSeen.Format("2006-01-02 15:04"))
		}
	}

	return w.Flush()
}

// DisplayBackendTable displays detailed backend information in table format
func DisplayBackendTable(backend *BackendDetails, verbose bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(w, "Backend ID:\t%s\n", backend.ID)
	_, _ = fmt.Fprintf(w, "Name:\t%s\n", backend.Name)
	_, _ = fmt.Fprintf(w, "Public Domain:\t%s\n", backend.PublicDomain)
	_, _ = fmt.Fprintf(w, "Local Address:\t%s\n", backend.LocalAddress)
	_, _ = fmt.Fprintf(w, "Frontend DC:\t%s\n", backend.FrontendDC)
	_, _ = fmt.Fprintf(w, "Backend DC:\t%s\n", backend.BackendDC)
	_, _ = fmt.Fprintf(w, "Connection Type:\t%s\n", backend.ConnectionType)
	_, _ = fmt.Fprintf(w, "Status:\t%s\n", backend.Status)
	_, _ = fmt.Fprintf(w, "Created:\t%s\n", backend.Created.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(w, "Updated:\t%s\n", backend.Updated.Format("2006-01-02 15:04:05"))

	if verbose && backend.Tunnel != nil {
		_, _ = fmt.Fprintf(w, "\nTunnel Details:\n")
		_, _ = fmt.Fprintf(w, "  Type:\t%s\n", backend.Tunnel.Type)
		_, _ = fmt.Fprintf(w, "  Status:\t%s\n", backend.Tunnel.Status.State)
		_, _ = fmt.Fprintf(w, "  Created:\t%s\n", backend.Tunnel.Created.Format("2006-01-02 15:04:05"))
	}

	if verbose && backend.Security != nil {
		_, _ = fmt.Fprintf(w, "\nSecurity Details:\n")
		_, _ = fmt.Fprintf(w, "  mTLS Enabled:\t%t\n", backend.Security.MTLS)
		_, _ = fmt.Fprintf(w, "  Encryption:\t%s\n", backend.Security.Encryption)
	}

	if verbose && backend.Metrics != nil {
		_, _ = fmt.Fprintf(w, "\nMetrics:\n")
		_, _ = fmt.Fprintf(w, "  Latency:\t%v\n", backend.Metrics.Latency)
		_, _ = fmt.Fprintf(w, "  Throughput:\t%d req/s\n", backend.Metrics.Throughput)
		_, _ = fmt.Fprintf(w, "  Error Rate:\t%.2f%%\n", backend.Metrics.ErrorRate)
		_, _ = fmt.Fprintf(w, "  Uptime:\t%.2f%%\n", backend.Metrics.UptimePercent)
	}

	return w.Flush()
}

// DisplayHealthTable displays backend health status in table format
func DisplayHealthTable(status *hybrid.ConnectionStatus) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(w, "Connection Status:\t%s\n", getStatusString(status.Connected))
	_, _ = fmt.Fprintf(w, "Last Seen:\t%s\n", status.LastSeen.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(w, "Latency:\t%v\n", status.Latency)

	_, _ = fmt.Fprintf(w, "\nHealth Checks:\n")
	for name, passing := range status.HealthChecks {
		_, _ = fmt.Fprintf(w, "  %s:\t%s\n", strings.Title(name), getStatusString(passing))
	}

	if len(status.Errors) > 0 {
		_, _ = fmt.Fprintf(w, "\nErrors:\n")
		for _, err := range status.Errors {
			_, _ = fmt.Fprintf(w, "  - %s\n", err)
		}
	}

	return w.Flush()
}

// DisplayDiagnosticsTable displays diagnostic results in table format
func DisplayDiagnosticsTable(diagnostics *BackendDiagnostics) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(w, "Diagnostics Report for Backend: %s\n", diagnostics.BackendID)
	_, _ = fmt.Fprintf(w, "Timestamp: %s\n\n", diagnostics.Timestamp.Format("2006-01-02 15:04:05"))

	if diagnostics.Connectivity != nil {
		_, _ = fmt.Fprintf(w, "Connectivity Test:\n")
		_, _ = fmt.Fprintf(w, "  Local Reachable:\t%s\n", getStatusString(diagnostics.Connectivity.LocalReachable))
		_, _ = fmt.Fprintf(w, "  Frontend Reachable:\t%s\n", getStatusString(diagnostics.Connectivity.FrontendReachable))
		_, _ = fmt.Fprintf(w, "  Tunnel Active:\t%s\n", getStatusString(diagnostics.Connectivity.TunnelActive))
		_, _ = fmt.Fprintf(w, "  Latency:\t%v\n", diagnostics.Connectivity.Latency)
		if diagnostics.Connectivity.Error != "" {
			_, _ = fmt.Fprintf(w, "  Error:\t%s\n", diagnostics.Connectivity.Error)
		}
		_, _ = fmt.Fprintf(w, "\n")
	}

	if diagnostics.DNSResolution != nil {
		_, _ = fmt.Fprintf(w, "DNS Resolution Test:\n")
		_, _ = fmt.Fprintf(w, "  Public Domain Resolved:\t%s\n", getStatusString(diagnostics.DNSResolution.PublicDomainResolved))
		_, _ = fmt.Fprintf(w, "  Local DNS Working:\t%s\n", getStatusString(diagnostics.DNSResolution.LocalDNSWorking))
		_, _ = fmt.Fprintf(w, "  Resolution Time:\t%v\n", diagnostics.DNSResolution.ResolutionTime)
		if diagnostics.DNSResolution.Error != "" {
			_, _ = fmt.Fprintf(w, "  Error:\t%s\n", diagnostics.DNSResolution.Error)
		}
		_, _ = fmt.Fprintf(w, "\n")
	}

	if diagnostics.Certificates != nil {
		_, _ = fmt.Fprintf(w, "Certificate Test:\n")
		_, _ = fmt.Fprintf(w, "  Certificate Valid:\t%s\n", getStatusString(diagnostics.Certificates.CertificateValid))
		_, _ = fmt.Fprintf(w, "  CA Valid:\t%s\n", getStatusString(diagnostics.Certificates.CAValid))
		_, _ = fmt.Fprintf(w, "  Expires At:\t%s\n", diagnostics.Certificates.ExpiresAt.Format("2006-01-02 15:04:05"))
		_, _ = fmt.Fprintf(w, "  Days Until Expiry:\t%d\n", diagnostics.Certificates.DaysUntilExpiry)
		if diagnostics.Certificates.Error != "" {
			_, _ = fmt.Fprintf(w, "  Error:\t%s\n", diagnostics.Certificates.Error)
		}
		_, _ = fmt.Fprintf(w, "\n")
	}

	if len(diagnostics.Recommendations) > 0 {
		_, _ = fmt.Fprintf(w, "Recommendations:\n")
		for _, rec := range diagnostics.Recommendations {
			_, _ = fmt.Fprintf(w, "  - %s\n", rec)
		}
	}

	return w.Flush()
}

// DisplayBackendsJSON displays backends in JSON format
func DisplayBackendsJSON(backends []BackendSummary) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(backends)
}

// DisplayBackendsYAML displays backends in YAML format
func DisplayBackendsYAML(backends []BackendSummary) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer func() { _ = encoder.Close() }()
	return encoder.Encode(backends)
}

// DisplayBackendJSON displays backend details in JSON format
func DisplayBackendJSON(backend *BackendDetails) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(backend)
}

// DisplayBackendYAML displays backend details in YAML format
func DisplayBackendYAML(backend *BackendDetails) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer func() { _ = encoder.Close() }()
	return encoder.Encode(backend)
}

// DisplayHealthJSON displays health status in JSON format
func DisplayHealthJSON(status *hybrid.ConnectionStatus) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

// DisplayHealthYAML displays health status in YAML format
func DisplayHealthYAML(status *hybrid.ConnectionStatus) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer func() { _ = encoder.Close() }()
	return encoder.Encode(status)
}

// DisplayDiagnosticsJSON displays diagnostics in JSON format
func DisplayDiagnosticsJSON(diagnostics *BackendDiagnostics) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(diagnostics)
}

// DisplayDiagnosticsYAML displays diagnostics in YAML format
func DisplayDiagnosticsYAML(diagnostics *BackendDiagnostics) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer func() { _ = encoder.Close() }()
	return encoder.Encode(diagnostics)
}

// getStatusString returns a formatted status string with visual indicator
func getStatusString(status bool) string {
	if status {
		return "✓ PASS"
	}
	return "✗ FAIL"
}
