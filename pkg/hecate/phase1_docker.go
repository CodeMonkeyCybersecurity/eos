// pkg/hecate/phase1_container.go

package hecate

import (
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

// OrchestrateHecateDockerCompose is a thin wrapper that collates fragments and builds the final docker-compose.yml.
func PhaseDockerCompose(rc *eos_io.RuntimeContext, logName, filePath string) error {
	// Step 1: Collate all compose fragments into one string block
	dynamicServices := CollateComposeFragmentsToString()

	// Step 2: Build the full docker-compose.yml with caddy + dynamic services + networks + volumes
	return BuildHecateCompose(
		rc,
		logName,
		DockerCaddyService, // always include the Caddy service block
		dynamicServices,
		filePath,
	)
}

// BuildHecateCompose assembles and writes the docker-compose.yml file.
func BuildHecateCompose(
	rc *eos_io.RuntimeContext,
	logName string,
	caddyService string,
	dynamicServices string,
	filePath string,
) error {
	data := struct {
		CaddyService    string
		DynamicServices string
		NetworksSection string
		VolumesSection  string
	}{
		CaddyService:    caddyService,
		DynamicServices: dynamicServices,
		NetworksSection: DockerNetworkSection,
		VolumesSection:  DockerVolumesSection,
	}

	return RenderAndWriteTemplate(
		rc,
		logName,
		DockerComposeMasterTemplate,
		data,
		filePath,
	)
}

// CollateComposeFragments handles collation + writing of the docker-compose.yml.
func CollateComposeFragments(rc *eos_io.RuntimeContext) error {
	footer := GetDockerFooter()

	return CollateAndWriteFile(
		rc,
		"hecate-compose-collation",
		composeFragments,
		HecateDockerCompose,
		"services:\n",
		footer,
		func(frag DockerComposeFragment) string { return frag.ServiceYAML },
	)
}

// CollateComposeFragmentsToString collates all DockerComposeFragment objects into a single string block.
func CollateComposeFragmentsToString() string {
	var dynamicParts []string
	for _, frag := range composeFragments {
		dynamicParts = append(dynamicParts, frag.ServiceYAML)
	}
	return strings.Join(dynamicParts, "\n\n")
}

// GetDockerNetworkSection returns the default Docker network section.
// This function now reuses the centralized constant.
func GetDockerNetworkSection() string {
	return DockerNetworkSection
}

// GetDockerVolumesSection returns the default Docker volumes section.
// This function now reuses the centralized constant.
func GetDockerVolumesSection() string {
	return DockerVolumesSection
}

// GetDockerFooter combines the network and volumes sections into a single footer block.
// This is handy for passing into templates or collators that expect a single footer string.
func GetDockerFooter() string {
	return GetDockerNetworkSection() + "\n" + GetDockerVolumesSection()
}
