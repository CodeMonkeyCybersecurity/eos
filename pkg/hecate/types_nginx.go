package hecate

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

var nginxFragments []NginxFragment

type NginxFragment struct {
	ServiceName string
	StreamBlock string
}

type NginxSpec struct {
	ServiceName  string // Added for context
	StreamBlocks []shared.NginxStreamBlock
	PortsTCP     []string // To help Docker Compose port injection
	PortsUDP     []string
}

const BaseNginxConf = `worker_processes  1;

events {
    worker_connections  1024;
}

` + StreamIncludeTemplate + `
`

// Template to render any upstream + server block.
const GenericStreamBlockTemplate = `
upstream {{ .UpstreamName }} {
    server {{ .BackendIP }}:{{ .BackendPort }};
}
server {
    listen {{ .ListenPort }};
    proxy_pass {{ .UpstreamName }};
}
`

// ToFragment renders the NginxSpec into a usable NginxFragment.
func (n *NginxSpec) ToFragment(backendIP string) (NginxFragment, error) {
	if len(n.StreamBlocks) == 0 {
		return NginxFragment{}, fmt.Errorf("no stream blocks to render for %s", n.ServiceName)
	}
	rendered, err := RenderStreamBlocks(backendIP, n.StreamBlocks)
	if err != nil {
		return NginxFragment{}, fmt.Errorf("failed to render stream blocks: %w", err)
	}
	return NginxFragment{
		ServiceName: n.ServiceName,
		StreamBlock: rendered,
	}, nil
}

// RenderStreamBlocks renders all stream blocks for a service.
func RenderStreamBlocks(backendIP string, blocks []shared.NginxStreamBlock) (string, error) {
	tmpl, err := template.New("stream").Parse(GenericStreamBlockTemplate)
	if err != nil {
		return "", err
	}

	var rendered bytes.Buffer
	for _, block := range blocks {
		// Fill in the backend IP dynamically.
		block.BackendIP = backendIP

		if err := tmpl.Execute(&rendered, block); err != nil {
			return "", err
		}
		rendered.WriteString("\n\n")
	}
	return rendered.String(), nil
}
