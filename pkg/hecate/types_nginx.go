package hecate

import (
	"bytes"
	"fmt"
	"text/template"
)

// Centralized port maps (unchanged).
var (
	MailcowPorts = ServicePorts{
		TCP: []string{"25", "587", "465", "110", "995", "143", "993"},
		UDP: []string{},
	}

	JenkinsPorts = ServicePorts{
		TCP: []string{"50000"},
		UDP: []string{},
	}

	WazuhPorts = ServicePorts{
		TCP: []string{"1515", "1514", "55000"},
		UDP: []string{"1515", "1514"},
	}
)

var nginxFragments []NginxFragment

const StreamIncludeTemplate = `
stream {
    include /etc/nginx/conf.d/stream/*.conf;
}
`

// NginxStreamBlock defines the config for one upstream + server block.
type NginxStreamBlock struct {
	BackendIP    string
	UpstreamName string
	BackendPort  string
	ListenPort   string
}

type NginxFragment struct {
	ServiceName string
	StreamBlock string
}

type NginxSpec struct {
	ServiceName  string // Added for context
	StreamBlocks []NginxStreamBlock
	PortsTCP     []string // To help Docker Compose port injection
	PortsUDP     []string
}

// Centralized port configs (TCP/UDP) for quick reference.
type ServicePorts struct {
	TCP []string
	UDP []string
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

// Centralized service stream blocks.
var (
	MailcowStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "mailcow_smtp", BackendPort: "25", ListenPort: "25"},
		{UpstreamName: "mailcow_submission", BackendPort: "587", ListenPort: "587"},
		{UpstreamName: "mailcow_smtps", BackendPort: "465", ListenPort: "465"},
		{UpstreamName: "mailcow_pop3", BackendPort: "110", ListenPort: "110"},
		{UpstreamName: "mailcow_pop3s", BackendPort: "995", ListenPort: "995"},
		{UpstreamName: "mailcow_imap", BackendPort: "143", ListenPort: "143"},
		{UpstreamName: "mailcow_imaps", BackendPort: "993", ListenPort: "993"},
	}

	JenkinsStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "jenkins_agent", BackendPort: "8059", ListenPort: "50000"},
	}

	WazuhStreamBlocks = []NginxStreamBlock{
		{UpstreamName: "wazuh_manager_1515", BackendPort: "1515", ListenPort: "1515"},
		{UpstreamName: "wazuh_manager_1514", BackendPort: "1514", ListenPort: "1514"},
		{UpstreamName: "wazuh_manager_55000", BackendPort: "55000", ListenPort: "55000"},
	}
)

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
func RenderStreamBlocks(backendIP string, blocks []NginxStreamBlock) (string, error) {
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
