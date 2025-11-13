// pkg/templates/jenkins.go

package templates

import (
	"text/template"
)

// funcMap defines template functions like 'default'
var funcMap = template.FuncMap{
	"default": func(def, val string) string {
		if val == "" {
			return def
		}
		return val
	},
}

// JenkinsComposeTemplate is a text/template for rendering a Jenkins + SSH Agent docker compose file.
var JenkinsComposeTemplate = template.Must(template.New("jenkins-compose").Funcs(funcMap).Parse(`
version: '3.8'

services:
  jenkins:
    image: {{ .JenkinsImage | default "jenkins/jenkins:lts" }}
    container_name: {{ .JenkinsContainer | default "jenkins" }}
    ports:
      - "{{ .JenkinsUIPort | default "8059" }}:8080"   # Jenkins web UI
      - "{{ .JenkinsAgentPort | default "9059" }}:50000"  # Inbound agent connections
    restart: always
    volumes:
      - {{ .VolumeName | default "jenkins_home" }}:/var/jenkins_home
    networks:
      - {{ .NetworkName | default "arachne-net" }}

  ssh-agent:
    container_name: {{ .SSHAgentContainer | default "ssh-agent" }}
    image: {{ .SSHAgentImage | default "jenkins/ssh-agent" }}
    restart: always
    networks:
      - {{ .NetworkName | default "arachne-net" }}

volumes:
  {{ .VolumeName | default "jenkins_home" }}:
    name: {{ .VolumeName | default "jenkins_home" }}

networks:
  {{ .NetworkName | default "arachne-net" }}:
    external: true
`))
