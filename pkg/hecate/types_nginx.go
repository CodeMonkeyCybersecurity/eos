//pkg/hecate/types_nginx.go

package hecate


type NginxStreamConfig struct {
    BackendIP string
}


const StreamIncludeTemplate = `
stream {
    include /etc/nginx/conf.d/stream/*.conf;
}
`


const MailcowStreamTemplate = `
#--------------------------------------------------
# MAILCOW STREAMS
#--------------------------------------------------
upstream mailcow_smtp {
    server {{ .BackendIP }}:25;
}
server {
    listen 25;
    proxy_pass mailcow_smtp;
}

upstream mailcow_submission {
    server {{ .BackendIP }}:587;
}
server {
    listen 587;
    proxy_pass mailcow_submission;
}

upstream mailcow_smtps {
    server {{ .BackendIP }}:465;
}
server {
    listen 465;
    proxy_pass mailcow_smtps;
}

upstream mailcow_pop3 {
    server {{ .BackendIP }}:110;
}
server {
    listen 110;
    proxy_pass mailcow_pop3;
}

upstream mailcow_pop3s {
    server {{ .BackendIP }}:995;
}
server {
    listen 995;
    proxy_pass mailcow_pop3s;
}

upstream mailcow_imap {
    server {{ .BackendIP }}:143;
}
server {
    listen 143;
    proxy_pass mailcow_imap;
}

upstream mailcow_imaps {
    server {{ .BackendIP }}:993;
}
server {
    listen 993;
    proxy_pass mailcow_imaps;
}
`

const JenkinsStreamTemplate = `
#--------------------------------------------------
# JENKINS STREAM
#--------------------------------------------------
upstream jenkins_agent {
    server {{ .BackendIP }}:8059;    # Backend port for agent connections
}
server {
    listen 50000;                   # External port for agent connections
    proxy_pass jenkins_agent;
}
`

const WazuhStreamTemplate = `
#--------------------------------------------------
# WAZUH STREAMS
#--------------------------------------------------
upstream wazuh_manager_1515 {
    server {{ .BackendIP }}:1515;
}
server {
    listen 1515;
    proxy_pass wazuh_manager_1515;
}

upstream wazuh_manager_1514 {
    server {{ .BackendIP }}:1514;
}
server {
    listen 1514;
    proxy_pass wazuh_manager_1514;
}

upstream wazuh_manager_55000 {
    server {{ .BackendIP }}:55000;
}
server {
    listen 55000;
    proxy_pass wazuh_manager_55000;
}
`