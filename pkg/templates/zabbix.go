// pkg/templates/zabbix.go

package templates

import (
	"text/template"
)

// ZabbixComposeTemplate is a text/template for rendering a complete Zabbix monitoring stack docker compose file.
var ZabbixComposeTemplate = template.Must(template.New("zabbix-compose").Funcs(funcMap).Parse(`
version: '3.8'

services:
  # PostgreSQL Database for Zabbix
  postgres-server:
    image: {{ .PostgresImage | default "postgres:15-alpine" }}
    container_name: {{ .PostgresContainer | default "zabbix-postgres" }}
    restart: unless-stopped
    environment:
      POSTGRES_USER: {{ .PostgresUser | default "zabbix" }}
      POSTGRES_PASSWORD: {{ .PostgresPassword | default "zabbix_pwd" }}
      POSTGRES_DB: {{ .PostgresDB | default "zabbix" }}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - zabbix-net
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U {{ .PostgresUser | default "zabbix" }}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # Zabbix Server - Core monitoring component
  zabbix-server:
    image: {{ .ZabbixServerImage | default "zabbix/zabbix-server-pgsql:alpine-6.4-latest" }}
    container_name: {{ .ZabbixServerContainer | default "zabbix-server" }}
    restart: unless-stopped
    depends_on:
      postgres-server:
        condition: service_healthy
    environment:
      DB_SERVER_HOST: postgres-server
      POSTGRES_USER: {{ .PostgresUser | default "zabbix" }}
      POSTGRES_PASSWORD: {{ .PostgresPassword | default "zabbix_pwd" }}
      POSTGRES_DB: {{ .PostgresDB | default "zabbix" }}
      ZBX_ENABLE_SNMP_TRAPS: "true"
    ports:
      - "{{ .ZabbixServerPort | default "10051" }}:10051"
    volumes:
      - zabbix-server-alertscripts:/usr/lib/zabbix/alertscripts
      - zabbix-server-externalscripts:/usr/lib/zabbix/externalscripts
      - zabbix-server-snmptraps:/var/lib/zabbix/snmptraps
    networks:
      - zabbix-net
    ulimits:
      nproc: 65535
      nofile:
        soft: 20000
        hard: 40000

  # Zabbix Web Frontend
  zabbix-web:
    image: {{ .ZabbixWebImage | default "zabbix/zabbix-web-nginx-pgsql:alpine-6.4-latest" }}
    container_name: {{ .ZabbixWebContainer | default "zabbix-web" }}
    restart: unless-stopped
    depends_on:
      - zabbix-server
      - postgres-server
    environment:
      ZBX_SERVER_HOST: zabbix-server
      ZBX_SERVER_PORT: "10051"
      DB_SERVER_HOST: postgres-server
      POSTGRES_USER: {{ .PostgresUser | default "zabbix" }}
      POSTGRES_PASSWORD: {{ .PostgresPassword | default "zabbix_pwd" }}
      POSTGRES_DB: {{ .PostgresDB | default "zabbix" }}
      PHP_TZ: "{{ .TimeZone | default "UTC" }}"
    ports:
      - "{{ .ZabbixWebPort | default "8080" }}:8080"
      - "{{ .ZabbixWebSSLPort | default "8443" }}:8443"
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /etc/timezone:/etc/timezone:ro
      - zabbix-web-ssl:/etc/ssl/nginx
    networks:
      - zabbix-net
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/ping"]
      interval: 30s
      timeout: 3s
      retries: 3

  # Zabbix Agent for monitoring the Zabbix server itself
  zabbix-agent:
    image: {{ .ZabbixAgentImage | default "zabbix/zabbix-agent:alpine-6.4-latest" }}
    container_name: {{ .ZabbixAgentContainer | default "zabbix-agent" }}
    restart: unless-stopped
    depends_on:
      - zabbix-server
    environment:
      ZBX_HOSTNAME: "{{ .ZabbixHostname | default "Zabbix server" }}"
      ZBX_SERVER_HOST: zabbix-server
      ZBX_SERVER_PORT: "10051"
      ZBX_PASSIVE_ALLOW: "true"
      ZBX_PASSIVESERVERS: "{{ .ZabbixPassiveServers | default "172.16.0.0/12" }}"
    ports:
      - "{{ .ZabbixAgentPort | default "10050" }}:10050"
    networks:
      - zabbix-net
    privileged: true
    pid: host

  # Optional: Zabbix Java Gateway for JMX monitoring
  zabbix-java-gateway:
    image: {{ .ZabbixJavaGatewayImage | default "zabbix/zabbix-java-gateway:alpine-6.4-latest" }}
    container_name: {{ .ZabbixJavaGatewayContainer | default "zabbix-java-gateway" }}
    restart: unless-stopped
    environment:
      ZBX_START_POLLERS: {{ .JavaGatewayPollers | default "5" }}
      ZBX_TIMEOUT: {{ .JavaGatewayTimeout | default "3" }}
      ZBX_DEBUGLEVEL: {{ .JavaGatewayDebugLevel | default "3" }}
    ports:
      - "{{ .ZabbixJavaGatewayPort | default "10052" }}:10052"
    networks:
      - zabbix-net

  # Optional: SNMP Trap receiver
  zabbix-snmptraps:
    image: {{ .ZabbixSNMPTrapsImage | default "zabbix/zabbix-snmptraps:alpine-6.4-latest" }}
    container_name: {{ .ZabbixSNMPTrapsContainer | default "zabbix-snmptraps" }}
    restart: unless-stopped
    ports:
      - "{{ .SNMPTrapsPort | default "162" }}:1162/udp"
    volumes:
      - zabbix-server-snmptraps:/var/lib/zabbix/snmptraps
    networks:
      - zabbix-net

networks:
  zabbix-net:
    driver: bridge
    ipam:
      config:
        - subnet: {{ .NetworkSubnet | default "172.16.238.0/24" }}

volumes:
  postgres-data:
    driver: local
  zabbix-server-alertscripts:
    driver: local
  zabbix-server-externalscripts:
    driver: local
  zabbix-server-snmptraps:
    driver: local
  zabbix-web-ssl:
    driver: local
`))