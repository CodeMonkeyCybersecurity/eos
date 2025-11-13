// pkg/hecate/phase4_coturn

package hecate

import (
	"bytes"
	"text/template"
)

func RenderCoturnSection(cfg DockerConfig) (string, error) {
	tmplStr := `
  coturn:
    image: coturn/coturn
    container_name: hecate-coturn
    restart: always
    ports:
      - "3478:3478"
      - "3478:3478/udp"
      - "5349:5349"
      - "5349:5349/udp"
      - "49160-49200:49160-49200/udp"
    environment:
      DETECT_EXTERNAL_IP: "yes"
      DETECT_RELAY_IP: "yes"
      DETECT_EXTERNAL_IPV6: "yes"
      DETECT_RELAY_IPV6: "yes"
    volumes:
      - ./certs:/etc/coturn/certs:ro
    command: >
      turnserver
      --listening-port=3478
      --listening-ip=0.0.0.0
      --fingerprint
      --no-cli
      --min-port=49160
      --max-port=49200
      --log-file=/var/log/coturn.log
      --cert=/etc/coturn/certs/hecate.fullchain.pem
      --pkey=/etc/coturn/certs/hecate.privkey.pem
      --static-auth-secret={{ .CoturnAuthSecret }}
      --verbose
    networks:
      - hecate-net
`
	tmpl, err := template.New("coturn").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}
