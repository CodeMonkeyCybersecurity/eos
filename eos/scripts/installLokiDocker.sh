#!/bin/bash

mkdir ~/loki && cd ~/loki && wget https://raw.githubusercontent.com/grafana/loki/v3.0.0/production/docker-compose.yaml -O docker-compose.yaml && \
docker compose -f docker-compose.yaml up -d && echo "finis"
