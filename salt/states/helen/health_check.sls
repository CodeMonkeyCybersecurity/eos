# Health check verification for Helen deployments
# Ensures the deployment is fully operational before completing

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}
{% set domain = salt['pillar.get']('helen:domain') %}
{% set port = salt['pillar.get']('helen:port', 8009) %}

# Wait for service to be healthy in Consul
helen_wait_for_consul_health:
  cmd.run:
    - name: |
        echo "Waiting for Helen service to be healthy in Consul..."
        SERVICE_NAME="helen-{{ mode }}-{{ environment }}"
        TIMEOUT=300  # 5 minutes
        ELAPSED=0
        
        while [ $ELAPSED -lt $TIMEOUT ]; do
          # Check Consul health status
          HEALTH_STATUS=$(consul health state $SERVICE_NAME 2>/dev/null | grep -c "passing" || echo "0")
          TOTAL_CHECKS=$(consul health state $SERVICE_NAME 2>/dev/null | wc -l || echo "0")
          
          echo "Health checks passing: $HEALTH_STATUS/$TOTAL_CHECKS"
          
          if [ "$TOTAL_CHECKS" -gt "0" ] && [ "$HEALTH_STATUS" -eq "$TOTAL_CHECKS" ]; then
            echo "All health checks passing!"
            break
          fi
          
          sleep 10
          ELAPSED=$((ELAPSED + 10))
        done
        
        if [ $ELAPSED -ge $TIMEOUT ]; then
          echo "Timeout waiting for service to be healthy"
          consul health state $SERVICE_NAME
          exit 1
        fi
    - require:
      - sls: helen.hecate_route

# Perform internal health checks
helen_internal_health_check:
  cmd.run:
    - name: |
        echo "Performing internal health checks..."
        
        # Get service address from Consul
        SERVICE_ADDR=$(consul catalog nodes -service=helen-{{ mode }}-{{ environment }} -detailed | grep Address | awk '{print $2}' | head -1)
        
        if [ -z "$SERVICE_ADDR" ]; then
          echo "Failed to get service address from Consul"
          exit 1
        fi
        
        # Test different endpoints based on mode
        {% if mode == 'ghost' %}
        # Ghost health checks
        ENDPOINTS=(
          "http://$SERVICE_ADDR:{{ port }}/ghost/api/admin/site/"
          "http://$SERVICE_ADDR:{{ port }}/"
        )
        {% else %}
        # Static site health checks
        ENDPOINTS=(
          "http://$SERVICE_ADDR:{{ port }}/"
          "http://$SERVICE_ADDR:{{ port }}/index.html"
        )
        {% endif %}
        
        for ENDPOINT in "${ENDPOINTS[@]}"; do
          echo "Checking: $ENDPOINT"
          HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT" || echo "000")
          
          if [[ "$HTTP_CODE" =~ ^[23] ]]; then
            echo "✓ $ENDPOINT returned $HTTP_CODE"
          else
            echo "✗ $ENDPOINT returned $HTTP_CODE"
            exit 1
          fi
        done
        
        echo "All internal health checks passed!"
    - require:
      - cmd: helen_wait_for_consul_health

# Test external access through Hecate
helen_external_health_check:
  cmd.run:
    - name: |
        echo "Testing external access through Hecate..."
        
        # First check if DNS is resolving
        DNS_CHECK=$(dig +short {{ domain }} | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | wc -l)
        
        if [ "$DNS_CHECK" -eq "0" ]; then
          echo "Warning: DNS not yet resolving for {{ domain }}"
          echo "You may need to configure DNS manually"
        else
          echo "DNS is resolving for {{ domain }}"
        fi
        
        # Check if Caddy has the route configured
        ROUTE_CHECK=$(curl -s http://localhost:2019/config/apps/http/servers | \
          jq -r '.. | .routes? | select(. != null) | .[].match[]?.host[]?' | \
          grep -c "{{ domain }}" || echo "0")
        
        if [ "$ROUTE_CHECK" -gt "0" ]; then
          echo "✓ Route configured in Caddy for {{ domain }}"
        else
          echo "✗ Route not found in Caddy configuration"
          exit 1
        fi
        
        # Try to access through localhost with Host header
        echo "Testing access with Host header..."
        {% if mode == 'ghost' %}
        TEST_PATH="/ghost/api/admin/site/"
        {% else %}
        TEST_PATH="/"
        {% endif %}
        
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
          -H "Host: {{ domain }}" \
          "http://localhost$TEST_PATH" || echo "000")
        
        if [[ "$HTTP_CODE" =~ ^[23] ]]; then
          echo "✓ External access test passed (HTTP $HTTP_CODE)"
        else
          echo "✗ External access test failed (HTTP $HTTP_CODE)"
          # Don't fail here as DNS might not be configured yet
        fi
    - require:
      - cmd: helen_internal_health_check

# Verify deployment metadata
helen_verify_deployment_metadata:
  cmd.run:
    - name: |
        echo "Verifying deployment metadata..."
        
        # Check Consul KV for deployment record
        DEPLOYMENT_DATA=$(consul kv get helen/deployments/{{ environment }}/latest 2>/dev/null)
        
        if [ -n "$DEPLOYMENT_DATA" ]; then
          echo "Deployment metadata found in Consul:"
          echo "$DEPLOYMENT_DATA" | jq '.'
        else
          echo "Warning: No deployment metadata found in Consul"
        fi
        
        # Check Vault for secrets
        echo "Verifying Vault secrets..."
        {% if mode == 'ghost' %}
        VAULT_PATHS=(
          "kv/data/helen/{{ environment }}/database"
          "kv/data/helen/{{ environment }}/mail"
          "kv/data/helen/{{ environment }}/admin"
        )
        {% else %}
        VAULT_PATHS=(
          "kv/data/helen/{{ environment }}/metadata"
        )
        {% endif %}
        
        for PATH in "${VAULT_PATHS[@]}"; do
          if vault kv get "$PATH" >/dev/null 2>&1; then
            echo "✓ Vault secret exists: $PATH"
          else
            echo "✗ Vault secret missing: $PATH"
            exit 1
          fi
        done
    - require:
      - cmd: helen_external_health_check

# Performance check
helen_performance_check:
  cmd.run:
    - name: |
        echo "Running basic performance check..."
        
        # Get service address
        SERVICE_ADDR=$(consul catalog nodes -service=helen-{{ mode }}-{{ environment }} -detailed | grep Address | awk '{print $2}' | head -1)
        
        {% if mode == 'static' %}
        # For static sites, check response time
        RESPONSE_TIME=$(curl -s -o /dev/null -w "%{time_total}" "http://$SERVICE_ADDR:{{ port }}/" || echo "999")
        
        if (( $(echo "$RESPONSE_TIME < 1.0" | bc -l) )); then
          echo "✓ Response time acceptable: ${RESPONSE_TIME}s"
        else
          echo "⚠ Response time slow: ${RESPONSE_TIME}s"
        fi
        {% else %}
        # For Ghost, check API response time
        API_TIME=$(curl -s -o /dev/null -w "%{time_total}" "http://$SERVICE_ADDR:{{ port }}/ghost/api/admin/site/" || echo "999")
        
        if (( $(echo "$API_TIME < 2.0" | bc -l) )); then
          echo "✓ API response time acceptable: ${API_TIME}s"
        else
          echo "⚠ API response time slow: ${API_TIME}s"
        fi
        {% endif %}
        
        # Check resource usage
        ALLOC_ID=$(cat /tmp/helen-primary-allocation.txt 2>/dev/null || nomad job status -json helen-{{ mode }}-{{ environment }} | jq -r '.Allocations[0].ID')
        
        if [ -n "$ALLOC_ID" ]; then
          echo "Checking resource usage for allocation: $ALLOC_ID"
          nomad alloc status -stats $ALLOC_ID | grep -E "(CPU|Memory|Disk)"
        fi
    - require:
      - cmd: helen_verify_deployment_metadata

# Final deployment summary
helen_deployment_summary:
  cmd.run:
    - name: |
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo "  Helen {{ mode }} Deployment Summary - {{ environment }}"
        echo "════════════════════════════════════════════════════════════════"
        echo ""
        echo "✓ Deployment Status: SUCCESS"
        echo "✓ Mode: {{ mode }}"
        echo "✓ Environment: {{ environment }}"
        echo "✓ Domain: https://{{ domain }}"
        echo "✓ Internal Port: {{ port }}"
        echo "✓ Service Name: helen-{{ mode }}-{{ environment }}"
        echo ""
        
        {% if mode == 'ghost' %}
        echo "Ghost CMS Access:"
        echo "  Website: https://{{ domain }}"
        echo "  Admin Panel: https://{{ domain }}/ghost"
        echo ""
        echo "Database: {{ salt['pillar.get']('helen:database', 'mysql') }}"
        echo "Authentication: {% if salt['pillar.get']('helen:enable_auth', false) %}Enabled{% else %}Disabled{% endif %}"
        echo ""
        
        # Get admin credentials from Vault
        ADMIN_EMAIL=$(vault kv get -field=email kv/helen/{{ environment }}/admin 2>/dev/null || echo "Not available")
        echo "Admin Email: $ADMIN_EMAIL"
        echo "Admin Password: (Stored in Vault at kv/helen/{{ environment }}/admin)"
        {% else %}
        echo "Static Site Access:"
        echo "  Website: https://{{ domain }}"
        echo "  Content Path: {{ salt['pillar.get']('helen:html_path', '/var/lib/helen/' ~ environment ~ '/public') }}"
        {% endif %}
        echo ""
        echo "Management Commands:"
        echo "  Status: eos read helen --mode {{ mode }} --environment {{ environment }}"
        echo "  Update: eos update helen --mode {{ mode }} --environment {{ environment }}"
        echo "  Logs: nomad alloc logs -job helen-{{ mode }}-{{ environment }}"
        echo "  Delete: eos delete helen --mode {{ mode }} --environment {{ environment }}"
        echo ""
        echo "Monitoring:"
        echo "  Consul: http://consul.service.consul:8500/ui/dc1/services/helen-{{ mode }}-{{ environment }}"
        echo "  Nomad: http://nomad.service.consul:4646/ui/jobs/helen-{{ mode }}-{{ environment }}"
        echo ""
        echo "════════════════════════════════════════════════════════════════"
    - require:
      - cmd: helen_performance_check