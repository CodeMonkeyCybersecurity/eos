# Configure Authentik policies and flows

# Create default authentication flow
configure_auth_flow:
  cmd.run:
    - name: |
        TOKEN=$(vault kv get -field=value secret/hecate/authentik/api_token)
        
        # Check if flow exists
        FLOW_EXISTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
          http://localhost:9000/api/v3/flows/instances/?slug=hecate-authentication | jq '.results | length')
        
        if [ "$FLOW_EXISTS" -eq 0 ]; then
          # Create authentication flow
          curl -s -X POST http://localhost:9000/api/v3/flows/instances/ \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
              "name": "Hecate Authentication",
              "slug": "hecate-authentication",
              "title": "Welcome to Hecate",
              "designation": "authentication",
              "authentication": "require_authenticated"
            }'
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200

# Create default authorization policy
create_default_policy:
  cmd.run:
    - name: |
        TOKEN=$(vault kv get -field=value secret/hecate/authentik/api_token)
        
        # Create policy for authenticated users
        curl -s -X POST http://localhost:9000/api/v3/policies/expression/ \
          -H "Authorization: Bearer $TOKEN" \
          -H "Content-Type: application/json" \
          -d '{
            "name": "hecate-require-auth",
            "expression": "return ak_is_authenticated",
            "execution_logging": false
          }'
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200

# Create application for Caddy
create_caddy_application:
  cmd.run:
    - name: |
        TOKEN=$(vault kv get -field=value secret/hecate/authentik/api_token)
        
        # Check if application exists
        APP_EXISTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
          http://localhost:9000/api/v3/core/applications/?slug=caddy | jq '.results | length')
        
        if [ "$APP_EXISTS" -eq 0 ]; then
          # Get provider ID
          PROVIDER_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
            http://localhost:9000/api/v3/providers/proxy/?name=caddy-forward-auth | jq -r '.results[0].pk')
          
          # Create application
          curl -s -X POST http://localhost:9000/api/v3/core/applications/ \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
              \"name\": \"Caddy Reverse Proxy\",
              \"slug\": \"caddy\",
              \"provider\": $PROVIDER_ID,
              \"meta_launch_url\": \"https://{{ grains.domain | default('example.com') }}\",
              \"open_in_new_tab\": true
            }"
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200

# Configure outpost for Caddy
configure_caddy_outpost:
  cmd.run:
    - name: |
        TOKEN=$(vault kv get -field=value secret/hecate/authentik/api_token)
        
        # Check if outpost exists
        OUTPOST_EXISTS=$(curl -s -H "Authorization: Bearer $TOKEN" \
          http://localhost:9000/api/v3/outposts/instances/?name=caddy-outpost | jq '.results | length')
        
        if [ "$OUTPOST_EXISTS" -eq 0 ]; then
          # Get provider ID
          PROVIDER_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
            http://localhost:9000/api/v3/providers/proxy/?name=caddy-forward-auth | jq -r '.results[0].pk')
          
          # Create outpost
          curl -s -X POST http://localhost:9000/api/v3/outposts/instances/ \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "{
              \"name\": \"caddy-outpost\",
              \"type\": \"proxy\",
              \"providers\": [$PROVIDER_ID],
              \"config\": {
                \"authentik_host\": \"http://hecate-authentik-server.service.consul:9000\",
                \"docker_network\": \"hecate-network\"
              }
            }"
        fi
    - env:
      - VAULT_ADDR: http://127.0.0.1:8200