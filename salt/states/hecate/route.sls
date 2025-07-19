# Salt state for managing individual routes
{% set route = salt['pillar.get']('hecate_route', {}) %}

{% if route %}
# Generate Caddy configuration for route
/etc/caddy/conf.d/{{ route.domain }}.json:
  file.managed:
    - contents: |
        {
          "@id": "{{ route.id | default('route-' ~ route.domain) }}",
          "match": [{
            "host": ["{{ route.domain }}"]
          }],
          "handle": [
            {% if route.auth_policy %}
            {
              "handler": "forward_auth",
              "uri": "http://authentik:9000/outpost.goauthentik.io/auth/caddy",
              "headers": {
                "X-Authentik-Meta-Outpost": ["authentik-embedded-outpost"],
                "X-Authentik-Meta-Provider": ["{{ route.auth_policy }}"],
                "X-Authentik-Meta-App": ["{{ route.domain }}"]
              }
            },
            {% endif %}
            {
              "handler": "reverse_proxy",
              "upstreams": [
                {% for upstream in route.upstreams %}
                {"dial": "{{ upstream.dial if upstream.dial is defined else upstream }}"}{% if not loop.last %},{% endif %}
                {% endfor %}
              ]
              {% if route.headers %},
              "headers": {
                "request": {
                  "set": {{ route.headers | tojson }}
                }
              }
              {% endif %}
            }
          ]
        }
    - user: caddy
    - group: caddy
    - mode: 644
    - makedirs: True
    - require:
      - user: caddy

# Reload Caddy configuration
caddy_reload_for_{{ route.domain | replace('.', '_') }}:
  cmd.run:
    - name: systemctl reload caddy
    - onchanges:
      - file: /etc/caddy/conf.d/{{ route.domain }}.json

# Store route configuration in Consul
consul_store_route_{{ route.domain | replace('.', '_') }}:
  cmd.run:
    - name: |
        consul kv put hecate/routes/{{ route.domain }} '{{ route | tojson }}'
    - require:
      - service: consul
    - onchanges:
      - file: /etc/caddy/conf.d/{{ route.domain }}.json

{% else %}
route_pillar_warning:
  test.show_notification:
    - text: "No route configuration found in pillar data"
{% endif %}