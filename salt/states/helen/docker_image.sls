# Docker image management for Helen deployments
# Handles both static nginx and Ghost CMS images

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}

{% if mode == 'static' %}
# Static mode uses nginx:alpine (existing behavior)

helen_pull_nginx_image:
  docker_image.present:
    - name: nginx:alpine
    - force: True
    - require:
      - sls: helen.prereqs

# If custom Dockerfile exists in repo, build it
{% if salt['pillar.get']('helen:repo_path') and salt['file.file_exists'](salt['pillar.get']('helen:repo_path') ~ '/Dockerfile') %}
helen_build_custom_static_image:
  docker_image.present:
    - name: helen-static:{{ environment }}
    - build: {{ salt['pillar.get']('helen:repo_path') }}
    - dockerfile: Dockerfile
    - force: True
    - buildargs:
      - NGINX_VERSION: alpine
      - BUILD_ENV: {{ environment }}
    - require:
      - docker_image: helen_pull_nginx_image
{% endif %}

{% elif mode == 'ghost' %}
# Ghost mode handles Ghost CMS images

helen_pull_ghost_image:
  docker_image.present:
    - name: {{ salt['pillar.get']('helen:docker_image', 'ghost:5-alpine') }}
    - force: True
    - require:
      - sls: helen.prereqs

# Check if there's a custom Ghost Dockerfile in the repo
{% if salt['pillar.get']('helen:repo_path') and salt['file.file_exists'](salt['pillar.get']('helen:repo_path') ~ '/Dockerfile.ghost') %}
helen_build_custom_ghost_image:
  docker_image.present:
    - name: helen-ghost:{{ environment }}
    - build: {{ salt['pillar.get']('helen:repo_path') }}
    - dockerfile: Dockerfile.ghost
    - force: True
    - buildargs:
      - GHOST_VERSION: {{ salt['pillar.get']('helen:ghost_version', '5') }}
      - NODE_ENV: {{ environment }}
      - BUILD_DATE: {{ salt['cmd.run']('date -u +%Y%m%d%H%M%S') }}
    - require:
      - docker_image: helen_pull_ghost_image

# Update pillar to use custom image
helen_update_ghost_image_pillar:
  module.run:
    - name: pillar.set
    - key: helen:docker_image
    - val: helen-ghost:{{ environment }}
    - require:
      - docker_image: helen_build_custom_ghost_image
{% endif %}

# Tag images for registry if configured
{% if salt['pillar.get']('helen:registry:enabled', false) %}
helen_tag_ghost_for_registry:
  docker_image.present:
    - name: {{ salt['pillar.get']('helen:registry:url') }}/helen-ghost:{{ environment }}-{{ salt['cmd.run']('date +%Y%m%d-%H%M%S') }}
    - image: {{ salt['pillar.get']('helen:docker_image', 'ghost:5-alpine') }}
    - require:
      - docker_image: helen_pull_ghost_image

helen_push_ghost_to_registry:
  module.run:
    - name: docker.push
    - image: {{ salt['pillar.get']('helen:registry:url') }}/helen-ghost:{{ environment }}-{{ salt['cmd.run']('date +%Y%m%d-%H%M%S') }}
    - require:
      - docker_image: helen_tag_ghost_for_registry
{% endif %}

{% endif %}

# Common image cleanup for both modes
helen_cleanup_old_images:
  cmd.run:
    - name: docker image prune -f --filter "label=service=helen" --filter "until=24h"
    - onlyif: docker images -q --filter "label=service=helen" | wc -l | grep -v '^0$'