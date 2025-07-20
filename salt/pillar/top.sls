# Salt Pillar Top File
# Defines which pillars are available to which minions

base:
  # Only load hecate secrets when actually deploying hecate
  'roles:hecate':
    - match: grain
    - hecate.secrets
    
  # Target specific minions if needed
  'hecate-*':
    - hecate.secrets
    
  # Test environment specific
  'test-*':
    - hecate.secrets