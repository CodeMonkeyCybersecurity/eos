# ClusterFuzz Templates

This directory contains template files for ClusterFuzz deployment on Nomad.

## Files

- `core.nomad` - Core services job template
- `bots.nomad` - Fuzzing bots job template  
- `web.dockerfile` - Web interface Docker image
- `bot.dockerfile` - Bot Docker image
- `init.sql` - Database initialization script

These templates are embedded in the Go binary and used during deployment.