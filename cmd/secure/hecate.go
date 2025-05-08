// cmd/secure/hecate.go

package secure

// TODO(harden-caddy): Add security hardening to the generated Caddyfile.
//
// - Add standard security headers (similar to what we used in Nginx):
//   - Strict-Transport-Security
//   - X-Frame-Options SAMEORIGIN
//   - X-Content-Type-Options nosniff
//   - Referrer-Policy no-referrer
//   - Permissions-Policy (disable mic/camera/etc. as needed)
//   - Content-Security-Policy (TBD)
//
// - Remove `start-dev` and `--hostname-strict=false` from Keycloak config
//   and ensure production-grade settings.
//
// - Confirm Caddyfile includes buffer settings & limits as needed (e.g., `encode`, `tls`, etc.)
//
// Reference: See previous Nginx configs & Keycloak docs for secure proxy settings.
