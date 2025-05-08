// pkg/hecate/types_names.go

package hecate

type AppProxy struct {
	AppName     string
	Subdomain   string
	BackendPort int
}

var AppProxies = []AppProxy{
	{AppName: "umami", Subdomain: "internal", BackendPort: 8117},
	{AppName: "minio", Subdomain: "s3", BackendPort: 8123},
	{AppName: "minio-api", Subdomain: "s3api", BackendPort: 9123},
	{AppName: "grafana", Subdomain: "grafana", BackendPort: 8069},
	{AppName: "jenkins", Subdomain: "jenkins", BackendPort: 8059},
	{AppName: "keycloak", Subdomain: "hera", BackendPort: 8080},
	{AppName: "mattermost", Subdomain: "mattermost", BackendPort: 8017},
	{AppName: "nextcloud", Subdomain: "nextcloud", BackendPort: 11000},
	{AppName: "helen", Subdomain: "helen", BackendPort: 8009},
}
