// pkg/hetzner/client.go

package hetzner

const hetznerDNSBaseURL = "https://dns.hetzner.com/api/v1"

type PrimaryServer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	ZoneID   string `json:"zone_id"`
	Created  string `json:"created"`
	Modified string `json:"modified"`
}

type primaryServerResponse struct {
	PrimaryServer PrimaryServer `json:"primary_server"`
}

type primaryServerListResponse struct {
	PrimaryServers []PrimaryServer `json:"primary_servers"`
}

const recordsBaseURL = "https://dns.hetzner.com/api/v1/records"

type DNSRecord struct {
	ID       string `json:"id,omitempty"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl,omitempty"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	ZoneID   string `json:"zone_id"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
}

type dnsRecordResponse struct {
	Record DNSRecord `json:"record"`
}

type dnsRecordListResponse struct {
	Records []DNSRecord `json:"records"`
}

type bulkRecordsPayload struct {
	Records []DNSRecord `json:"records"`
}

const zonesBaseURL = "https://dns.hetzner.com/api/v1/zones"

type DNSZone struct {
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	TTL      int    `json:"ttl"`
	Created  string `json:"created,omitempty"`
	Modified string `json:"modified,omitempty"`
}

type dnsZoneResponse struct {
	Zone DNSZone `json:"zone"`
}

type dnsZoneListResponse struct {
	Zones []DNSZone `json:"zones"`
}
