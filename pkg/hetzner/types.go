// pkg/hetzner/types.go

package hetzner

// NOTE: hetznerDNSBaseURL moved to constants.go to fix P0 duplication violation
// (was defined in both types.go:5 and dns_servers.go:121)

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

// NOTE: recordsBaseURL moved to constants.go (HetznerDNSRecordsURL) to consolidate API endpoints

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

// NOTE: zonesBaseURL moved to constants.go (HetznerDNSZonesURL) to consolidate API endpoints

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

type ServerSpec struct {
	Name        string
	Image       string
	Type        string
	Location    string
	SSHKeys     []string
	UserData    string
	Labels      map[string]string
	FirewallIDs []int
}

// CreateRecordRequest is the request body for creating or updating a DNS record.
// Moved from dns_servers.go:124-130 to make exported and centralize types.
type CreateRecordRequest struct {
	ZoneID string `json:"zone_id"`
	Type   string `json:"type"`  // e.g. "A", "AAAA", "CNAME"
	Name   string `json:"name"`  // Subdomain label or "@" for zone apex
	Value  string `json:"value"` // IP address, hostname, or text value
	TTL    int    `json:"ttl"`   // Time-to-live in seconds
}

// RecordResponse holds data for the record creation response.
// Moved from dns_servers.go:132-139 to make exported and centralize types.
type RecordResponse struct {
	Record struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"record"`
}

// ZonesResponse is used to decode the JSON containing a list of zones.
// Moved from dns_servers.go:141-147 to make exported and centralize types.
type ZonesResponse struct {
	Zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"zones"`
}
