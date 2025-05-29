// pkg/hetzner/fw.go

package hetzner

import (
	"fmt"
	"net"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func GetAllFws(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	firewalls, err := client.Firewall.All(rc.Ctx)
	if err != nil {
		fmt.Println("❌ Error retrieving firewalls:", err)
		return
	}
	for _, fw := range firewalls {
		fmt.Printf("✅ Firewall: %s (ID: %d)\n", fw.Name, fw.ID)
	}
}

func CreateAFw(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	result, _, err := client.Firewall.Create(rc.Ctx, hcloud.FirewallCreateOpts{
		ApplyTo: []hcloud.FirewallResource{
			{
				Type: hcloud.FirewallResourceTypeServer,
				Server: &hcloud.FirewallResourceServer{
					ID: 42,
				},
			},
		},
		Labels: map[string]string{
			"env": "dev",
		},
		Name: "Corporate Intranet Protection",
		Rules: []hcloud.FirewallRule{
			{
				Description: hcloud.Ptr("Allow port 80"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Port:        hcloud.Ptr("80"),
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				SourceIPs: []net.IPNet{
					{IP: net.ParseIP("28.239.13.1"), Mask: net.CIDRMask(32, 32)},
					{IP: net.ParseIP("28.239.14.0"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("ff21:1eac:9a3b:ee58:5ca:990c:8bc9:c03b"), Mask: net.CIDRMask(128, 128)},
				},
			},
		},
	})
	if err != nil {
		fmt.Println("❌ Error creating firewall:", err)
		return
	}

	err = client.Action.WaitFor(rc.Ctx, result.Actions...)
	if err != nil {
		fmt.Println("❌ Error waiting for actions:", err)
		return
	}

	fmt.Printf("✅ Created firewall: %s (ID: %d)\n", result.Firewall.Name, result.Firewall.ID)
}

func GetAFw(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	fw, _, err := client.Firewall.GetByID(rc.Ctx, 123)
	if err != nil {
		fmt.Println("❌ Error retrieving firewall:", err)
		return
	}
	fmt.Printf("✅ Got firewall: %s (ID: %d)\n", fw.Name, fw.ID)
}

func UpdateAFw(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	_, _, err := client.Firewall.Update(rc.Ctx, &hcloud.Firewall{ID: 123}, hcloud.FirewallUpdateOpts{
		Labels: map[string]string{
			"environment":    "prod",
			"example.com/my": "label",
			"just-a-key":     "",
		},
		Name: "new-name",
	})
	if err != nil {
		fmt.Println("❌ Error updating firewall:", err)
	}
}

func DeleteAFw(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	_, err := client.Firewall.Delete(rc.Ctx, &hcloud.Firewall{ID: 123})
	if err != nil {
		fmt.Println("❌ Error deleting firewall:", err)
	}
}

func ApplyToResources(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	actions, _, err := client.Firewall.ApplyResources(rc.Ctx, &hcloud.Firewall{ID: 123}, []hcloud.FirewallResource{
		{
			Type: hcloud.FirewallResourceTypeServer,
			Server: &hcloud.FirewallResourceServer{
				ID: 42,
			},
		},
	})
	if err != nil {
		fmt.Println("❌ Error applying firewall to resources:", err)
		return
	}
	_ = client.Action.WaitFor(rc.Ctx, actions...)
}

func RemoveFromResources(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	actions, _, err := client.Firewall.RemoveResources(rc.Ctx, &hcloud.Firewall{ID: 123}, []hcloud.FirewallResource{
		{
			Type: hcloud.FirewallResourceTypeServer,
			Server: &hcloud.FirewallResourceServer{
				ID: 42,
			},
		},
	})
	if err != nil {
		fmt.Println("❌ Error removing firewall from resources:", err)
		return
	}
	_ = client.Action.WaitFor(rc.Ctx, actions...)
}

func SetRules(rc *eos_io.RuntimeContext) {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	actions, _, err := client.Firewall.SetRules(rc.Ctx, &hcloud.Firewall{ID: 123}, hcloud.FirewallSetRulesOpts{
		Rules: []hcloud.FirewallRule{
			{
				Description: hcloud.Ptr("Allow port 80"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Port:        hcloud.Ptr("80"),
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				SourceIPs: []net.IPNet{
					{IP: net.ParseIP("28.239.13.1"), Mask: net.CIDRMask(32, 32)},
					{IP: net.ParseIP("28.239.14.0"), Mask: net.CIDRMask(24, 32)},
					{IP: net.ParseIP("ff21:1eac:9a3b:ee58:5ca:990c:8bc9:c03b"), Mask: net.CIDRMask(128, 128)},
				},
			},
		},
	})
	if err != nil {
		fmt.Println("❌ Error setting firewall rules:", err)
		return
	}
	_ = client.Action.WaitFor(rc.Ctx, actions...)
}
