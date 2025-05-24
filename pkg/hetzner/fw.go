// pkg/hetzner/fw.go

package hetzner

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func GetAllFws() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	firewalls, err := client.Firewall.All(ctx)
	if err != nil {
		fmt.Println("❌ Error retrieving firewalls:", err)
		return
	}
	for _, fw := range firewalls {
		fmt.Printf("✅ Firewall: %s (ID: %d)\n", fw.Name, fw.ID)
	}
}

func CreateAFw() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	result, _, err := client.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
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

	err = client.Action.WaitFor(ctx, result.Actions...)
	if err != nil {
		fmt.Println("❌ Error waiting for actions:", err)
		return
	}

	fmt.Printf("✅ Created firewall: %s (ID: %d)\n", result.Firewall.Name, result.Firewall.ID)
}

func GetAFw() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	fw, _, err := client.Firewall.GetByID(ctx, 123)
	if err != nil {
		fmt.Println("❌ Error retrieving firewall:", err)
		return
	}
	fmt.Printf("✅ Got firewall: %s (ID: %d)\n", fw.Name, fw.ID)
}

func UpdateAFw() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	_, _, err := client.Firewall.Update(ctx, &hcloud.Firewall{ID: 123}, hcloud.FirewallUpdateOpts{
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

func DeleteAFw() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	_, err := client.Firewall.Delete(ctx, &hcloud.Firewall{ID: 123})
	if err != nil {
		fmt.Println("❌ Error deleting firewall:", err)
	}
}

func ApplyToResources() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	actions, _, err := client.Firewall.ApplyResources(ctx, &hcloud.Firewall{ID: 123}, []hcloud.FirewallResource{
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
	_ = client.Action.WaitFor(ctx, actions...)
}

func RemoveFromResources() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	actions, _, err := client.Firewall.RemoveResources(ctx, &hcloud.Firewall{ID: 123}, []hcloud.FirewallResource{
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
	_ = client.Action.WaitFor(ctx, actions...)
}

func SetRules() {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	actions, _, err := client.Firewall.SetRules(ctx, &hcloud.Firewall{ID: 123}, hcloud.FirewallSetRulesOpts{
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
	_ = client.Action.WaitFor(ctx, actions...)
}
