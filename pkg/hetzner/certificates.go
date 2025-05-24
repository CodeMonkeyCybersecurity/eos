// pkg /hetzner/certificates.go
package hetzner

import (
	"context"
	"fmt"
	"os"

	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func GetAllCerts() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	certs, err := client.Certificate.All(ctx)
	if err != nil {
		return cerr.Wrap(err, "failed to retrieve certificates")
	}
	for _, c := range certs {
		fmt.Printf("📜 Certificate: %s (ID: %d)\n", c.Name, c.ID)
	}
	return nil
}

func CreateManagedCert() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	cert, _, err := client.Certificate.Create(ctx, hcloud.CertificateCreateOpts{
		DomainNames: []string{
			"example.com",
			"webmail.example.com",
			"www.example.com",
		},
		Name: "my website cert",
		Type: hcloud.CertificateTypeManaged,
	})
	if err != nil {
		return cerr.Wrap(err, "failed to create managed certificate")
	}
	fmt.Printf("✅ Managed cert created: %s (ID: %d)\n", cert.Name, cert.ID)
	return nil
}

func CreateUploadedCert() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	cert, _, err := client.Certificate.Create(ctx, hcloud.CertificateCreateOpts{
		Certificate: "-----BEGIN CERTIFICATE-----\n...",
		Name:        "my website cert",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----\n...",
		Type:        hcloud.CertificateTypeUploaded,
	})
	if err != nil {
		return cerr.Wrap(err, "failed to create uploaded certificate")
	}
	fmt.Printf("✅ Uploaded cert created: %s (ID: %d)\n", cert.Name, cert.ID)
	return nil
}

func GetCert() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	cert, _, err := client.Certificate.GetByID(ctx, 123)
	if err != nil {
		return cerr.Wrap(err, "failed to get certificate")
	}
	fmt.Printf("🔍 Got certificate: %s (ID: %d)\n", cert.Name, cert.ID)
	return nil
}

func UpdateCert() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	updated, _, err := client.Certificate.Update(ctx, &hcloud.Certificate{ID: 123}, hcloud.CertificateUpdateOpts{
		Labels: map[string]string{
			"environment":    "prod",
			"example.com/my": "label",
			"just-a-key":     "",
		},
		Name: "my website cert",
	})
	if err != nil {
		return cerr.Wrap(err, "failed to update certificate")
	}
	fmt.Printf("✏️ Updated certificate: %s (ID: %d)\n", updated.Name, updated.ID)
	return nil
}

func DeleteCert() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	_, err := client.Certificate.Delete(ctx, &hcloud.Certificate{ID: 123})
	if err != nil {
		return cerr.Wrap(err, "failed to delete certificate")
	}
	fmt.Println("🗑️ Certificate deleted")
	return nil
}

func GetAllActions() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	actions, err := client.Certificate.Action.All(ctx, hcloud.ActionListOpts{})
	if err != nil {
		return cerr.Wrap(err, "failed to get certificate actions")
	}
	for _, a := range actions {
		fmt.Printf("📦 Cert Action: %s (ID: %d, Status: %s)\n", a.Command, a.ID, a.Status)
	}
	return nil
}

func GetAnAction() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	action, _, err := client.Certificate.Action.GetByID(ctx, 123)
	if err != nil {
		return cerr.Wrap(err, "failed to get certificate action")
	}
	fmt.Printf("🎯 Cert Action ID %d: %s (%s)\n", action.ID, action.Command, action.Status)
	return nil
}

func RetryRenewal() error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))
	ctx := context.TODO()

	action, _, err := client.Certificate.RetryIssuance(ctx, &hcloud.Certificate{ID: 123})
	if err != nil {
		return cerr.Wrap(err, "failed to trigger retry")
	}

	if err := client.Action.WaitFor(ctx, action); err != nil {
		return cerr.Wrap(err, "retry wait failed")
	}

	fmt.Println("🔁 Certificate retry successful")
	return nil
}
