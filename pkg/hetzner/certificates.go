// pkg /hetzner/certificates.go
package hetzner

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	cerr "github.com/cockroachdb/errors"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

func GetAllCerts(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	certs, err := client.Certificate.All(rc.Ctx)
	if err != nil {
		return cerr.Wrap(err, "failed to retrieve certificates")
	}
	for _, c := range certs {
		fmt.Printf(" Certificate: %s (ID: %d)\n", c.Name, c.ID)
	}
	return nil
}

func CreateManagedCert(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	cert, _, err := client.Certificate.Create(rc.Ctx, hcloud.CertificateCreateOpts{
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
	fmt.Printf(" Managed cert created: %s (ID: %d)\n", cert.Name, cert.ID)
	return nil
}

func CreateUploadedCert(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	cert, _, err := client.Certificate.Create(rc.Ctx, hcloud.CertificateCreateOpts{
		Certificate: "-----BEGIN CERTIFICATE-----\n...",
		Name:        "my website cert",
		PrivateKey:  "-----BEGIN PRIVATE KEY-----\n...",
		Type:        hcloud.CertificateTypeUploaded,
	})
	if err != nil {
		return cerr.Wrap(err, "failed to create uploaded certificate")
	}
	fmt.Printf(" Uploaded cert created: %s (ID: %d)\n", cert.Name, cert.ID)
	return nil
}

func GetCert(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	cert, _, err := client.Certificate.GetByID(rc.Ctx, 123)
	if err != nil {
		return cerr.Wrap(err, "failed to get certificate")
	}
	fmt.Printf(" Got certificate: %s (ID: %d)\n", cert.Name, cert.ID)
	return nil
}

func UpdateCert(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	updated, _, err := client.Certificate.Update(rc.Ctx, &hcloud.Certificate{ID: 123}, hcloud.CertificateUpdateOpts{
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
	fmt.Printf(" Updated certificate: %s (ID: %d)\n", updated.Name, updated.ID)
	return nil
}

func DeleteCert(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	_, err := client.Certificate.Delete(rc.Ctx, &hcloud.Certificate{ID: 123})
	if err != nil {
		return cerr.Wrap(err, "failed to delete certificate")
	}
	fmt.Println(" Certificate deleted")
	return nil
}

func GetAllActions(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	actions, err := client.Certificate.Action.All(rc.Ctx, hcloud.ActionListOpts{})
	if err != nil {
		return cerr.Wrap(err, "failed to get certificate actions")
	}
	for _, a := range actions {
		fmt.Printf(" Cert Action: %s (ID: %d, Status: %s)\n", a.Command, a.ID, a.Status)
	}
	return nil
}

func GetAnAction(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	action, _, err := client.Certificate.Action.GetByID(rc.Ctx, 123)
	if err != nil {
		return cerr.Wrap(err, "failed to get certificate action")
	}
	fmt.Printf(" Cert Action ID %d: %s (%s)\n", action.ID, action.Command, action.Status)
	return nil
}

func RetryRenewal(rc *eos_io.RuntimeContext) error {
	token := os.Getenv("HCLOUD_TOKEN")
	client := hcloud.NewClient(hcloud.WithToken(token))

	action, _, err := client.Certificate.RetryIssuance(rc.Ctx, &hcloud.Certificate{ID: 123})
	if err != nil {
		return cerr.Wrap(err, "failed to trigger retry")
	}

	if err := client.Action.WaitFor(rc.Ctx, action); err != nil {
		return cerr.Wrap(err, "retry wait failed")
	}

	fmt.Println(" Certificate retry successful")
	return nil
}
