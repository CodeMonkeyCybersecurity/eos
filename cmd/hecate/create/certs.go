// cmd/hecate/create/certs.gop

package create

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	eos "github.com/CodeMonkeyCybersecurity/eos/pkg/eoscli"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eosio"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/hecate"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	letsEncryptPath = "/etc/letsencrypt/live/"
	hecateDir       = "/opt/hecate"
	certsDir        = "certs"
)

// CertsCmd is a Cobra command to generate and manage Hecate TLS certificates.
var CertsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Generate certificates for Hecate",
	RunE: eos.Wrap(func(ctx *eosio.RuntimeContext, cmd *cobra.Command, args []string) error {
		log := ctx.Log.Named("certs")
		log.Info("Checking Docker processes...")
		if err := runCommand([]string{"docker", "ps"}); err != nil {
			log.Error("Error running docker ps", zap.Error(err))
			return fmt.Errorf("checking docker processes: %w", err)
		}

		fmt.Println("Stopping Hecate...")
		if err := runCommand([]string{"docker", "compose", "down"}); err != nil {
			fmt.Println("Warning: Docker compose down failed (likely because there is no Hecate container up). Continuing...")
		}

		// 2. Load previous values (if available) and prompt for new ones.
		prevValues, err := loadLastValues()
		if err != nil {
			fmt.Printf("Error loading last values: %v\n", err)
			return fmt.Errorf("checking docker processes: %w", err)
		}

		baseDomain := interaction.PromptInput("Enter the base domain (e.g. domain.com)", prevValues["BASE_DOMAIN"], log)
		subdomain := promptSubdomain()
		mailCert := interaction.PromptInput("Enter the contact email (e.g. example@domain.com)", prevValues["EMAIL"], log)

		// Save the new values for future runs.
		newValues := map[string]string{
			"BASE_DOMAIN": baseDomain,
			"EMAIL":       mailCert,
		}
		if err := saveLastValues(newValues); err != nil {
			fmt.Printf("Error saving last values: %v\n", err)
			os.Exit(1)
		}

		// 3. Create the full domain for the certificate.
		fullDomain := baseDomain
		if subdomain != "" {
			fullDomain = fmt.Sprintf("%s.%s", subdomain, baseDomain)
		}
		fmt.Printf("\nThe full domain for certificate generation will be: %s\n", fullDomain)

		// 4. Run certbot to obtain the certificate.
		certbotCmd := []string{
			"certbot", "certonly", "--standalone",
			"-d", fullDomain,
			"--email", mailCert,
			"--agree-tos",
		}
		if err := runCommand(certbotCmd); err != nil {
			fmt.Printf("Error running certbot: %v\n", err)
			os.Exit(1)
		}

		// 5. Verify that the certificate files exist.
		certPath := fmt.Sprintf("letsEncryptPath%s/", fullDomain)
		fmt.Printf("Verifying that the certificates are in '%s'...\n", certPath)
		if err := runCommand([]string{"ls", "-l", certPath}); err != nil {
			fmt.Printf("Error verifying certificates at %s: %v\n", certPath, err)
			os.Exit(1)
		}

		// 6. Change to the /opt/hecate directory and ensure certs/ exists.
		if err := os.Chdir(hecateDir); err != nil {
			fmt.Printf("Error changing directory to %s: %v\n", hecateDir, err)
			os.Exit(1)
		}
		if err := os.MkdirAll(certsDir, shared.DirPermStandard); err != nil {
			fmt.Printf("Error creating certs directory: %v\n", err)
			os.Exit(1)
		}

		// 7. Ask user to confirm certificate name.
		//    If subdomain is blank, the default will be the base domain.
		defaultCertName := baseDomain
		if subdomain != "" {
			defaultCertName = subdomain
		}
		reader := bufio.NewReader(os.Stdin)
		var certName string
		for {
			fmt.Printf("Use certificate name '%s'? (yes/no): ", defaultCertName)
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm == "yes" || confirm == "y" {
				certName = defaultCertName
				break
			} else if confirm == "no" || confirm == "n" {
				certName = interaction.PromptInput("Enter the desired certificate name (for file naming)", "", log)
				break
			} else {
				fmt.Println("Please answer yes or no.")
			}
		}

		// 8. Copy certificate files.
		sourceFullchain := fmt.Sprintf("letsEncryptPath%s/fullchain.pem", fullDomain)
		sourcePrivkey := fmt.Sprintf("letsEncryptPath%s/privkey.pem", fullDomain)
		destFullchain := fmt.Sprintf("certs/%s.fullchain.pem", certName)
		destPrivkey := fmt.Sprintf("certs/%s.privkey.pem", certName)

		fmt.Println("Copying certificate files...")
		if err := runCommand([]string{"cp", sourceFullchain, destFullchain}); err != nil {
			fmt.Printf("Error copying fullchain.pem: %v\n", err)
			return fmt.Errorf("checking docker processes: %w", err)
		}
		if err := runCommand([]string{"cp", sourcePrivkey, destPrivkey}); err != nil {
			fmt.Printf("Error copying privkey.pem: %v\n", err)
			return fmt.Errorf("checking docker processes: %w", err)
		}

		// 9. Set appropriate permissions.
		fmt.Println("Setting appropriate permissions on the certificate files...")
		if err := runCommand([]string{"chmod", "644", destFullchain}); err != nil {
			fmt.Printf("Error setting permissions on %s: %v\n", destFullchain, err)
			return fmt.Errorf("checking docker processes: %w", err)
		}
		if err := runCommand([]string{"chmod", "600", destPrivkey}); err != nil {
			fmt.Printf("Error setting permissions on %s: %v\n", destPrivkey, err)
			return fmt.Errorf("checking docker processes: %w", err)
		}

		// 10. List the certs/ directory.
		fmt.Println("Listing the certs/ directory:")
		if err := runCommand([]string{"ls", "-lah", "certs/"}); err != nil {
			fmt.Printf("Error listing certs directory: %v\n", err)
			return fmt.Errorf("checking docker processes: %w", err)
		}

		// Final message.
		fmt.Printf("\nYou should now have the appropriate certificates for https://%s\n", fullDomain)
		fmt.Println("Next, run ./updateConfigVariables.py and ./updateEosApps.py before (re)starting Hecate")
		fmt.Println("\nfinis")

		return nil
	}),
}

// runCommand executes a command represented as a slice of strings.
// It prints the command, attaches Stdout/Stderr, and returns an error if the command fails.
func runCommand(cmd []string) error {
	fmt.Printf("Running command: %s\n", strings.Join(cmd, " "))
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

// loadLastValues reads key="value" pairs from .hecate.conf, returning a map.
// If the file does not exist, an empty map is returned.
func loadLastValues() (map[string]string, error) {
	values := make(map[string]string)
	file, err := os.Open(hecate.LastValuesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return values, nil
		}
		return nil, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close file %s: %v\n", hecate.LastValuesFile, cerr)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"`)
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

// saveLastValues writes the provided key/value pairs to .hecate.conf.
func saveLastValues(values map[string]string) error {
	file, err := os.Create(hecate.LastValuesFile)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			fmt.Printf("⚠️ Warning: failed to close file %s: %v\n", hecate.LastValuesFile, cerr)
		}
	}()

	for key, value := range values {
		_, err := fmt.Fprintf(file, `%s="%s"`+"\n", key, value)
		if err != nil {
			return err
		}
	}
	return nil
}

// promptSubdomain asks for a subdomain and, if the user leaves it blank,
// prompts for confirmation before returning an empty string.
func promptSubdomain() string {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter the subdomain to configure (e.g. sub). Leave blank if none: ")
		subdomain, _ := reader.ReadString('\n')
		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			fmt.Print("You entered a blank subdomain. Do you wish to continue with no subdomain? (yes/no): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm == "yes" || confirm == "y" {
				return ""
			}
			continue
		} else {
			return subdomain
		}
	}
}
