// pkg/kvm/templates.go

package kvm

import (
	"errors"
	"strings"
)

type TemplateContext struct {
	Username     string
	Password     string
	Hostname     string
	SSHKey       string
	TailscaleKey string
	VMName       string
}

// Validate ensures all required fields are set and safe
func (c *TemplateContext) Validate() error {
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("username is required")
	}
	if strings.TrimSpace(c.Password) == "" {
		return errors.New("password is required")
	}
	if strings.TrimSpace(c.Hostname) == "" {
		return errors.New("hostname is required")
	}
	if strings.TrimSpace(c.SSHKey) == "" {
		return errors.New("SSH key is required")
	}
	if strings.ContainsAny(c.Username, " \t\n\"'`$") {
		return errors.New("username contains unsafe characters")
	}
	return nil
}

const KickstartTemplate = `# CentOS Stream 9 Automated Tenant VM Kickstart

lang en_US.UTF-8
keyboard us
timezone UTC --utc
auth --enableshadow --passalgo=sha512
selinux --enforcing
firewall --enabled --service=ssh
rootpw --lock
services --enabled=sshd
firstboot --disable
autopart --type=lvm

# ----------- Pre-Install (Dynamic hostname + DHCP) ----------
%pre
echo "# Network and hostname config" > /tmp/hostname.ks
echo "network --bootproto=dhcp --activate --hostname={{ .Hostname }} --device=eth0" >> /tmp/hostname.ks
%end

%include /tmp/hostname.ks

%post --interpreter=/bin/bash
set -euxo pipefail

# Install QEMU agent
dnf install -y qemu-guest-agent
systemctl enable --now qemu-guest-agent

# Create user and set password
USERNAME='{{ .Username }}'
PASSWORD='{{ .Password }}'
useradd -m -G wheel "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
mkdir -p /root/.secrets
echo "$PASSWORD" > "/root/.secrets/${USERNAME}.pwd"
chmod 600 "/root/.secrets/${USERNAME}.pwd"

# Inject SSH key
mkdir -p "/home/$USERNAME/.ssh"
cat <<EOF > "/home/$USERNAME/.ssh/authorized_keys"
{{ .SSHKey }}
EOF
chmod 700 "/home/$USERNAME/.ssh"
chmod 600 "/home/$USERNAME/.ssh/authorized_keys"
chown -R "$USERNAME:$USERNAME" "/home/$USERNAME/.ssh"

# Enable SSH
systemctl enable sshd
systemctl start sshd

# Install and start Tailscale
for i in {1..3}; do curl -fsSL https://tailscale.com/install.sh | sh && break || sleep 3; done
tailscale up --authkey='{{ .TailscaleKey }}' --hostname="$(hostname)" --ssh || echo "⚠️ Tailscale failed to start"

# Debug info
ip a > /root/network-debug.txt
tailscale status > /root/tailscale-status.txt || true
hostname > /root/hostname.txt

echo "✅ VM Provisioned Successfully"
%end

reboot
`
