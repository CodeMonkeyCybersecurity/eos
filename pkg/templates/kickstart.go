// pkg/templates/kickstart.go

package templates

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
echo "network --bootproto=dhcp --ipv6=auto --hostname={{ .VMName }} --device=eth0 --activate" >> /tmp/hostname.ks
echo "network --hostname={{ .Hostname }}" >> /tmp/hostname.ks
%end

%include /tmp/hostname.ks

%post --interpreter=/bin/bash
set -euxo pipefail

dnf install -y qemu-guest-agent
systemctl enable --now qemu-guest-agent

USERNAME="debugadmin"
USERHOME="/home/$USERNAME"
mkdir -p /root/.secrets

PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)
useradd -m -G wheel "$USERNAME"
echo "$USERNAME:$PASS" | chpasswd
echo "$PASS" > /root/.secrets/$USERNAME.pwd
chmod 600 /root/.secrets/$USERNAME.pwd

mkdir -p "$USERHOME/.ssh"
cat /tmp/id_ed25519.pub > "$USERHOME/.ssh/authorized_keys"
chmod 700 "$USERHOME/.ssh"
chmod 600 "$USERHOME/.ssh/authorized_keys"
chown -R "$USERNAME:$USERNAME" "$USERHOME/.ssh"

systemctl enable sshd
systemctl start sshd

for i in {1..3}; do curl -fsSL https://tailscale.com/install.sh | sh && break || sleep 3; done
TAILSCALE_KEY="tskey-REPLACE_THIS"
tailscale up --authkey=$TAILSCALE_KEY --hostname=$(hostname) --ssh || echo "⚠️ Tailscale failed to start"

ip a > /root/network-debug.txt
tailscale status > /root/tailscale-status.txt || true
hostname > /root/hostname.txt

echo "✅ VM Provisioned Successfully"
%end

reboot
`
