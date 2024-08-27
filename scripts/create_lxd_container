#! /bin/sh

id=400000  # some large uid outside of typical range, and outside of already mapped ranges in /etc/sub{u,g}id
uid=$(id -u)
gid=$(id -g)
user=$(id -un)
group=$(id -gn)

# give lxc permission to map your user/group id through
sudo usermod --add-subuids ${uid}-${uid} --add-subgids ${gid}-${gid} root

# create a profile to control this
lxc profile create $user >/dev/null 2>&1

# configure profile
cat << EOF | lxc profile edit $user
name: $user
description: allow home dir mounting for $user
config:
  raw.idmap: |
    uid $uid $id
    gid $gid $id
  user.user-data: |
    #cloud-config
    runcmd:
      - "groupadd $group --gid $id"
      - "useradd $user --uid $id --gid $group --groups adm,sudo --shell /bin/bash"
      - "echo '$user ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/90-cloud-init-users"
      - "chmod 0440 /etc/sudoers.d/90-cloud-init-users"
devices:
  home:
    type: disk
    source: $HOME
    path: $HOME
EOF
