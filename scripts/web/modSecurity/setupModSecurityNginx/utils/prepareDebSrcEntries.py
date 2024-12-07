def prepare_deb_src_entries(ubuntu_codename):
    entries = [
        "Types: deb-src",
        "URIs: http://archive.ubuntu.com/ubuntu/",
        f"Suites: {ubuntu_codename} {ubuntu_codename}-updates {ubuntu_codename}-backports",
        "Components: main restricted universe multiverse",
        "",
        "Types: deb-src",
        "URIs: http://security.ubuntu.com/ubuntu/",
        f"Suites: {ubuntu_codename}-security",
        "Components: main restricted universe multiverse",
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"
    ]
    return "\n".join(entries)

