# Eos
Eos aims to help make ubuntu server administration easier for those of us who weren't born in a bash shell.

We use all the tools here on a daily basis. Because of this, you can be assured they are actively used and maintained. You should also be aware, therefore, that because they are being actively updated and adjusted, they should be considered 'current best effort' and not a perfect product.

# See out knowledge base, [Athena](https://wiki.cybermonkey.net.au), for more on how to use this.

# Quick deployment
## Unix-like systems only
Give yourself admin access
```
su
```

```
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
```

Install golang on RHEL:
```
yum update
yum install golang
go install golang.org/x/term
```

Install golang on Debian-based:
```
apt update
apt install golang
go install golang.org/x/term
```
 


# Other links
See our website: [cybermonkey.net.au](https://cybermonkey.net.au/)

Our [Facebook](https://www.facebook.com/codemonkeycyber)

Or [X/Twitter](https://x.com/codemonkeycyber)


# Complaints, compliments, confusion:

Secure email: [main@cybermonkey.net.au](mailto:main@cybermonkey.net.au)  
Website: [cybermonkey.net.au](https://cybermonkey.net.au)

```
#     ___         _       __  __          _
#    / __|___  __| |___  |  \/  |___ _ _ | |_____ _  _
#   | (__/ _ \/ _` / -_) | |\/| / _ \ ' \| / / -_) || |
#    \___\___/\__,_\___| |_|  |_\___/_||_|_\_\___|\_, |
#                  / __|  _| |__  ___ _ _         |__/
#                 | (_| || | '_ \/ -_) '_|
#                  \___\_, |_.__/\___|_|
#                      |__/
```


---
© 2025 [Code Monkey Cybersecurity](https://cybermonkey.net.au/). ABN: 77 177 673 061. All rights reserved.
