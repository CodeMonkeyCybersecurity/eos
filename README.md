# Eos
**Eos** aims to help make ubuntu server administration easier for those of us who weren't born in a bash shell.

We use all the tools here on a daily basis - this means that they're **actively maintained**, but also **constantly evolving**.

See our knowledge base, [Athena](https://wiki.cybermonkey.net.au), for more on how to use this.

---

## 🚀 Quick Deployment

### Get admin access 

#### UNIX-like systems, including MacOS):
```
sudo -i  # or 'su' if you prefer
```

#### On Windows
Open PowerShell or Command Prompt as Administrator


### Clone the repo and prep Go modules:
```
cd /opt
git clone https://github.com/CodeMonkeyCybersecurity/eos.git
cd eos
```

#### On RHEL:
```
yum update
yum install golang
go mod tidy
```

#### On Debian-based systems:
```
apt update
apt install golang
go mod tidy
```
 
#### On MacOS X:
Install Homebrew if you haven’t:
```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Update and install Go using Homebrew
```
brew update
brew install go
```

#### On Windows:
Go to `https://go.dev/dl/`

Download and run the .msi installer for Windows.

Run the installer

After install, restart your terminal (PowerShell or CMD)



# Other links
Website: [cybermonkey.net.au](https://cybermonkey.net.au/)

[Facebook](https://www.facebook.com/codemonkeycyber)

[X/Twitter](https://x.com/codemonkeycyber)

[LinkedIn](https://www.linkedin.com/company/codemonkeycyber)

[YouTube](https://www.youtube.com/@CodeMonkeyCybersecurity)


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
