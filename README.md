# Eos
Eos aims to help make ubuntu server administration easier for those of us who weren't born in a bash shell.

We use all the tools here on a daily basis. Because of this, you can be assured they are actively used and maintained. You should also be aware, therefore, that because they are being actively updated and adjusted, they should be considered 'current best effort' and not a perfect product.

## Run getStarted.sh
This is done typing: 
``` bash
user@hostname:~$ cd ~/Eos
user@hostname:~$ sudo ./getStarted.sh
```
While not 100% necessary, this adds some helpful open source shell utilities and the necessary packages needed to run the scripts in Eos without further bother. So, not strictly necessary, but highly recommended.


## For example
Turns:
``` bash
sudo useradd -m -s /bin/bash user
echo "user:supersecretpassword" | sudo chpasswd
sudo usermod -aG sudo user
```

Into something a human can understand:
``` bash
sudo ./addUser.sh
```
The terminal will then ask you to:
```bash
Enter the new username:
Enter the password:
Confirm password:
Should this user have sudo privileges?:
```

## How to use scripts ending in .sh
These scripts are bash shell scripts
In the 'For Example' section above, we added a new user. The script to add a new user is called 'addUser.sh', so:

Start in the main scripts directory
``` bash
user@hostname:~$ cd ~/Eos/scripts
```

Make sure the script you want to run is executable:
```bash
user@hostname:~/Eos/scripts$ sudo chmod +x addUser.sh
```

Then execute it:
```bash
user@hostname:~/Eos/scripts$ sudo ./addUser.sh
```

The script to create a new SSH key is called 'createSshKey.sh'. So, to create a new SSH key, we simply: 
```bash
user@hostname:~/Eos/scripts$ sudo ./createSshKey.sh
```

## How to use scripts ending in .py
These scripts are written in python. Python is almost always installed by default in Ubuntu distributions.
If the script ends in .py, for example configureBorg.py, type:
```bash
user@hostname:~$ cd ~/Eos/scripts
user@hostname:~/Eos/scripts$ sudo python3 configureBorg.py
```
and press enter

## How to use scripts ending in .mjs
These scripts are written in a javascript-based scripting language which is maintained by Google, zx.
These zx scripts end in .mjs, for example 'installKube.mjs'.
The 'installKube.mjs' script helps install a Kubernetes cluster.
If the script ends in .mjs, for example 'installKube.mjs':

Install zx globally using node package manager (npm)
```bash
user@hostname:~$ cd ~/Eos/scripts
user@hostname:~/Eos/scripts$ sudo apt install npm #If npm isn't already installed, or you don't know whether it is installed or not
user@hostname:~/Eos/scripts$ sudo npm install -g zx
```

Make sure the script you want to run is executable. For this example we are using 'installKube.mjs', so:
```bash
user@hostname:~/Eos/scripts$ sudo chmod +x installKube.mjs
```

To run the script:
```bash
user@hostname:~/Eos/scripts$ sudo zx installKube.mjs
```

Replace 'installKube.mjs' with whichever .mjs script you want to run.

## What other scripts are available?
To find out what other scripts are available:
```bash
user@hostname:~/Eos/scripts$ ls
```

## Complaints, compliments, confusion and other communications:

Secure email: [git@cybermonkey.net.au](mailto:git@cybermonkey.net.au)  

Website: [cybermonkey.net.au](https://cybermonkey.net.au)

```
     ___         _       __  __          _
    / __|___  __| |___  |  \/  |___ _ _ | |_____ _  _
   | (__/ _ \/ _` / -_) | |\/| / _ \ ' \| / / -_) || |
    \___\___/\__,_\___| |_|  |_\___/_||_|_\_\___|\_, |
                  / __|  _| |__  ___ _ _         |__/
                 | (_| || | '_ \/ -_) '_|
                  \___\_, |_.__/\___|_|
                      |__/
```
