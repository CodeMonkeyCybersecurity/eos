# MonQ-fabric
To help make ubuntu server administration easier for those of us who weren't born in a bash shell.

## For example
Turns:
``` bash
sudo useradd -m -s /bin/bash user
echo "user:supersecretpassword" | sudo chpasswd
sudo usermod -aG sudo user
```

Into something a human can understand:
``` bash
sudo run add_user.sh
```
The terminal will then ask you to:
```bash
Enter the new username:
Enter the password:
Confirm password:
Should this user have sudo privileges?:
```

## How to install 
1. Start in your main user directory
``` bash
cd ~
```

2. Clone this repository
``` bash
git clone https://github.com/chickenj0/MonQ-fabric.git
```

3. Enter the directory you've just made
``` bash
cd MonQ-fabric
```

4. Install the 'run' command
``` bash
sudo chmod +x install_run.sh
sudo ./install_run.sh
```

## How to use 
In the 'For Example' section above, we added a new user. We did this by using the command 'run', and then selecting the script we want to use by typing it out. The script to add a new user is called 'add_user.sh', so:
``` bash
sudo run add_user.sh
```

The script to create a new SSH key is called 'create_ssh_key.sh'. So, to create a new SSH key, we simply: 
```bash
sudo run create_ssh_key.sh
```

To see what else you can do with 'run', simply type:
```bash
run
```
