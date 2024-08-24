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
Enter the new username:
Enter the password:
Confirm password:
Should this user have sudo privileges?:
```

## How to use 
Start in your main user directory

``` bash
cd ~
```

Clone this repository
``` bash
git clone https://github.com/chickenj0/MonQ-fabric.git
```

Enter the directory you've just made
``` bash
cd MonQ-fabric
```

Find the available scripts
``` bash
ls -lah
```

Install the 'run' command
``` bash
sudo chmod +x install_run.sh
sudo ./install_run.sh


Use the 'run' command. For the example above (adding a new user), it would look like
``` bash
run add_user.sh
```

Or, to create a new ssh key
```bash
run create_ssh_key.sh
```

Or, to check what else you can do with the 'run' command, simply type:
```bash
run
```
