# MonQ-fabric
 scripting and automation

To help make ubuntu server administration easier for those of us who weren't born in a bash shell.

## For example

Turns:
``` bash
sudo useradd -m -s /bin/bash user
echo "user:supersecretpassword" | sudo chpasswd
sudo usermod -aG sudo user
```

Into something the rest of us can use:
``` bash
Enter the new username:
Enter the password:
Confirm password:
Should this user have sudo privileges?:
```

## How to use 
Start in your main user directory

``` bash
git clone https://github.com/chickenj0/MonQ-fabric.git
cd MonQ-fabric
```
Find the available scripts
``` bash
ls -lah
```

Chose the script you want and execute it. In the example above:
``` bash
chmod +x add_user.sh
./add_user.sh
```
