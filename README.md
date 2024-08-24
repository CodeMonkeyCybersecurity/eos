## MonQ-fabric
 scripting and automation

To help make ubuntu-server administration easier for those of us who weren't born in a bash shell.

# For example

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

