# Eos
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
sudo run addUser.sh
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
git clone https://github.com/chickenj0/Eos.git
```

3. Enter the directory you've just made
``` bash
cd Eos
```
4. Then 
``` bash
sudo python3 eos.py
cd ~/Eos/scripts
```



## How to use 
In the 'For Example' section above, we added a new user. The script to add a new user is called 'addUser.sh', so:
``` bash
user@hostname:~/Eos/scripts$ sudo chmod +x addUser.sh
user@hostname:~/Eos/scripts$ sudo ./addUser.sh
```

The script to create a new SSH key is called 'createSshKey.sh'. So, to create a new SSH key, we simply: 
```bash
sudo run createSshKey.sh
```

If the script ends in .py, for example configureBorg.py, type:
```bash
sudo python3 configureBorg.py
```
and press enter
