# Draft 


* On the Mailcow server, consider restricting inbound connections for mail ports (25, 587, 993, etc.) only from your remote proxy server’s IP if you want to force all mail traffic to go through the proxy.
```
# for mailcow
sudo ufw allow 25
sudo ufw allow 587
sudo ufw allow 993
```
