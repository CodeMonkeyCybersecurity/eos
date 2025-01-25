# How to fix invalid signatures in Kali

Has been happening in fresh Kali installs ~25/1/25
```
┌──(kali㉿kali)-[~]
└─$ sudo apt update                            
Get:1 http://kali.download/kali kali-rolling InRelease [41.5 kB]
Err:1 http://kali.download/kali kali-rolling InRelease
  The following signatures were invalid: EXPKEYSIG ED444FF07D8D0BF6 Kali Linux Repository <devel@kali.org>
Fetched 41.5 kB in 1s (53.4 kB/s)
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
833 packages can be upgraded. Run 'apt list --upgradable' to see them.
W: An error occurred during the signature verification. The repository is not updated and the previous index files will be used. GPG error: http://kali.download/kali kali-rolling InRelease: The following signatures were invalid: EXPKEYSIG ED444FF07D8D0BF6 Kali Linux Repository <devel@kali.org>
W: Failed to fetch http://http.kali.org/kali/dists/kali-rolling/InRelease  The following signatures were invalid: EXPKEYSIG ED444FF07D8D0BF6 Kali Linux Repository <devel@kali.org>
W: Some index files failed to download. They have been ignored, or old ones used instead.
```


## Answer
The error you're encountering is due to an expired GPG key used to verify the repository signature for Kali Linux. This is a fairly common issue and can be fixed by updating the GPG keys used for package authentication.

Here's how you can resolve it:

1. **Update the expired key:**
   Kali Linux uses a repository key to verify package authenticity. You need to update the key that’s causing the error. To do this, run the following command to fetch and install the latest GPG key:

   ```bash
   sudo apt-key adv --fetch-keys http://archive.kali.org/archive-key.asc
   ```

2. **Update apt and repositories:**
   After updating the GPG key, refresh your package list by running:

   ```bash
   sudo apt update
   ```

3. **If the above doesn't work (in case `apt-key` is deprecated):**
   You may need to manually download and add the key to your system. You can use the `gpg` command for this purpose.

   First, download the key:

   ```bash
   wget -q -O - https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali-archive.gpg
   ```

   Then, run `sudo apt update` again:

   ```bash
   sudo apt update
   ```

4. **Check repository URL:**
   Make sure your `/etc/apt/sources.list` is correctly set up. The default Kali sources list should look something like this:

   ```bash
   deb http://http.kali.org/kali kali-rolling main non-free contrib
   ```

   You can check or edit the sources list with:

   ```bash
   sudo nano /etc/apt/sources.list
   ```

Once you've done these steps, the error should be fixed and you should be able to update your system successfully.
```
