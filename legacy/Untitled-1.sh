
sudo echo 'deb http://linux.dell.com/repo/community/openmanage/{product-version}/{release-name} {release-name} main' | sudo tee -a /etc/apt/sources.list.d/linux.dell.com.sources.list

v5.4.0.0

sudo echo 'deb http://linux.dell.com/repo/community/openmanage/540/noble noble main' | sudo tee -a /etc/apt/sources.list.d/linux.dell.com.sources.list




dpkg -i dcism-osc-5.4.0.0.ubuntu.24.04.deb




gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dell.gpg


wget -qO - https://linux.dell.com/repo/pgp_pubkeys/0x1285491434D8786F.asc | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/dell.gpg




sudo microceph cluster join eyJzZWNyZXQiOiI1NjQ5NjRmODdhOGEzNWM4MGI3ZWQ4YjU2M2U5M2E2NzdjOTg0NmU2N2QxNzg1Njc3MDI2N2UzZGZmMjgyY2JmIiwiZmluZ2VycHJpbnQiOiIxNzc5NDJkNGMyM2Q1ZDQ3NGZjOGNlMTViYjljM2Q0OGRhZGMyMzEyZDVlYTI2ZTFiZDg2ZGIwMWMzNDVjMzVhIiwiam9pbl9hZGRyZXNzZXMiOlsiMTkyLjE2OC40LjIzOTo3NDQzIl19 --microceph-ip 192.168.4.239:7443