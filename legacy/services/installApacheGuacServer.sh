#!/bin/bash
# installApacheGuacServer.sh
source../utilities/start.sh
apt update
# https://guacamole.apache.org/doc/gug/installing-guacamole.html
apt install -y gcc vim curl wget g++ libcairo2-dev libjpeg-turbo8-dev libpng-dev libtool-bin libossp-uuid-dev libavcodec-dev  libavformat-dev libavutil-dev libswscale-dev build-essential libpango1.0-dev libssh2-1-dev libvncserver-dev libtelnet-dev libpulse-dev libssl-dev libvorbis-dev libwebp-dev libwebsockets-dev
read -p "what is the latest version of of apache guacamole (eg. 1.5.5)?: " GUAC_VERSION
wget -o https://apache.org/dyn/closer.lua/guacamole/${GUAC_VERSION}/source/guacamole-server-${GUAC_VERSION}.tar.gz /tmp/guacServer_${GUAC_VERSION}
tar -xzf guacamole-server-${GUAC_VERSION}.tar.gz
cd guacamole-server-${GUAC_VERSION}/
./configure --with-init-dir=/etc/init.d
make
make install
ldconfig
cp guacamole/target/guacamole-${GUAC_VERSION}.war /var/lib/tomcat/webapps/guacamole.war

# TO DO FIGURE this shuit out:
# /etc/init.d/tomcat7 restart
# /etc/init.d/guacd start
# sudo add-apt-repository ppa:remmina-ppa-team/remmina-next-daily
# sudo apt update
# sudo apt install freerdp2-dev freerdp2-x11 -y
# sudo apt install openjdk-11-jdk
# java --version
# sudo apt install tomcat9 tomcat9-admin tomcat9-common tomcat9-user
# systemctl status tomcat9
# ufw allow 8080/tcp