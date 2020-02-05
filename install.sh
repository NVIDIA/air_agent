#!/bin/bash

who=`whoami`
if [ $who != 'root' ]; then
    echo 'Install script must be run as root'
    exit 1
fi

echo "####################################"
echo "# Installing pip requirements      #"
echo "####################################"
pip3 install -r ./requirements.txt

echo "####################################"
echo "# Creating key file mount          #"
echo "####################################"
mkdir /mnt/air
chown cumulus:cumulus /mnt/air
echo '/dev/vdb /mnt/air auto defaults,nofail 0 0' >> /etc/fstab
mount -a

echo "####################################"
echo "# Installing air-agent             #"
echo "####################################"
mkdir -p /usr/local/lib/air-agent
chown cumulus:cumulus /usr/local/lib/air-agent
cp ./*.py /usr/local/lib/air-agent/

echo "####################################"
echo "# Configuring air-agent            #"
echo "####################################"
mkdir -p /etc/cumulus-air
chown cumulus:cumulus /etc/cumulus-air
cp ./agent.ini /etc/cumulus-air/agent.ini

echo "####################################"
echo "# Enabling systemd service         #"
echo "####################################"
cp ./air-agent.service /etc/systemd/system/air-agent.service
systemctl enable air-agent
systemctl start air-agent

exit 0
