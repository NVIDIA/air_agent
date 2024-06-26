#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -e # exit on error

who=`whoami`
if [ $who != 'root' ]; then
    echo 'Install script must be run as root'
    exit 1
fi

while getopts ":v:" opt; do
    case "${opt}" in
        v)
            AIR_VRF=${OPTARG}
            ;;
    esac
done

install_service() {
    if [ -z "$1" ]; then
        cp ./air-agent.service /etc/systemd/system/air-agent.service
        systemctl enable air-agent
        systemctl start air-agent
    else
        echo "Enabling in VRF ${1}..."
        IP_BIN=`which ip`
        cp ./air-agent@.service /etc/systemd/system/air-agent@.service
        sed -i 's,{1},'"${IP_BIN}"',' /etc/systemd/system/air-agent@.service
        sed -i "s/{2}/${1}/" /etc/systemd/system/air-agent@.service
        systemctl enable air-agent@${1}
        systemctl start air-agent@${1}
    fi
}

echo "####################################"
echo "# Installing air-agent             #"
echo "####################################"
mkdir -p /usr/local/lib/air-agent
cp ./*.py /usr/local/lib/air-agent/
echo "Done!"

echo "####################################"
echo "# Enabling systemd service         #"
echo "####################################"
install_service $AIR_VRF
echo "Done!"

exit 0
