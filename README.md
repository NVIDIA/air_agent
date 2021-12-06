# air-agent

The AIR Agent is a systemd service that detects if a VM has been cloned. When a clone operation has been detected, it calls out to the AIR API to see if there are any post-clone instructions available to execute.

## Pre-requisites

Make sure `python3` and `pip3` are installed.

### Ubuntu 18.04 (python 3.6)

```
sudo apt update && sudo apt install -y python3 python3-pip
```

### Cumulus Linux 3.x (python 3.4)

```
echo 'deb http://deb.debian.org/debian/ jessie main' | sudo tee -a /etc/apt/sources.list
sudo apt update
sudo apt-get install -y build-essential libffi-dev python3-dev python3-setuptools
# As of February 2020, pip3 v20.x.x is having issues installing our dependencies,
#  so use v19.3.1 for now
sudo easy_install3 pip==19.3.1
```

## Installing

Make sure `python3` and `pip3` are installed, and then run:

`sudo ./install.sh`

For python < 3.6, you must install from the `python3.4` branch.

## Configuration

Configuration options are set in `/etc/nvidia-air/agent.ini`. After making configuration changes, the service must be restarted with `systemctl restart air-agent`.
