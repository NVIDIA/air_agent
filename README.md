# air-agent

The NVIDIA Air Agent is a systemd service that detects if a VM has been cloned. When a clone operation has been detected, it calls out to the Air API to see if there are any post-clone instructions available to execute.

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

_**NOTE:** For python < 3.6, you must install from the `python3.4` branch._

### For devices where connectivity to Air is desired over a VRF

Pass the desired VRF name to the install script:

`sudo ./install.sh -v <VRF>`

For example, in newer Cumulus Linux versions where eth0 is configured in the mgmt VRF by default:

`sudo ./install.sh -v mgmt`

## Configuration

The Air platform dynamically injects an appropriate agent configuration into the VM via /mnt/air/agent.ini. This path can be overridden with the `-c`/`--config-file` command line argument.
