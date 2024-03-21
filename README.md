# air-agent

The NVIDIA Air Agent is a systemd service that detects if a VM has been cloned. When a clone operation has been detected, it calls out to the Air API to see if there are any post-clone instructions available to execute.

## Pre-requisites

Make sure `python3` and `pip3` are installed.

### Ubuntu 18.04 (python 3.6)

```
sudo apt update && sudo apt install -y python3 python3-pip
```

## Installing

Make sure `python3` and `pip3` are installed, and then run:

`sudo ./install.sh`


### For devices where connectivity to Air is desired over a VRF

Pass the desired VRF name to the install script:

`sudo ./install.sh -v <VRF>`

For example, in newer Cumulus Linux versions where eth0 is configured in the mgmt VRF by default:

`sudo ./install.sh -v mgmt`

## Configuration

The Air platform dynamically injects an appropriate agent configuration into the VM via /mnt/air/agent.ini. This path can be overridden with the `-c`/`--config-file` command line argument.

Additionally, individual settings can be overriden using environment variables prefixed with `AIR_AGENT_`. For example, to override the `LOG_LEVEL` setting, set an environment variable named `AIR_AGENT_LOG_LEVEL`.
