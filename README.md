# air-agent

The AIR Agent is a systemd service that detects if a VM has been cloned. When a clone operation has been detected, it calls out to the AIR API to see if there are any post-clone instructions available to execute.

## Installing

Make sure `python3` and `pip3` are installed, and then run:

`sudo ./install.sh`

## Configuration

Configuration options are set in `/etc/cumulus-air/agent.ini`. After making configuration changes, the service must be restarted with `systemctl restart air-agent`.
