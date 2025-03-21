#!/bin/bash

linux_version=6.1.0-30-amd64
sudo apt update
sudo apt install build-essential gcc make iperf3 sockperf linux-image-$linux_version linux-headers-$linux_version
sudo systemctl reboot