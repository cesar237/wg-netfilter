#!/bin/bash

modprobe wireguard
rmmod wireguard
make clean && make
insmod wireguard.ko
wg-quick up wg