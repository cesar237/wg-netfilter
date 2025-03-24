#!/bin/bash

vagrant up
vagrant ssh-config > ~/.ssh/config.d/20-vagrant

scp ./setup_server.sh server:~
scp ./setup_client.sh client:~

ssh server "./setup_server.sh"
ssh client "./setup_client.sh"

sleep 5

scp wg-client.conf client:wg.conf
scp wg-server.conf server:wg.conf

ssh server " sudo cp wg.conf /etc/wireguard "
ssh client " sudo cp wg.conf /etc/wireguard "

scp -r  wg-nf server: