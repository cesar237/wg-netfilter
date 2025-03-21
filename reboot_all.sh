#!/bin/bash


sudo virsh destroy wg-netfilter_server
sudo virsh destroy wg-netfilter_client
vagrant up
