# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
# Define the Ubuntu box to use - libvirt compatible box
ubuntu_box = "generic/debian12"  # Debian12 LTS for libvirt

# Configure the client VM
config.vm.define "client" do |client|
    client.vm.box = ubuntu_box
    client.vm.hostname = "client"
    
    client.vm.provider "libvirt" do |lv|
    lv.memory = "1024"
    lv.cpus = 1
    end
end

# Configure the server VM
config.vm.define "server" do |server|
    server.vm.box = ubuntu_box
    server.vm.hostname = "server"
    
    server.vm.provider "libvirt" do |lv|
    lv.memory = "1024"
    lv.cpus = 1
    end
end

# Configure the target VM
config.vm.define "target" do |target|
    target.vm.box = ubuntu_box
    target.vm.hostname = "target"
    
    target.vm.provider "libvirt" do |lv|
    lv.memory = "1024"
    lv.cpus = 1
    end
end

end