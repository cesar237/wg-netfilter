ccflags-y := -D'pr_fmt(fmt)=KBUILD_MODNAME ": " fmt'
ccflags-$(CONFIG_WIREGUARD_DEBUG) += -DDEBUG
wireguard-y := main.o
wireguard-y += noise.o
wireguard-y += wg_netfilter.o
wireguard-y += device.o
wireguard-y += peer.o
wireguard-y += timers.o
wireguard-y += queueing.o
wireguard-y += send.o
wireguard-y += receive.o
wireguard-y += socket.o
wireguard-y += peerlookup.o
wireguard-y += allowedips.o
wireguard-y += ratelimiter.o
wireguard-y += cookie.o
wireguard-y += netlink.o
obj-$(CONFIG_WIREGUARD) := wireguard.o

KERN_DIR=/lib/modules/$(shell uname -r)/build/

host:
	make -C $(KERN_DIR) M=$(PWD) modules
install:
	make -C $(KERN_DIR) M=$(PWD) modules_install
	depmod -A
clean:
	make -C $(KERN_DIR) M=$(PWD) clean
help:
	make -C $(KERN_DIR) M=$(PWD) help
