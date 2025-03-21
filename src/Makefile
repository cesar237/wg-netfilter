obj-m += wg_netfilter.o noise.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

install:
	make -C $(KERNELDIR) M=$(PWD) modules_install
	depmod -a

uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/wg_netfilter.ko
	depmod -a

load:
	insmod wg-netfilter.ko port_to_encrypt=8000

unload:
	rmmod wg-netfilter