# https://www.kernel.org/doc/Documentation/kbuild/modules.txt

KDIR=/lib/modules/$(shell uname -r)/build

ifeq ($(m),client)
obj-m := iproxy-client.o
iproxy-client-y := client.o route.o masq.o
else
obj-m := iproxy-server.o
iproxy-server-y := server.o xlate.o route.o masq.o
endif

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
