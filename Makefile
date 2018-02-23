obj-m += iproxy-server.o iproxy-client.o
#obj-m += test.o
iproxy-server-objs := server.o xlate.o route.o masq.o
iproxy-client-objs := client.o route.o masq.o
#test-objs := masq.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
