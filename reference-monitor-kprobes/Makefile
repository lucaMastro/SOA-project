obj-m += reference_monitor.o
reference_monitor-objs += the_reference_monitor.o ../lib/hash_helper.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

update:
	./unload.sh
	sudo dmesg -C
	./load.sh

