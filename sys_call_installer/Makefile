obj-m += sys_call_installer.o
sys_call_installer-objs += the_sys_call_installer.o ../lib/hash_helper.o
KBUILD_EXTRA_SYMBOLS=/home/luca/Scrivania/shared/Linux-sys_call_table-discoverer/Module.symvers /home/luca/Scrivania/shared/reference-monitor-kprobes/Module.symvers

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

update:
	./unload.sh
	dmesg -C
	./load.sh

