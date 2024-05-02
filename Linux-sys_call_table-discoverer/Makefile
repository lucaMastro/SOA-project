obj-m += the_usctm.o
the_usctm-objs += usctm.o ./lib/vtpmo.o
KBUILD_EXTRA_SYMBOLS=/home/luca/Scrivania/shared/reference-monitor-kprobes/Module.symvers
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

update:
	./umount.sh
	sudo dmesg -C
	./mount.sh
