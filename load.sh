
#!/bin/bash

PS4="[*] "
ROOT=`pwd`

password=`echo "asd" | tr -d "\n" | sha256sum | cut -d' ' -f1 | tr -d "\n"`

set -ex

sudo dmesg -C
cd $ROOT/reference-monitor-kprobes
make all
sudo insmod reference_monitor.ko starting_pass=$password

cd $ROOT/Linux-sys_call_table-discoverer
make all
sudo insmod the_usctm.ko

cd $ROOT/sys_call_installer
make all
sudo insmod sys_call_installer.ko

set +x
