#!/bin/bash

PS4='[\033[93m*\033[0m] '
ROOT=`pwd`

set -ex

sudo dmesg -C
cd $ROOT/singlefile-FS
./load.sh

cd $ROOT/reference-monitor-kprobes
./load.sh

cd $ROOT/Linux-sys_call_table-discoverer
./load.sh

cd $ROOT/sys_call_installer
./load.sh

# user space:
cd $ROOT
./generate_syscall_numbers_header.sh

cd $ROOT/user
make all

set +x
