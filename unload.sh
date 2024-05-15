#!/bin/bash

PS4='[\033[93m*\033[0m] '
ROOT=`pwd`

set -x

cd $ROOT/sys_call_installer
./unload.sh

cd $ROOT/Linux-sys_call_table-discoverer
./unload.sh

cd $ROOT/reference-monitor-kprobes
./unload.sh

cd $ROOT/singlefile-FS
./unload.sh

rm $ROOT/lib/*.o

# user space:
cd $ROOT/user
make clean

set +x

