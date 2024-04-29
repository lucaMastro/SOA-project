#!/bin/bash

PS4="[*] "
ROOT=`pwd`

set -x

cd $ROOT/sys_call_installer
sudo rmmod sys_call_installer
make clean

cd $ROOT/Linux-sys_call_table-discoverer
sudo rmmod the_usctm
make clean

cd $ROOT/reference-monitor-kprobes
sudo rmmod reference_monitor
make clean


set +x

