#!/bin/bash

ROOT=$(dirname "`pwd`")
password=`echo "asd" | tr -d "\n" | sha256sum | cut -d' ' -f1 | tr -d "\n"`

PS4='[\033[95m**\033[0m] '
set -ex

make all
sudo insmod reference_monitor.ko starting_pass=$password singlefile_fs_path=$ROOT/singlefile-FS/mount/the-file
