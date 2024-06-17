#!/bin/bash

ROOT=$(dirname "`pwd`")

while true; do
    echo -e "[\033[92m>>>\033[0m] Give me initial password: "
    read -s PLAINTEXT_PASS
    if [ -n "$PLAINTEXT_PASS" ]; then
        break
    else
        echo -e "[\033[91mxxx\033[0m] Password cannot be empty. Please try again."
    fi
done

password=`echo $PLAINTEXT_PASS | tr -d "\n" | sha256sum | cut -d' ' -f1 | tr -d "\n"`

PS4='[\033[95m**\033[0m] '
set -ex

make all
sudo insmod reference_monitor.ko starting_pass=$password singlefile_fs_path=$ROOT/singlefile-FS/mount/the-file
