#!/bin/bash

PS4="[*] "
set -x

sudo umount ./mount
sudo rmmod singlefilefs
make clean
rm singlefilemakefs
rmdir mount
rm image

set +x
