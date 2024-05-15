#!/bin/bash

PS4='[\033[95m**\033[0m] '
set -x

sudo umount ./mount
sudo rmmod singlefilefs
make clean
rm singlefilemakefs
rmdir mount
rm image

set +x
