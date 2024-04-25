#!/bin/bash

PS4="[*] "
set -x

sudo umount ./mount
sudo rmmod singlefilefs
make clean

set +x
