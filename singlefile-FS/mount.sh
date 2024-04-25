#!/bin/bash

PS4="[*] "
set -ex

make all &&
sudo insmod singlefilefs.ko &&
make create-fs &&
sudo make mount-fs &&

set +x
