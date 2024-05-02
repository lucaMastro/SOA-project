#!/bin/bash

PS4="[*] "
set -ex

make all &&
sudo insmod the_usctm.ko

set +x
