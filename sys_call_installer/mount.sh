#!/bin/bash

PS4="[*] "
set -ex

make all &&
sudo insmod sys_call_installer.ko

set +x
