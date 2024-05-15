#!/bin/bash

PS4='[\033[95m**\033[0m] '
set -ex

make all &&
sudo insmod sys_call_installer.ko

set +x
