#!/bin/bash

PS4="[*] "
set -ex

make all 
sudo insmod reference_monitor.ko

set +x
