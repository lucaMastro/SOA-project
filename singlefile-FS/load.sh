#!/bin/bash

PS4='[\033[95m**\033[0m] '
set -ex

make all
sudo insmod singlefilefs.ko
make create-fs
sudo make mount-fs
