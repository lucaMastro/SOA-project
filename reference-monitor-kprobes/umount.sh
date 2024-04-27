#!/bin/bash

PS4="[*] "
set -x

sudo rmmod reference_monitor
make clean

set +x
