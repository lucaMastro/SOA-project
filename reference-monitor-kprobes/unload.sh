#!/bin/bash

PS4='[\033[95m**\033[0m] '
set -x

sudo rmmod reference_monitor
make clean

set +x
