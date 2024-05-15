#!/bin/bash

PS4='[\033[95m**\033[0m] '
set -x

sudo rmmod the_usctm
make clean

set +x
