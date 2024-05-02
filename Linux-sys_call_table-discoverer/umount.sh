#!/bin/bash

PS4="[*] "
set -x

sudo rmmod the_usctm
make clean

set +x
