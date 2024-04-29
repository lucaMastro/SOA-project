#!/bin/bash

PS4="[*] "
set -x

sudo rmmod sys_call_installer
make clean

set +x
