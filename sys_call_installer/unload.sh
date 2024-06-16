#!/bin/bash

PS4='[\033[95m**\033[0m] '
set -x

sudo rmmod sys_call_installer
make clean
