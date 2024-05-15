#!/bin/bash

syscall_macros=("SYS_ADD" "SYS_GET" "SYS_RM" "SYS_CHANGE_PASS" "SYS_CHANGE_STATE")

# getting only non-0 elements
used_syscall_indexes=$(cat /sys/module/sys_call_installer/parameters/installed_syscall | awk -F',' '{for(i=1;i<=NF;i++) if($i!=0) print $i}')

# generate an array
used_syscall_indexes_array=($used_syscall_indexes)

size=${#used_syscall_indexes_array[@]}

if [ $size -ne ${#syscall_macros[@]} ]; then
    echo "Something went wrong: installed syscall numbers is different from the expected one"
    exit -1
fi


string=""
for (( i=0;i<$size;i++ )); do
    string+="#define ${syscall_macros[$i]} ${used_syscall_indexes_array[$i]}\n"
done

echo -e $string > `pwd`/user/lib/sys_call_numbers_header.h
