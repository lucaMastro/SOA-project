#!/bin/bash
PASS_FILE="/home/luca/Scrivania/shared/hash_sha256"

echo "Give me the password: "
read -s password
rm $PASS_FILE
#echo "$password" | tr -d "\n" | sudo openssl dgst -sha256 -binary | sudo tee $PASS_FILE >/dev/null
echo "$password" | sudo openssl dgst -sha256 -binary | sudo tee $PASS_FILE >/dev/null
