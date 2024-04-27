#!/bin/bash

echo "Give me the password: "
read -s password
echo "$password" | sudo openssl dgst -sha256 -binary | sudo tee hash_sha256.bin >/dev/null
