#!/bin/bash
# Command format like: ./generateKeys.sh <keyname>

# Check if the user has provided a key name
if [ $# -ne 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: ./generateKeys.sh <keyname>/clean"
    exit 1
fi

# if clean
if [ "$1" = "clean" ]; then
    # are you sure?
    read -p "Are you sure you want to remove all .pem keys in this directory? (y/n) " -n 1 -r
    echo # new line
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f *.pem
        echo -e "\e[32mAll keys removed\e[0m"
    else
        echo -e "\e[33mOperation cancelled\e[0m"
    fi
    exit 0
fi

# Get the key name from the command line
keyname=$1

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Step 1: Generate RSA PRIVATE Key
openssl genpkey -algorithm RSA -out ${keyname}-PRIVATE_key.pem -pkeyopt rsa_keygen_bits:2048
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Step 1: PRIVATE key generated: ${keyname}-PRIVATE_key.pem${NC}"
else
    echo -e "${RED}Step 1: Failed to generate PRIVATE key${NC}"
    exit 1
fi

# Step 2: Extract the Public Key
openssl rsa -pubout -in ${keyname}-PRIVATE_key.pem -out ${keyname}-public_key.pem
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Step 2: Public key extracted: ${keyname}-public_key.pem${NC}"
else
    echo -e "${RED}Step 2: Failed to extract public key${NC}"
    exit 1
fi

echo -e "${GREEN}All keys generated successfully${NC}"