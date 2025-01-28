#!/bin/bash
# Usage: ./prepSourceCodeForStudents.sh <source_file> <private_key> <public_key>

# if clean, delete all .sig and .sha512 files
if [ "$1" = "clean" ]; then
    read -p "Are you sure you want to remove all .sig and .sha512 files in this directory? (y/n) " -n 1 -r
    echo # Add newline after response
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -f *.sig *.sha512
        echo -e "${GREEN}Successfully removed all signature and hash files${NC}"
        exit 0
    else
        echo -e "\e[33mOperation cancelled\e[0m"
        exit 0
    fi
fi

# Validate required arguments
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <source_file> <private_key> <public_key>"
    exit 1
fi

SOURCE_FILE=$1
PRIVATE_KEY=$2
PUBLIC_KEY=$3
SOURCE_BASENAME=$(basename "$SOURCE_FILE")

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Validate files exist
for file in "$SOURCE_FILE" "$PRIVATE_KEY" "$PUBLIC_KEY"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: File '$file' not found${NC}"
        exit 1
    fi
done

# Step 1: Create SHA-512 Hash
openssl dgst -sha512 "$SOURCE_FILE" > "${SOURCE_BASENAME}.sha512"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Step 1: SHA-512 hash created successfully${NC}"
else
    echo -e "${RED}Step 1: Failed to create hash${NC}"
    exit 1
fi

# Step 2: Create signature
openssl dgst -sha512 -sign "$PRIVATE_KEY" \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:-1 \
    -out "${SOURCE_BASENAME}.sig" "$SOURCE_FILE"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Step 2: Signature created successfully${NC}"
else
    echo -e "${RED}Step 2: Failed to create signature${NC}"
    exit 1
fi

# Step 3: Validate signature
openssl dgst -sha512 -verify "$PUBLIC_KEY" \
    -signature "${SOURCE_BASENAME}.sig" \
    -sigopt rsa_padding_mode:pss \
    -sigopt rsa_pss_saltlen:-1 "$SOURCE_FILE"
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Step 3: Signature validated successfully${NC}"
    echo -e "${GREEN}All steps completed successfully${NC}"
else
    echo -e "${RED}Step 3: Failed to validate signature${NC}"
    exit 1
fi