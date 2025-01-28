#!/bin/bash

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;94m'
NC='\033[0m' # No Color

# Check if correct number of arguments provided
if [ "$#" -lt 4 ] || [ "$#" -gt 5 ]; then
    echo -e "${YELLOW}Usage:${NC} $0 <student_encrypted_file> <student_key_file> <instructor_private_key> <instructor_public_key> [--keep-key]"
    exit 1
fi

STUDENT_FILE=$1
STUDENT_KEY=$2  
PRIVATE_KEY=$3
PUBLIC_KEY=$4
KEEP_KEY=false

# Check for optional flag
if [ "$#" -eq 5 ] && [ "$5" = "--keep-key" ]; then
    KEEP_KEY=true
fi

# Extract student and project names
FILENAME=$(basename "$STUDENT_FILE")
STU_PROJ=${FILENAME%-submission.aes}

# Define output files
SYMM_KEY="${STU_PROJ}-symm_key.bin"
PLAIN_CODE="${STU_PROJ}.plaincode"
KEY_DECRYPTED="${STU_PROJ}-submission.key_decrypted"

# Validate files exist
for file in "$STUDENT_FILE" "$STUDENT_KEY" "$PRIVATE_KEY" "$PUBLIC_KEY"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}Error: Required file '$file' not found${NC}"
        exit 1
    fi
done

# 1. Decrypt the AES Key (with explicit OAEP padding)
echo "Decrypting the AES Key..."
cat ${STUDENT_KEY} | xxd -p -r | openssl pkeyutl -decrypt \
    -inkey $PRIVATE_KEY \
    -pkeyopt rsa_padding_mode:oaep \
    -pkeyopt rsa_oaep_md:sha256 \
    -out "$SYMM_KEY"

# 2. Extract IV and Ciphertext from student file
echo "Extracting IV and Ciphertext..."
IV_HEX=$(cut -d: -f1 ${STUDENT_FILE}) 
CIPHER_HEX=$(cut -d: -f2 ${STUDENT_FILE})

# 3. Decrypt the Project
echo "$CIPHER_HEX" | xxd -p -r | openssl enc -d -aes-256-cbc \
  -iv "$IV_HEX" \
  -K $(xxd -p -c 256 "$SYMM_KEY") \
  -out "$PLAIN_CODE-temp"

cp "$PLAIN_CODE-temp" "$PLAIN_CODE"

# Cleanup
if [ "$KEEP_KEY" = false ]; then
    rm -f "$SYMM_KEY"
fi

# Read and trim plaincode file
PLAINCODE_FILE=$(cat "$PLAIN_CODE")
echo "$PLAINCODE_FILE" | awk -v delim=$'\u2400' 'index($0, delim) { exit } { print }' > "$PLAIN_CODE"

echo -e "${GREEN}Decryption complete!${NC}"
echo "Decrypted code saved as: $PLAIN_CODE"

# 4. Validate decrypted content (fixed version)
echo "Validating decrypted content..."

# Use strict delimiter parsing
DELIMITER=$'\u2400' # Match the Unicode character from TypeScript

# Extract code content (everything before first delimiter)
CODE_CONTENT=$(awk -v delim="${DELIMITER}PUBKEY" 'index($0, delim) { exit } { print }' "$PLAIN_CODE-temp")

# Check delimiter presence first
if ! grep -q "${DELIMITER}PUBKEY" "$PLAIN_CODE-temp"; then
  echo "ERROR: Missing PUBKEY delimiter"
  exit 1
fi

if ! grep -q "${DELIMITER}HASH" "$PLAIN_CODE-temp"; then
  echo "ERROR: Missing HASH delimiter"
  exit 1
fi

# Extract public key (between PUBKEY and HASH delimiters)
EMBEDDED_KEY=$(awk -v start_delim="${DELIMITER}PUBKEY" -v end_delim="${DELIMITER}HASH" '
  found && $0 ~ end_delim { exit }
  found { print }
  $0 ~ start_delim { found=1 }
' "$PLAIN_CODE-temp")

# Extract hash (after HASH delimiter)
EMBEDDED_HASH=$(awk -v delim="${DELIMITER}HASH" 'index($0, delim) { getline; printf "%s", $0; exit }' "$PLAIN_CODE-temp")

rm "$PLAIN_CODE-temp"

# Generate hash with EXACT same content
GENERATED_HASH=$(printf "%s" "$CODE_CONTENT" | sha512sum | cut -d' ' -f1)

echo
echo -e "${BLUE}Embedded public key:"
echo -e "${BLUE}${EMBEDDED_KEY}${NC}"
echo 
echo -e "${BLUE}Instructor public key:"
echo -e "${BLUE}$(cat "$PUBLIC_KEY")${NC}"
echo
echo -e "${BLUE}Embedded hash: ${EMBEDDED_HASH}${NC}"
echo -e "${BLUE}Generated hash: ${GENERATED_HASH}${NC}"
echo

if [ "$GENERATED_HASH" = "$EMBEDDED_HASH" ]; then
    echo -e "${GREEN}Hash validation successful: Code integrity verified${NC}"
else
    echo -e "${RED}Error: Code integrity check failed - hash mismatch${NC}"
    exit 1
fi