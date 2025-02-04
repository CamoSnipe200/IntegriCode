#!/bin/bash
# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;94m'
MAGENTA='\033[0;35m'  # For suggestions
NC='\033[0m'  # No Color

usage() {
    echo -e "${YELLOW}Usage:${NC} $0 [-B <directory>] <instructor_private_key> <instructor_public_key> [--keep-key]"
    echo -e "For single mode: $0 <student_encrypted_file> <student_key_file> <instructor_private_key> <instructor_public_key> [--keep-key]"
    echo -e "  -B: Batch mode, process all student submissions in the specified directory"
    echo -e "  --keep-key: Keep the decrypted AES key file after processing"
    exit 1
}

# ---------------------------
# Parse command-line arguments
# ---------------------------
BATCH_MODE=false
KEEP_KEY=false
BATCH_DIR=""
positional=()

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        -B)
            BATCH_MODE=true
            shift
            if [ -z "$1" ]; then usage; fi
            BATCH_DIR="$1"
            shift
            ;;
        --keep-key)
            KEEP_KEY=true
            shift
            ;;
        *)
            positional+=("$1")
            shift
            ;;
    esac
done

if $BATCH_MODE; then
    if [ "${#positional[@]}" -ne 2 ]; then usage; fi
    PRIVATE_KEY="${positional[0]}"
    PUBLIC_KEY="${positional[1]}"
    if [ ! -d "$BATCH_DIR" ]; then
        echo -e "${RED}Error: Directory '$BATCH_DIR' not found or not a directory${NC}"
        exit 1
    fi
    for file in "$PRIVATE_KEY" "$PUBLIC_KEY"; do
        if [ ! -f "$file" ]; then
            echo -e "${RED}Error: Required file '$file' not found${NC}"
            echo -e "${MAGENTA}Suggestion: Verify that the file exists and the path is correct. It is most likely that the file is missing or the path is incorrect. Please verify for yourself.${NC}"
            exit 1
        fi
    done
else
    if [ "${#positional[@]}" -ne 4 ]; then usage; fi
    STUDENT_FILE="${positional[0]}"
    STUDENT_KEY="${positional[1]}"
    PRIVATE_KEY="${positional[2]}"
    PUBLIC_KEY="${positional[3]}"
    for file in "$STUDENT_FILE" "$STUDENT_KEY" "$PRIVATE_KEY" "$PUBLIC_KEY"; do
        if [ ! -f "$file" ]; then
            echo -e "${RED}Error: Required file '$file' not found${NC}"
            echo -e "${MAGENTA}Suggestion: Verify that the file exists and the path is correct. It is most likely that the file is missing or the path is incorrect. Please verify for yourself.${NC}"
            exit 1
        fi
    done
fi

# ---------------------------
# Helper: Print a separator line
print_separator() {
    echo -e "${BLUE}========================================${NC}"
}

# ---------------------------
# Function to process one submission
process_submission() {
    local student_file="$1"
    local student_key="$2"
    local filename
    filename=$(basename "$student_file")
    local stu_proj=${filename%-submission.aes}

    # Use BATCH_DIR if in batch mode, otherwise use current directory
    local output_dir
    if $BATCH_MODE; then
        output_dir="$BATCH_DIR"
    else
        output_dir="$(dirname "$student_file")"
    fi

    local symm_key="${output_dir}/${stu_proj}-symm_key.bin"
    local plain_code="${output_dir}/${stu_proj}.plaincode"

    print_separator
    echo -e "${BLUE}Processing submission for ${stu_proj}${NC}"

    # Validate required files
    for file in "$student_file" "$student_key" "$PRIVATE_KEY" "$PUBLIC_KEY"; do
        if [ ! -f "$file" ]; then
            echo -e "${RED}Error: Required file '$file' not found${NC}"
            echo -e "${MAGENTA}Suggestion: Verify that the file exists and the path is correct. It is most likely that the file is missing or the path is incorrect. Please verify for yourself.${NC}"
            return 1
        fi
    done

    # 1. Decrypt the AES Key (using OAEP padding)
    echo -e "${YELLOW}Decrypting the AES key...${NC}"
    # Read the student key as hex and check its length.
    student_key_hex=$(cat "$student_key")
    key_length=${#student_key_hex}
    if ! echo "$student_key_hex" | xxd -p -r | openssl pkeyutl -decrypt \
         -inkey "$PRIVATE_KEY" \
         -pkeyopt rsa_padding_mode:oaep \
         -pkeyopt rsa_oaep_md:sha256 \
         -out "$symm_key" ; then
         echo -e "${RED}Error: Failed to decrypt AES key for ${stu_proj}${NC}"
         if [ "$key_length" -lt 512 ]; then
             echo -e "${MAGENTA}Suggestion: It is likely a key that is too short (expected at least 512 hex characters, actual: ${key_length}). Please verify for yourself.${NC}"
         else
             echo -e "${MAGENTA}Suggestion: The student key file may be corrupted or mismatched with the instructor's private key. Please verify for yourself.${NC}"
         fi
         return 1
    fi

    # 2. Extract IV and Ciphertext from the student file
    echo -e "${YELLOW}Extracting IV and ciphertext...${NC}"
    local iv_hex
    iv_hex=$(cut -d: -f1 "$student_file")
    local cipher_hex
    cipher_hex=$(cut -d: -f2 "$student_file")
    if [ -z "$iv_hex" ] || [ -z "$cipher_hex" ]; then
        echo -e "${RED}Error: IV or ciphertext extraction failed for ${stu_proj}${NC}"
        if [ -z "$iv_hex" ]; then
            echo -e "${MAGENTA}Suggestion: It is likely that the IV is missing (expected 32 hex characters, actual: ${#iv_hex}). Please verify for yourself.${NC}"
        fi
        if [ -z "$cipher_hex" ]; then
            echo -e "${MAGENTA}Suggestion: It is likely that the ciphertext is missing. Please verify for yourself.${NC}"
        fi
        rm -f "$symm_key"
        return 1
    fi
    if [ ! -z "$iv_hex" ] && [ ${#iv_hex} -ne 32 ]; then
         echo -e "${MAGENTA}Suggestion: It is likely that the IV is malformed (expected 32 hex characters, actual: ${#iv_hex}). Please verify for yourself.${NC}"
    fi

    # 3. Decrypt the project code
    echo -e "${YELLOW}Decrypting the project...${NC}"
    if ! echo "$cipher_hex" | xxd -p -r | openssl enc -d -aes-256-cbc \
         -iv "$iv_hex" \
         -K "$(xxd -p -c 256 "$symm_key")" \
         -out "${plain_code}-temp" ; then
         echo -e "${RED}Error: Failed to decrypt project for ${stu_proj}${NC}"
         symm_key_hex=$(xxd -p -c 256 "$symm_key" 2>/dev/null)
         if [ -z "$symm_key_hex" ] || [ ${#symm_key_hex} -lt 64 ]; then
             echo -e "${MAGENTA}Suggestion: It is likely that the AES key is too short (expected 64 hex characters, actual: ${#symm_key_hex}). Please verify for yourself.${NC}"
         else
             echo -e "${MAGENTA}Suggestion: The IV or ciphertext may be corrupted or mismatched. Please verify for yourself.${NC}"
         fi
         rm -f "$symm_key"
         return 1
    fi
    if ! cp "${plain_code}-temp" "$plain_code" ; then
         echo -e "${RED}Error: Failed to save decrypted project for ${stu_proj}${NC}"
         echo -e "${MAGENTA}Suggestion: It is likely an issue with file write permissions or disk space. Please verify for yourself.${NC}"
         rm -f "$symm_key" "${plain_code}-temp"
         return 1
    fi
    [ "$KEEP_KEY" = false ] && rm -f "$symm_key"

    # Trim decrypted file before the delimiter
    plaincode_content=$(cat "$plain_code")
    if ! echo "$plaincode_content" | awk -v delim=$'\u2400' 'index($0, delim) { exit } { print }' > "$plain_code" ; then
         echo -e "${RED}Error: Failed to trim decrypted content for ${stu_proj}${NC}"
         echo -e "${MAGENTA}Suggestion: It is likely that the decrypted file is incomplete or contains unexpected formatting. Please verify for yourself.${NC}"
         rm -f "${plain_code}-temp"
         return 1
    fi
    echo -e "${GREEN}Decryption complete for ${stu_proj}!${NC}"
    echo -e "Decrypted code saved as: ${BLUE}${plain_code}${NC}"

    # 4. Validate decrypted content
    echo -e "${YELLOW}Validating decrypted content...${NC}"
    local delimiter=$'\u2400'
    local code_content
    code_content=$(awk -v delim="${delimiter}PUBKEY" 'index($0, delim) { exit } { print }' "${plain_code}-temp")
    if ! grep -q "${delimiter}PUBKEY" "${plain_code}-temp"; then
         echo -e "${RED}ERROR: Missing PUBKEY delimiter for ${stu_proj}${NC}"
         echo -e "${MAGENTA}Suggestion: It is most likely that the decrypted file is incomplete or tampered with. Please verify for yourself.${NC}"
         rm -f "${plain_code}-temp"
         return 1
    fi
    if ! grep -q "${delimiter}HASH" "${plain_code}-temp"; then
         echo -e "${RED}ERROR: Missing HASH delimiter for ${stu_proj}${NC}"
         echo -e "${MAGENTA}Suggestion: It is most likely that the decrypted file is missing critical sections. Please verify for yourself.${NC}"
         rm -f "${plain_code}-temp"
         return 1
    fi

    local embedded_key
    embedded_key=$(awk -v start_delim="${delimiter}PUBKEY" -v end_delim="${delimiter}HASH" '
         found && $0 ~ end_delim { exit }
         found { print }
         $0 ~ start_delim { found=1 }
    ' "${plain_code}-temp")
    local embedded_hash
    embedded_hash=$(awk -v delim="${delimiter}HASH" 'index($0, delim) { getline; printf "%s", $0; exit }' "${plain_code}-temp")
    rm -f "${plain_code}-temp"

    local generated_hash
    generated_hash=$(printf "%s" "$code_content" | sha512sum | cut -d' ' -f1)

    echo
    echo -e "${BLUE}Embedded public key:${NC}"
    echo -e "${BLUE}${embedded_key}${NC}"
    echo
    echo -e "${BLUE}Instructor public key:${NC}"
    echo -e "${BLUE}$(cat "$PUBLIC_KEY")${NC}"
    echo
    echo -e "${BLUE}Embedded hash: ${embedded_hash}${NC}"
    echo -e "${BLUE}Generated hash: ${generated_hash}${NC}"
    echo

    if [ "$generated_hash" = "$embedded_hash" ]; then
         echo -e "${GREEN}Hash validation successful for ${stu_proj}: Code integrity verified ✓${NC}"
         return 0
    else
         echo -e "${RED}Error: Code integrity check failed for ${stu_proj} - hash mismatch ✗${NC}"
         echo -e "${MAGENTA}Possible causes:${NC}"
         local instructor_key
         instructor_key=$(cat "$PUBLIC_KEY")
         if [ "$embedded_key" != "$instructor_key" ]; then
             echo -e "${MAGENTA}- The embedded public key does not match the instructor's public key. Please verify for yourself.${NC}"
         fi
         if [ ${#embedded_key} -lt 100 ]; then
             echo -e "${MAGENTA}- The embedded public key appears too short (expected at least 100 characters, actual: ${#embedded_key}). Please verify for yourself.${NC}"
         fi
         if [ ${#embedded_hash} -ne 128 ]; then
             echo -e "${MAGENTA}- The embedded hash length is not valid (expected 128 hex characters, actual: ${#embedded_hash}). Please verify for yourself.${NC}"
         fi
         echo -e "${MAGENTA}- The generated hash does not match the embedded hash. This may indicate tampering with the AES submission file or data corruption. Please verify for yourself.${NC}"
         return 1
    fi
}

# ---------------------------
# Main execution
# ---------------------------
print_separator
echo -e "${BLUE}Starting decryption process...${NC}"

if $BATCH_MODE; then
    echo -e "${BLUE}Batch mode activated. Processing submissions in: ${BATCH_DIR}${NC}"
    declare -a success_list
    declare -a failure_list

    shopt -s nullglob
    for aes_file in "$BATCH_DIR"/*-submission.aes; do
        [ -f "$aes_file" ] || continue
        key_file="${aes_file%.aes}.key"
        if [ ! -f "$key_file" ]; then
            echo -e "${RED}Error: Matching key file for $(basename "$aes_file") not found${NC}"
            echo -e "${MAGENTA}Suggestion: Verify that the key file exists in the same directory as the submission file. Please verify for yourself.${NC}"
            failure_list+=("$(basename "$aes_file" .aes)")
            continue
        fi
        if process_submission "$aes_file" "$key_file"; then
            success_list+=("$(basename "$aes_file" .aes)")
        else
            failure_list+=("$(basename "$aes_file" .aes)")
        fi
    done

    print_separator
    printf "\n"
    echo -e "Summary results:"
    for proj in "${success_list[@]}"; do
         echo -e "${GREEN}${proj} ✓${NC}"
    done
    for proj in "${failure_list[@]}"; do
         echo -e "${RED}${proj} ✗${NC}"
    done
    printf "\n"
    [ "${#failure_list[@]}" -gt 0 ] && exit 1 || exit 0
else
    if process_submission "$STUDENT_FILE" "$STUDENT_KEY"; then
         echo -e "${GREEN}Processing complete.${NC}"
         printf "\n"
         exit 0
    else
         exit 1
    fi
fi
