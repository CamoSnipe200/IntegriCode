# integricode README

## Instructor Scripts Guide

### Step 1: Generate Keys (generateKeys.sh)

Generates RSA key pairs for encryption/decryption. Creates both private and public keys in PEM format.

#### Usage
```bash
./generateKeys.sh <name>
./generateKeys.sh clean
```
The name could be your professor name, the class name, or anything else you'd like to identify this key by. It will be in the filename of the public key you give to students. 

### Step 2: Prepare Source Code For Students (prepSourceCodeForStudents.sh)

Prepares source code files for student distribution by generating cryptographic signatures and hashes. **TODO: Provide instructions for how to do this when you don't have any code to give to students**

#### Usage
```bash
./prepSourceCodeForStudents.sh <code_source_file> <private_key> <public_key>
./prepSourceCodeForStudents.sh clean
```

(This is the point where the students would do their steps. See the guide for students below...)

### Step 3: Validate and Decrypt Student Code for Submission (validateAndDecryptStudentSubmission.sh)

#### Usage
```bash
./validateAndDecryptStudentSubmission.sh <student_encrypted_project_file> <student_key_file> <instructor_private_key> <instructor_public_key> [--keep-key]"
```
`--keep-key` keeps the temporary symmetric key decrypted from the `<student_key_file>` when included (not usually necessary).

## Student usage guide

### Step 1: IntegriCode: Open New Project File
It will take the instructor
- Plaintext source code
- Signature (.sig)
- Public key (.pem)
- Hash of the source code (.sha512)

And save the project as a .enc IntegriCode project file.

### Step 2: IntegriCode: Open Encrypted Project
It will as for the .enc file to open so that the student can edit
Press the `Save Encrypted Project` button to save your changes with IntegriCode's encryption features. The project must only ever be saved this way, or it will not be vaible to open again or submit to the instructor.

### Step 3: IntegriCode: Encrypt and Submit
Will prompt the student for their:
- Username
- Project name
- .enc IntegriCode Project

And save a 
- `-submission.aes` encrypted project file
- `-submission.key` used to encrypt the project file

### Step 4: Send the files to your instructor
It's as simple as that. They can decrypt it and grade your code.