/// extension.ts

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import * as keytar from 'keytar';
import * as fs from 'fs';
import * as path from 'path';
import { TextDecoder, TextEncoder } from 'util';

const SERVICE_NAME = 'IntegriCodeExtension';
const SYMMETRIC_KEY = 'symmetricKey';
let lastUsedDirectory: vscode.Uri | undefined;

// Add a variable to store the current encrypted file path
let currentEncryptedFilePath: string | null = null;

export async function activate(context: vscode.ExtensionContext) {
    console.log('Extension "IntegriCode" is now active!');

    // Ensure symmetric key exists
    await ensureSymmetricKey();

    // Register the "IntegriCode: Open New Project" command
    const openNewProjectFileCommand = vscode.commands.registerCommand('integriCode.openNewProjectFile', async () => {
        try {
            // Step 1: Inform the user to select the code file
            const codeFileInfo = await vscode.window.showInformationMessage(
                'Select the input code file your instructor provided. Click "OK" to proceed.',
                { modal: true },
                'OK'
            );

            if (codeFileInfo !== 'OK') {
                vscode.window.showErrorMessage('Operation cancelled by the user.');
                return;
            }

            // Step 2: Select the code file
            const codeFileUri = await vscode.window.showOpenDialog({
                canSelectMany: false,
                openLabel: 'Select Code File',
                filters: {
                    'Code Files': ['c', 'cpp', 'java', 'js', 'ts', 'py', 'txt'],
                    'All Files': ['*']
                }
            });

            if (!codeFileUri || codeFileUri.length === 0) {
                vscode.window.showErrorMessage('No code file selected.');
                return;
            }

            const codeFilePath = codeFileUri[0].fsPath;

            // Step 3: Inform the user to select the signature file
            const signatureFileInfo = await vscode.window.showInformationMessage(
                'Select the signature file corresponding to the code file. Click "OK" to proceed.',
                { modal: true },
                'OK'
            );

            if (signatureFileInfo !== 'OK') {
                vscode.window.showErrorMessage('Operation cancelled by the user.');
                return;
            }

            // Step 4: Select the signature file
            const signatureFileUri = await vscode.window.showOpenDialog({
                canSelectMany: false,
                openLabel: 'Select Signature File',
                filters: {
                    'Signature Files': ['sig', 'signature'],
                    'All Files': ['*']
                }
            });

            if (!signatureFileUri || signatureFileUri.length === 0) {
                vscode.window.showErrorMessage('No signature file selected.');
                return;
            }

            const signatureFilePath = signatureFileUri[0].fsPath;

            // Step 5: Inform the user to select the public key file
            const publicKeyInfo = await vscode.window.showInformationMessage(
                'Select the public key file provided by your instructor. Click "OK" to proceed.',
                { modal: true },
                'OK'
            );

            if (publicKeyInfo !== 'OK') {
                vscode.window.showErrorMessage('Operation cancelled by the user.');
                return;
            }

            // Step 6: Select the public key file
            const publicKeyUri = await vscode.window.showOpenDialog({
                canSelectMany: false,
                openLabel: 'Select Public Key File',
                filters: {
                    'Key Files': ['pem', 'key'],
                    'All Files': ['*']
                }
            });

            if (!publicKeyUri || publicKeyUri.length === 0) {
                vscode.window.showErrorMessage('No public key file selected.');
                return;
            }

            const publicKeyPath = publicKeyUri[0].fsPath;

            // Step 7: Read the code file
            const codeContent = await vscode.workspace.fs.readFile(vscode.Uri.file(codeFilePath));
            const codeString = Buffer.from(codeContent).toString('utf8');

            // Step 8: Read the signature file as binary
            const signatureContent = await vscode.workspace.fs.readFile(vscode.Uri.file(signatureFilePath));
            const signature = signatureContent; // Keep it as a Buffer without conversion

            // Step 9: Read the instructor's public key
            const instructorPublicKey = fs.readFileSync(publicKeyPath, 'utf8');

            // Step 10: Verify the signature using SHA-512 and RSA-PSS
            const isValid = crypto.verify(
                'sha512',
                Buffer.from(codeString, 'utf8'),
                {
                    key: instructorPublicKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
                },
                signature // Pass the signature directly as binary data
            );

            if (isValid) {
                vscode.window.showInformationMessage('Signature verification successful. The file is authentic.');
            
                // Modify the appended content creation to use unambiguous delimiters
                const DELIMITER = '\u2400'; // Unicode NON-BREAKING HYPHEN (␀) - rarely used in code

                // Step 11: Append instructor's public key and SHA-512 hash to the plaintext code
                const hash = crypto.createHash('sha512').update(codeString, 'utf8').digest('hex');
                const appendedContent = [
                    codeString,
                    DELIMITER + 'PUBKEY',
                    instructorPublicKey,
                    DELIMITER + 'HASH',
                    hash
                  ].join('\n');
                
            
                // Step 12: Retrieve the symmetric key from secure storage
                const symmetricKey = await getSymmetricKey();
            
                // Step 13: Encrypt the appended content with the symmetric key using AES-256-GCM
                const iv = crypto.randomBytes(12); // 96-bit IV for GCM
                const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
                let encryptedData = cipher.update(appendedContent, 'utf8');
                encryptedData = Buffer.concat([encryptedData, cipher.final()]);
                const authTag = cipher.getAuthTag(); // Authentication tag for GCM
            
                // Combine IV, authTag, and encrypted data
                const combinedEncryptedData = Buffer.concat([iv, authTag, encryptedData]);
            
                // Step 14: Ask the user where to save the encrypted file
                const saveFileUri = await vscode.window.showSaveDialog({
                    saveLabel: 'Save Encrypted File',
                    defaultUri: vscode.Uri.file(`${codeFilePath}.enc`),
                    filters: {
                        'Encrypted Files': ['enc'],
                        'All Files': ['*']
                    }
                });
            
                if (!saveFileUri) {
                    vscode.window.showErrorMessage('No save location selected.');
                    return;
                }
            
                // Step 15: Write the encrypted content to the chosen path
                await vscode.workspace.fs.writeFile(saveFileUri, combinedEncryptedData);
            
                vscode.window.showInformationMessage(`Encrypted file saved to: ${saveFileUri.fsPath}`);
            } else {
                vscode.window.showErrorMessage('Signature verification failed. The file may have been tampered with.');
                // Optionally, close the active editor
                await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            }

        } catch (error) {
            console.error(`Error during signature verification: ${error}`);
            vscode.window.showErrorMessage(`An error occurred: ${error instanceof Error ? error.message : String(error)}`);
        }
    });

    // Register the "IntegriCode: Create Project" command
    const createProjectCommand = vscode.commands.registerCommand('integriCode.createProject', async () => {
        try {
            // Step 1: Inform the user to select the public key file
            const publicKeyInfo = await vscode.window.showInformationMessage(
                'Select the public key file provided by your instructor. Click "OK" to proceed.',
                { modal: true },
                'OK'
            );

            if (publicKeyInfo !== 'OK') {
                vscode.window.showErrorMessage('Operation cancelled by the user.');
                return;
            }

            // Step 2: Select the public key file
            const publicKeyUri = await vscode.window.showOpenDialog({
                canSelectMany: false,
                openLabel: 'Select Public Key File',
                filters: {
                    'Key Files': ['pem', 'key'],
                    'All Files': ['*']
                }
            });

            if (!publicKeyUri || publicKeyUri.length === 0) {
                vscode.window.showErrorMessage('No public key file selected.');
                return;
            }

            const publicKeyPath = publicKeyUri[0].fsPath;

            // Step 3: Read the instructor's public key
            const instructorPublicKey = fs.readFileSync(publicKeyPath, 'utf8');

            // Step 4: Create content with a space
            const content = ' '; // Single space as placeholder

            // Step 5: Generate SHA-512 hash
            const hash = generateHash(content);

            // Modify the appended content creation to use unambiguous delimiters
            const DELIMITER = '\u2400'; // Unicode NON-BREAKING HYPHEN (␀) - rarely used in code

            // Step 6: Append instructor's public key and hash
            const appendedContent = [
                content,
                DELIMITER + 'PUBKEY',
                instructorPublicKey,
                DELIMITER + 'HASH',
                hash
              ].join('\n');

            // Step 7: Retrieve the symmetric key from secure storage
            const symmetricKey = await getSymmetricKey();

            // Step 8: Encrypt the appended content with the symmetric key using AES-256-GCM
            const iv = crypto.randomBytes(12); // 96-bit IV for GCM
            const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
            let encryptedData = cipher.update(appendedContent, 'utf8');
            encryptedData = Buffer.concat([encryptedData, cipher.final()]);
            const authTag = cipher.getAuthTag();

            // Step 9: Combine IV, authTag, and encrypted data
            const combinedEncryptedData = Buffer.concat([iv, authTag, encryptedData]);

            // Step 10: Ask the user where to save the encrypted file
            const saveFileUri = await vscode.window.showSaveDialog({
                saveLabel: 'Save Encrypted Project File',
                defaultUri: vscode.Uri.file('newProject.enc'),
                filters: {
                    'Encrypted Files': ['enc'],
                    'All Files': ['*']
                }
            });

            if (!saveFileUri) {
                vscode.window.showErrorMessage('No save location selected.');
                return;
            }

            // Step 11: Write the encrypted content to the chosen path
            await vscode.workspace.fs.writeFile(saveFileUri, combinedEncryptedData);

            vscode.window.showInformationMessage(`Encrypted project file saved to: ${saveFileUri.fsPath}`);
        } catch (error) {
            console.error(`Error during project creation: ${error}`);
            vscode.window.showErrorMessage(`An error occurred: ${error instanceof Error ? error.message : String(error)}`);
        }
    });

    // Modify the openEncryptedProjectCommand to use the getWebviewContent function
const openEncryptedProjectCommand = vscode.commands.registerCommand('integriCode.openEncryptedProject', async () => {
    try {
        // Step 1: Select the encrypted file
        const encryptedFileUri = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select Encrypted Project File',
            defaultUri: lastUsedDirectory,
            filters: {
                'Encrypted Files': ['enc'],
                'All Files': ['*']
            }
        });

        if (!encryptedFileUri || encryptedFileUri.length === 0) {
            vscode.window.showErrorMessage('No encrypted file selected.');
            return;
        }

        lastUsedDirectory = vscode.Uri.file(encryptedFileUri[0].fsPath.substring(0, encryptedFileUri[0].fsPath.lastIndexOf(path.sep)));

        const encryptedFilePath = encryptedFileUri[0].fsPath;
        currentEncryptedFilePath = encryptedFilePath; // Store the encrypted file path

        console.log('Encrypted File Path:', currentEncryptedFilePath);

        // Step 2: Read the encrypted file
        const encryptedContent = await vscode.workspace.fs.readFile(vscode.Uri.file(encryptedFilePath));

        // Step 3: Decrypt the content
        const decryptedContent = await decryptContent(encryptedContent)
        
        // Define delimiter
        const DELIMITER = '\u2400'; // Unicode NON-BREAKING HYPHEN (␀)
        
        console.log('Decrypted content length:', decryptedContent.length);
        
        // Extract sections using new delimiter format
        if (!decryptedContent.includes(DELIMITER + 'PUBKEY') || !decryptedContent.includes(DELIMITER + 'HASH')) {
            vscode.window.showErrorMessage('Invalid file format: Missing required delimiters');
            return;
        }
        
        const parts = decryptedContent.split(DELIMITER);
        console.log('Found', parts.length - 1, 'delimited sections');
        
        // Extract code (everything before first delimiter)
        const code = parts[0].trim();
        console.log('Code length:', code.length);
        
        // Extract public key (between PUBKEY and HASH)
        const publicKey = decryptedContent
            .split(DELIMITER + 'PUBKEY')[1]
            .split(DELIMITER + 'HASH')[0]
            .trim();
        console.log('Public key length:', publicKey.length);
        
        // Debug statement
        console.log('Successfully parsed encrypted content');

        const panel = vscode.window.createWebviewPanel(
            'integriCodeEncryptedProject', // Identifies the type of the webview. Used internally
            'IntegriCode Encrypted Project', // Title of the panel displayed to the user
            vscode.ViewColumn.One, // Editor column to show the new webview panel in
            {
                enableScripts: true // Enable scripts in the webview
            }
        );

        // Step 4: Determine the current theme
        const theme = vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.Dark ? 'vs-dark' : 'light';

        // Step 5: Set the HTML content
        panel.webview.html = getWebviewContent(theme, code);


        // Step 6: Add message listener for the webview
        panel.webview.onDidReceiveMessage(async message => {
            switch (message.command) {
                case 'SaveEncryptedProject':
                    await SaveEncryptedProject(message.code, encryptedFilePath, publicKey);
                    break;
                case 'noop':
                    vscode.window.showInformationMessage('Copy/Paste actions are disabled for encrypted projects.');
                    break;
                default:
                    console.warn(`Unknown command: ${message.command}`);
            }
        }, undefined, context.subscriptions);

        console.log('Webview panel created.');

    } catch (error) {
        console.error(`Error opening encrypted project: ${error}`);
        vscode.window.showErrorMessage(`An error occurred: ${error instanceof Error ? error.message : String(error)}`);
    }
});

    // Register the "IntegriCode: Encrypt and Submit File" command
    const encryptAndSubmitCommand = vscode.commands.registerCommand('integriCode.encryptAndSubmit', async () => {
        // Get student username
        const studentUsername = await vscode.window.showInputBox({
            prompt: 'Enter your student username',
            placeHolder: 'username',
            validateInput: text => {
                return text && text.trim().length > 0 ? null : 'Username is required';
            }
        });

        if (!studentUsername) {
            vscode.window.showErrorMessage('Student username is required.');
            return;
        }

        // Get project name
        const projectName = await vscode.window.showInputBox({
            prompt: 'Enter the project name',
            placeHolder: 'project1',
            validateInput: text => {
                return text && text.trim().length > 0 ? null : 'Project name is required';
            }
        });

        if (!projectName) {
            vscode.window.showErrorMessage('Project name is required.');
            return;
        }

        // Step 1: Select the encrypted file
        const encryptedFileUri = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select Project to Encrypt and Submit',
            filters: {
                'Encrypted Files': ['enc'],
                'All Files': ['*']
            }
        });
    
        if (!encryptedFileUri || encryptedFileUri.length === 0) {
            vscode.window.showErrorMessage('No encrypted file selected.');
            return;
        }
    
        const encryptedFilePath = encryptedFileUri[0].fsPath;
        currentEncryptedFilePath = encryptedFilePath; // Store the encrypted file path
    
        console.log('Encrypted File Path:', currentEncryptedFilePath);
    
        // Step 2: Read the encrypted file
        const encryptedContent = await vscode.workspace.fs.readFile(vscode.Uri.file(encryptedFilePath));
    
        // Step 3: Decrypt the content
        const decryptedContent = await decryptContent(encryptedContent);
        console.log('Decrypted content length:', decryptedContent.length);

        // Define delimiter
        const DELIMITER = '\u2400'; // Unicode NON-BREAKING HYPHEN (␀)
        console.log('Looking for sections using delimiter:', DELIMITER);

        // Validate format
        if (!decryptedContent.includes(DELIMITER + 'PUBKEY') || 
            !decryptedContent.includes(DELIMITER + 'HASH')) {
            console.error('Missing required delimiters in decrypted content');
            vscode.window.showErrorMessage('Invalid encrypted file format: Missing delimiters');
            return;
        }

        // Extract sections
        const sections = decryptedContent.split(DELIMITER);
        console.log('Found', sections.length - 1, 'delimited sections');

        // Parse content
        const code = sections[0].trim();
        const publicKey = sections.find(s => s.startsWith('PUBKEY'))?.substring(6).trim();
        const hash = sections.find(s => s.startsWith('HASH'))?.substring(4).trim();

        if (!code || !publicKey || !hash) {
            console.error('Failed to extract required sections');
            vscode.window.showErrorMessage('Invalid file structure: Missing required content');
            return;
        }

        console.log('Successfully extracted:',
            '\nCode length:', code.length,
            '\nPublic key length:', publicKey.length,
            '\nHash length:', hash.length
        );

        try {
            // Step 4: Generate a symmetric key
            const symmetricKey = crypto.randomBytes(32); // AES-256 key
    
            // Step 5: Encrypt the decrypted content using the symmetric key
            const iv = crypto.randomBytes(16); // Initialization vector
            const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, iv);
            let encryptedData = cipher.update(decryptedContent, 'utf8', 'hex');
            encryptedData += cipher.final('hex');
    
            // Step 6: Encrypt the symmetric key with the public key
            const encryptedSymmetricKey = crypto.publicEncrypt(
                {
                    key: publicKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256',
                },
                symmetricKey
            ).toString('hex');
    
        // Step 7: Save the encrypted content and encrypted symmetric key
        const basePath = path.dirname(encryptedFilePath);
        const submissionPrefix = path.join(basePath, `${studentUsername}-${projectName}`);

        const encryptedContentToSave = `${iv.toString('hex')}:${encryptedData}`;
        await vscode.workspace.fs.writeFile(
            vscode.Uri.file(`${submissionPrefix}-submission.aes`), 
            Buffer.from(encryptedContentToSave, 'utf8')
        );
        await vscode.workspace.fs.writeFile(
            vscode.Uri.file(`${submissionPrefix}-submission.key`), 
            Buffer.from(encryptedSymmetricKey, 'utf8')
        );

        vscode.window.showInformationMessage(`Files encrypted and saved with prefix: ${studentUsername}-${projectName}`);
        } catch (error) {
            vscode.window.showErrorMessage('Encryption failed.');
            console.error(error);
        }
    });
    
    context.subscriptions.push(encryptAndSubmitCommand);
}

export function deactivate() {
    console.log('Extension "code-integrity" is now deactivated.');
}

// Function to ensure the symmetric key exists
async function ensureSymmetricKey() {
    let symmetricKey = await keytar.getPassword(SERVICE_NAME, SYMMETRIC_KEY);
    if (!symmetricKey) {
        // Generate a 256-bit (32 bytes) random key
        const keyBuffer = crypto.randomBytes(32);
        symmetricKey = keyBuffer.toString('base64');
        await keytar.setPassword(SERVICE_NAME, SYMMETRIC_KEY, symmetricKey);
        console.log('Symmetric key generated and stored securely.');
    } else {
        console.log('Symmetric key already exists.');
    }
    return symmetricKey;
}

// Function to retrieve the symmetric key
async function getSymmetricKey(): Promise<Buffer> {
    const symmetricKey = await keytar.getPassword(SERVICE_NAME, SYMMETRIC_KEY);
    if (!symmetricKey) {
        throw new Error('Symmetric key not found.');
    }
    return Buffer.from(symmetricKey, 'base64');
}

async function decryptContent(encryptedData: Uint8Array): Promise<string> {
    const symmetricKey = await getSymmetricKey();
    const iv = encryptedData.slice(0, 12); // 96-bit IV for GCM
    const authTag = encryptedData.slice(12, 28); // 128-bit auth tag
    const ciphertext = encryptedData.slice(28);

    const decipher = crypto.createDecipheriv('aes-256-gcm', symmetricKey, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

async function encryptContent(plainText: string): Promise<Uint8Array> {
    const symmetricKey = await getSymmetricKey();
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
    let encrypted = cipher.update(plainText, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Combine IV, authTag, and encrypted data
    return Buffer.concat([iv, authTag, encrypted]);
}

/**
 * Generates a SHA-512 hash of the given content.
 * Also, SHA-512 is just cool B-)
 * 
 * @param content The content to hash.
 * @returns The hexadecimal representation of the hash.
 */
function generateHash(content: string): string {
    return crypto.createHash('sha512').update(content, 'utf8').digest('hex');
}

function getWebviewContent(theme: string, code: string): string {
    const isDark = theme === 'vs-dark';
    const backgroundColor = isDark ? '#1E1E1E' : '#FFFFFF';
    const textColor = isDark ? '#D4D4D4' : '#000000';
    const fontFamily = `'Segoe UI', 'Consolas', 'Courier New', monospace`;
    // Use lucario regardless of the VS Code theme
    const editorTheme = 'dracula';

    // Escape all backslashes and backticks so that every \ (including \n, \t, etc.) is shown literally.
    const safeCode = code.replace(/\\/g, '\\\\').replace(/`/g, '\\`');

    return `<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <title>IntegriCode Encrypted Project</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/theme/dracula.min.css">
    <style>
        html, body {
            height: 100%;
            margin: 0;
            background-color: ${backgroundColor};
        }
        #editor {
            height: calc(100% - 40px);
        }
        .CodeMirror {
            height: 100%;
            font-family: ${fontFamily};
            font-size: 14px;
            color: ${textColor};
        }
        #saveEncryptedProject {
            width: 100%;
            height: 40px;
            font-size: 16px;
            background-color: ${isDark ? '#3C3C3C' : '#F3F3F3'};
            color: ${textColor};
            border: none;
            cursor: pointer;
        }
        #saveEncryptedProject:hover {
            background-color: ${isDark ? '#505050' : '#E1E1E1'};
        }
    </style>
</head>
<body>
    <div id="editor"></div>
    <button id="saveEncryptedProject">Save Encrypted Project</button>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/codemirror.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/mode/javascript/javascript.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.2/addon/edit/closebrackets.min.js"></script>
    <script>
        const vscode = acquireVsCodeApi();
        const editor = CodeMirror(document.getElementById('editor'), {
            value: \`${safeCode}\`,
            mode: 'javascript', // Adjust according to your language
            theme: '${editorTheme}',
            lineNumbers: true,
            autoCloseBrackets: true,
            tabSize: 4,
            indentUnit: 4,
            indentWithTabs: true
        });
        
        // Disable copy, cut, contextmenu events
        ['copy', 'cut', 'contextmenu'].forEach(eventType => {
            document.addEventListener(eventType, function(e) {
                e.preventDefault();
                vscode.postMessage({ command: 'noop' });
            });
        });
        
        // Disable paste by capturing before CodeMirror processes it.
        editor.getWrapperElement().addEventListener('paste', function(e) {
            e.preventDefault();
            vscode.postMessage({ command: 'noop' });
        }, true);

        document.getElementById('saveEncryptedProject').addEventListener('click', () => {
            const plaintextCode = editor.getValue();
            vscode.postMessage({ command: 'SaveEncryptedProject', code: plaintextCode, filePath: '${currentEncryptedFilePath}' });
        });
    </script>
</body>
</html>`;
}

async function SaveEncryptedProject(code: string, filePath: string, publicKey: string) {
    // This function handles saving the encrypted project using the provided code, publicKey, and filePath

    // Validate that the publicKey parameter is provided
    if (!publicKey) {
        console.error('Public key is undefined. Cannot save encrypted project.');
        vscode.window.showErrorMessage('Public key is missing. Cannot save encrypted project.');
        return;
    }

    console.log('Saving Encrypted Project:', { code, filePath, publicKey });

    try {
        // Step 2: Generate SHA-512 hash of the code
        const hash = generateHash(code);

        // Modify the appended content creation to use unambiguous delimiters
        const DELIMITER = '\u2400'; // Unicode NON-BREAKING HYPHEN (␀) - rarely used in code

        // Step 3: Append instructor's public key and hash
        const appendedContent = [
            code,
            DELIMITER + 'PUBKEY',
            publicKey,
            DELIMITER + 'HASH',
            hash
          ].join('\n');

        // Step 4: Retrieve the symmetric key from secure storage
        const symmetricKey = await getSymmetricKey();

        // Step 5: Encrypt the appended content with the symmetric key using AES-256-GCM
        const iv = crypto.randomBytes(12); // 96-bit IV for GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', symmetricKey, iv);
        let encryptedData = cipher.update(appendedContent, 'utf8');
        encryptedData = Buffer.concat([encryptedData, cipher.final()]);
        const authTag = cipher.getAuthTag(); // Authentication tag for GCM

        // Step 6: Combine IV, authTag, and encrypted data
        const combinedEncryptedData = Buffer.concat([iv, authTag, encryptedData]);

        // Step 7: Overwrite the encrypted file with the new encrypted data
        await vscode.workspace.fs.writeFile(vscode.Uri.file(filePath), combinedEncryptedData);

        // ---------------- New Code for Saving Plain Code Version ----------------
        // Determine plain file path by removing the '.enc' suffix if it exists
        const plainFilePath = filePath.endsWith('.enc') ? filePath.slice(0, -4) : filePath;

        // Big disclaimer comment to add at the top and bottom
        const disclaimer =
            `/*********************************************************\n` +
            `CHANGES TO THIS FILE WILL NOT BE SAVED. MAKE YOUR\n` +
            `UPDATES WITH THE INTEGRICODE OPEN ENCRYPTED PROJECT FUNCTION\n` +
            `**********************************************************/\n\n`;

        // Compose the plain code file content with the disclaimer
        const plainCodeContent = disclaimer + code + "\n\n" + disclaimer;

        // Save the plain code file
        await vscode.workspace.fs.writeFile(vscode.Uri.file(plainFilePath), Buffer.from(plainCodeContent, 'utf8'));
        // -------------------------------------------------------------------------

        vscode.window.showInformationMessage(`Encrypted project saved successfully at: ${filePath}`);
    } catch (error) {
        console.error(`Error saving encrypted project: ${error}`);
        vscode.window.showErrorMessage(`An error occurred while saving: ${error instanceof Error ? error.message : String(error)}`);
    }
}
