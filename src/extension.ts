/// extension.ts

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import * as keytar from 'keytar';
import * as fs from 'fs';
import * as path from 'path';
import { TextDecoder, TextEncoder } from 'util'; // Add if not already present

const SERVICE_NAME = 'IntegriCodeExtension';
const SYMMETRIC_KEY = 'symmetricKey';

// TODO: Actually disable copy paste. Remove public key and hash from code when opened. Set file type when opened. 
// Override saving. Fix Integricode: Integricode: Open Encrypted Project. Can the white dot go away?

// Add a Map to store public key and hash for each encrypted project
const encryptedProjectData = new Map<string, { publicKey: string; hash: string }>();

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
            
                // Step 11: Append instructor's public key and SHA-512 hash to the plaintext code
                const hash = crypto.createHash('sha512').update(codeString, 'utf8').digest('hex');
                const appendedContent = `${codeString}\n---INSTRUCTOR_PUBLIC_KEY---\n${instructorPublicKey}\n---HASH---\n${hash}`;
                
            
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
                    defaultUri: vscode.Uri.file(`${codeFilePath}.encrypted.enc`),
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
        const projectName = await vscode.window.showInputBox({
            prompt: 'Enter Project Name',
            placeHolder: 'MyIntegriCodeProject'
        });

        if (projectName) {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (workspaceFolders && workspaceFolders.length > 0) {
                const projectPath = `${workspaceFolders[0].uri.fsPath}/${projectName}`;
                // Logic to create project directory and necessary files
                vscode.window.showInformationMessage(`IntegriCode Project created at: ${projectPath}`);
            } else {
                vscode.window.showErrorMessage('No workspace folder is open.');
            }
        }
    });

    // Modify the openEncryptedProjectCommand to use the getWebviewContent function
const openEncryptedProjectCommand = vscode.commands.registerCommand('integriCode.openEncryptedProject', async () => {
    try {
        // Step 1: Select the encrypted file
        const encryptedFileUri = await vscode.window.showOpenDialog({
            canSelectMany: false,
            openLabel: 'Select Encrypted Project File',
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

        // Step 2: Create a Webview Panel
        const panel = vscode.window.createWebviewPanel(
            'integriCodeEncryptedProject', // Identifies the type of the webview. Used internally
            'IntegriCode Encrypted Project', // Title of the panel displayed to the user
            vscode.ViewColumn.One, // Editor column to show the new webview panel in
            {
                enableScripts: true // Enable scripts in the webview
            }
        );

        // Step 3: Determine the current theme
        const theme = vscode.window.activeColorTheme.kind === vscode.ColorThemeKind.Dark ? 'vs-dark' : 'light';

        // Step 4: Set the HTML content using the getWebviewContent function
        panel.webview.html = getWebviewContent(theme);

        console.log('Webview panel created.');
    } catch (error) {
        console.error(`Error opening encrypted project: ${error}`);
        vscode.window.showErrorMessage(`An error occurred: ${error instanceof Error ? error.message : String(error)}`);
    }
});

    // Register the No-Op command to override clipboard actions
    const noopCommand = vscode.commands.registerCommand('integriCode.noop', () => {
        vscode.window.showInformationMessage('Copy/Paste actions are disabled for encrypted projects.');
    });
    context.subscriptions.push(noopCommand);

    // **Add the Save Encrypted Project command**
    const saveEncryptedProjectCommand = vscode.commands.registerCommand('integriCode.saveEncryptedProject', async (text: string) => {
        if (!currentEncryptedFilePath) {
            vscode.window.showErrorMessage('No encrypted project is currently open.');
            return;
        }

        try {
            // Step 1: Retrieve project data
            const projectData = encryptedProjectData.get(currentEncryptedFilePath);
            if (!projectData) {
                vscode.window.showErrorMessage('Project data not found.');
                return;
            }

            const { publicKey: instructorPublicKey } = projectData;

            // Step 2: Generate SHA-512 hash of the code
            const hash = generateHash(text);

            // Step 3: Append instructor's public key and hash to the plaintext code
            const appendedContent = `${text}\n---INSTRUCTOR_PUBLIC_KEY---\n${instructorPublicKey}\n---HASH---\n${hash}`;

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
            await vscode.workspace.fs.writeFile(vscode.Uri.file(currentEncryptedFilePath), combinedEncryptedData);

            vscode.window.showInformationMessage(`Encrypted project saved successfully at: ${currentEncryptedFilePath}`);
        } catch (error) {
            console.error(`Error saving encrypted project: ${error}`);
            vscode.window.showErrorMessage(`An error occurred while saving: ${error instanceof Error ? error.message : String(error)}`);
        }
    });
    context.subscriptions.push(saveEncryptedProjectCommand);

    // Add the commands to the extension's subscriptions
    context.subscriptions.push(openNewProjectFileCommand, createProjectCommand, openEncryptedProjectCommand);
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
 * 
 * @param content The content to hash.
 * @returns The hexadecimal representation of the hash.
 */
function generateHash(content: string): string {
    return crypto.createHash('sha512').update(content, 'utf8').digest('hex');
}

// Function to generate the webview content
function getWebviewContent(theme: string): string {
    const isDark = theme === 'vs-dark';
    const backgroundColor = isDark ? '#1E1E1E' : '#FFFFFF';
    const textColor = isDark ? '#D4D4D4' : '#000000';
    const fontFamily = `'Segoe UI', 'Consolas', 'Courier New', monospace`;

    // Optional: Include Highlight.js for syntax highlighting
    const highlightJsLink = isDark
        ? 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/vs2015.min.css'
        : 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/github.min.css';
    const highlightJsScript = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/highlight.min.js';

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IntegriCode Encrypted Project</title>
    <link rel="stylesheet" href="${highlightJsLink}">
    <style>
        body, html {
            height: 100%;
            margin: 0;
            display: flex;
            flex-direction: column;
            background-color: ${backgroundColor};
            color: ${textColor};
            font-family: ${fontFamily};
        }
        textarea {
            flex: 1;
            width: 100%;
            resize: none;
            font-family: inherit;
            font-size: 14px;
            background-color: ${backgroundColor};
            color: ${textColor};
            border: none;
            padding: 10px;
            box-sizing: border-box;
        }
        
    </style>
</head>
<body>
    <textarea id="editor">Hello World</textarea>
    <script src="${highlightJsScript}"></script>
    <script>
        const vscode = acquireVsCodeApi();

        // Initialize Highlight.js (optional)
        hljs.highlightAll();

        // Disable copy, cut, paste, and context menu
        ['copy', 'cut', 'paste', 'contextmenu'].forEach(event => {
            document.addEventListener(event, (e) => {
                e.preventDefault();
                vscode.postMessage({ command: 'noop' });
            });
        });
    </script>
</body>
</html>`;
}
