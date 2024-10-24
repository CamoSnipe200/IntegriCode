/// extension.ts

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import * as keytar from 'keytar';
import * as fs from 'fs'; // Ensure fs is imported

const SERVICE_NAME = 'IntegriCodeExtension';
const SYMMETRIC_KEY = 'symmetricKey';

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

    // Register the "IntegriCode: Open Encrypted Project" command
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

            // Step 2: Read the encrypted file
            const encryptedContent = await vscode.workspace.fs.readFile(vscode.Uri.file(encryptedFilePath));

            // Step 3: Decrypt the content
            const decryptedContent = await decryptContent(encryptedContent);

            // Step 4: Open decrypted content in a virtual document
            const decryptedDocument = await vscode.workspace.openTextDocument({
                content: decryptedContent,
                language: 'plaintext'
            });

            const editor = await vscode.window.showTextDocument(decryptedDocument, { preview: false });

            // Set context to indicate editing an encrypted project
        await vscode.commands.executeCommand('setContext', 'integriCode.editingEncryptedProject', true);

        // Register event listener to prevent direct saving
        const disposable = vscode.workspace.onWillSaveTextDocument(event => {
            if (event.document === decryptedDocument) {
                vscode.window.showWarningMessage('Please use "IntegriCode: Save Encrypted Project" to save your changes securely.');
                event.waitUntil(Promise.reject('Direct saving is disabled.'));
            }
        });

        context.subscriptions.push(disposable);

        } catch (error) {
            console.error(`Error opening encrypted project: ${error}`);
            vscode.window.showErrorMessage(`An error occurred: ${error instanceof Error ? error.message : String(error)}`);
        }
    });

    // Register the custom save command
    const saveEncryptedProjectCommand = vscode.commands.registerCommand('integriCode.saveEncryptedProject', async () => {
        try {
            const activeEditor = vscode.window.activeTextEditor;
            if (!activeEditor) {
                vscode.window.showErrorMessage('No active editor found.');
                return;
            }

            const document = activeEditor.document;

            // Ensure the document is the decrypted one
            // (You might need a better way to track this)
            if (document.uri.scheme !== 'untitled') { // Example condition
                vscode.window.showErrorMessage('This command can only be used on decrypted project documents.');
                return;
            }

            const decryptedContent = document.getText();

            // Step 1: Encrypt the content
            const encryptedContent = await encryptContent(decryptedContent);

            // Step 2: Ask user where to save the encrypted file
            const saveFileUri = await vscode.window.showSaveDialog({
                saveLabel: 'Save Encrypted Project',
                defaultUri: vscode.Uri.file(`${document.fileName}.enc`),
                filters: {
                    'Encrypted Files': ['enc'],
                    'All Files': ['*']
                }
            });

            if (!saveFileUri) {
                vscode.window.showErrorMessage('No save location selected.');
                return;
            }

            // Step 3: Write the encrypted content to the chosen path
            await vscode.workspace.fs.writeFile(saveFileUri, encryptedContent);

            vscode.window.showInformationMessage(`Encrypted project saved to: ${saveFileUri.fsPath}`);

            // Optional: Close the decrypted document
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');

        } catch (error) {
            console.error(`Error saving encrypted project: ${error}`);
            vscode.window.showErrorMessage(`An error occurred: ${error instanceof Error ? error.message : String(error)}`);
        }
    });

    // Add the commands to the extension's subscriptions
    context.subscriptions.push(openNewProjectFileCommand, createProjectCommand, openEncryptedProjectCommand, saveEncryptedProjectCommand);
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
