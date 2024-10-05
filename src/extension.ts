// Import necessary VS Code APIs and other modules
import * as vscode from 'vscode';
import * as crypto from 'crypto'; // Using Node.js built-in crypto module
import * as fs from 'fs';
import * as keytar from 'keytar';
// If you installed crypto-js, you can import it instead
// import * as CryptoJS from 'crypto-js';

const SERVICE_NAME = 'IntegriCodeExtension';
const ACCOUNT_PUBLIC_KEY = 'publicKey';
const ACCOUNT_PRIVATE_KEY = 'privateKey';

export async function activate(context: vscode.ExtensionContext) {
    console.log('Extension "IntegriCode" is now active!');

        // Ensure key pair exists
        await ensureKeyPair();

            // TODO REMOVE DEBUG THINGY
            // Verify keys and show output dialog
    await verifyKeys();

    // Register the "IntegriCode: Open File" command
    const openFileCommand = vscode.commands.registerCommand('integriCode.openFile', async () => {
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

            // Step 4: Read the code file
            const codeContent = await vscode.workspace.fs.readFile(vscode.Uri.file(codeFilePath));
            const codeString = Buffer.from(codeContent).toString('utf8');

            // Step 5: Read the signature file
            const signatureContent = await vscode.workspace.fs.readFile(vscode.Uri.file(signatureFilePath));
            const signature = signatureContent;

            // Step 6: Read the public key
            const publicKey = fs.readFileSync(publicKeyPath, 'utf8');

            // Step 7: Verify the signature
            const verifier = crypto.createVerify('sha512');
            verifier.update(codeString);
            verifier.end();

            const isValid = verifier.verify(publicKey, signature);

            if (isValid) {
                vscode.window.showInformationMessage('Signature verification successful. The file is authentic.');
            } else {
                vscode.window.showErrorMessage('Signature verification failed. The file may have been tampered with.');
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

    // Add the commands to the extension's subscriptions
    context.subscriptions.push(openFileCommand, createProjectCommand);
}

export function deactivate() {
    console.log('Extension "code-integrity" is now deactivated.');
}

/**
 * Ensures that the extension has a generated key pair stored securely.
 * If not, generates a new RSA 2048 key pair and stores them using keytar.
 */
async function ensureKeyPair() {
    // Check if keys already exist
    const existingPublicKey = await keytar.getPassword(SERVICE_NAME, ACCOUNT_PUBLIC_KEY);
    const existingPrivateKey = await keytar.getPassword(SERVICE_NAME, ACCOUNT_PRIVATE_KEY);

    if (existingPublicKey && existingPrivateKey) {
        console.log('Key pair already exists.');
        return;
    }

    console.log('Generating new RSA 2048 key pair...');

    // Generate RSA 2048 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        }
    });

    // Store the keys securely using keytar
    await keytar.setPassword(SERVICE_NAME, ACCOUNT_PUBLIC_KEY, publicKey);
    await keytar.setPassword(SERVICE_NAME, ACCOUNT_PRIVATE_KEY, privateKey);

    console.log('Key pair generated and stored securely.');
}

/**
 * Retrieves the stored public key.
 * @returns The public key in PEM format.
 */
export async function getPublicKey(): Promise<string> {
    const publicKey = await keytar.getPassword(SERVICE_NAME, ACCOUNT_PUBLIC_KEY);
    if (!publicKey) {
        throw new Error('Public key not found.');
    }
    return publicKey;
}

/**
 * Retrieves the stored private key.
 * @returns The private key in PEM format.
 */
export async function getPrivateKey(): Promise<string> {
    const privateKey = await keytar.getPassword(SERVICE_NAME, ACCOUNT_PRIVATE_KEY);
    if (!privateKey) {
        throw new Error('Private key not found.');
    }
    return privateKey;
}

/**
 * Verifies that the extension has access to both public and private keys.
 * Displays an information or error dialog based on the verification result.
 */
async function verifyKeys() {
    try {
        const publicKey = await keytar.getPassword(SERVICE_NAME, ACCOUNT_PUBLIC_KEY);
        const privateKey = await keytar.getPassword(SERVICE_NAME, ACCOUNT_PRIVATE_KEY);

        if (publicKey && privateKey) {
            vscode.window.showInformationMessage('IntegriCode: Key pair is successfully loaded.');
        } else {
            vscode.window.showErrorMessage('IntegriCode: Missing public or private key.');
        }
    } catch (error) {
        console.error(`Error verifying keys: ${error}`);
        vscode.window.showErrorMessage('IntegriCode: An error occurred while verifying keys.');
    }
}

/**
 * Decrypts the encrypted metadata using the editor's private key.
 * Implement this function based on your cryptographic requirements.
 * 
 * @param encryptedMetadata The encrypted metadata string.
 * @returns The decrypted metadata string.
 */
function decryptMetadata(encryptedMetadata: string): string {
    // Example using Node.js crypto module with RSA
    // Replace with your actual decryption logic

    // Load the editor's private key
    const privateKeyPath = '/path/to/editor_private_key.pem'; // Update the path accordingly
	const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    // Decrypt the metadata
    const decryptedBuffer = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_PADDING,
        },
        Buffer.from(encryptedMetadata, 'base64')
    );

    return decryptedBuffer.toString('utf8');
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
