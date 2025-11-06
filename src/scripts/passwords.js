/**
 * Encodes a string into a hash using Web Crypto API (SHA-256)
 * This is a pure JavaScript solution that doesn't require WebAssembly
 * @param {string} input - The string to encode
 * @returns {Promise<string>} - Promise that resolves to the hash as a hexadecimal string
 */
export async function encodeString(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('Input must be a non-empty string');
    }

    // Convert string to array buffer (UTF-8 encoding)
    const utf8Bytes = new TextEncoder().encode(input);

    // Hash using Web Crypto API (SHA-256)
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8Bytes);

    // Convert ArrayBuffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    return '0x' + hashHex;
}

/**
 * Decodes a hash back to the original string (NOT POSSIBLE with cryptographic hashes)
 * This function verifies if a string matches the given hash
 * 
 * Note: Cryptographic hashes are one-way functions. True decoding is impossible.
 * This function instead verifies if a candidate string produces the same hash.
 * 
 * @param {string} hash - The hash to verify against
 * @param {string} candidate - The candidate string to check
 * @returns {Promise<boolean>} - Promise that resolves to true if the candidate string matches the hash
 */
export async function decodeString(hash, candidate) {
    if (!hash || typeof hash !== 'string') {
        throw new Error('Hash must be a non-empty string');
    }

    if (!candidate || typeof candidate !== 'string') {
        throw new Error('Candidate must be a non-empty string');
    }

    // Encode the candidate string
    const candidateHash = await encodeString(candidate);

    // Compare hashes (normalize to lowercase for comparison)
    return candidateHash.toLowerCase() === hash.toLowerCase();
}

/**
 * Alternative: Reversible encoding using field element encoding
 * This is NOT a cryptographic hash, but a reversible encoding scheme
 * that uses zk-friendly primitives
 * 
 * @param {string} input - The string to encode
 * @returns {string} - Encoded representation as hex string
 */
export function encodeStringReversible(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('Input must be a non-empty string');
    }

    // Convert string to UTF-8 bytes
    const utf8Bytes = new TextEncoder().encode(input);

    // Convert to hex string
    const hexString = Array.from(utf8Bytes)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');

    // Convert to BigInt for zk-friendly representation
    const bigIntValue = BigInt('0x' + hexString);

    // Return as hex string with 0x prefix
    return '0x' + bigIntValue.toString(16);
}

/**
 * Decodes a reversibly encoded string back to original
 * 
 * @param {string} encoded - The encoded hex string
 * @returns {string} - The original string
 */
export function decodeStringReversible(encoded) {
    if (!encoded || typeof encoded !== 'string') {
        throw new Error('Encoded must be a non-empty string');
    }

    // Remove 0x prefix if present
    const hexString = encoded.startsWith('0x') ? encoded.slice(2) : encoded;

    // Convert hex string to bytes
    const bytes = [];
    for (let i = 0; i < hexString.length; i += 2) {
        const byte = parseInt(hexString.substr(i, 2), 16);
        bytes.push(byte);
    }

    // Convert bytes to string
    return new TextDecoder().decode(new Uint8Array(bytes));
}

/**
 * Encodes a string using Base64 encoding (reversible, hash-like appearance)
 * This produces a string that looks like a hash but can be decoded back to the original
 * 
 * @param {string} input - The string to encode
 * @returns {string} - Base64-encoded string
 */
export function encodeStringBase64(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('Input must be a non-empty string');
    }

    // Convert string to UTF-8 bytes
    const utf8Bytes = new TextEncoder().encode(input);

    // Convert bytes to base64 string
    // In browser environment, use btoa with proper UTF-8 handling
    let binary = '';
    for (let i = 0; i < utf8Bytes.length; i++) {
        binary += String.fromCharCode(utf8Bytes[i]);
    }
    return btoa(binary);
}

/**
 * Decodes a Base64-encoded string back to original
 * 
 * @param {string} encoded - The Base64-encoded string
 * @returns {string} - The original string
 */
export function decodeStringBase64(encoded) {
    if (!encoded || typeof encoded !== 'string') {
        throw new Error('Encoded must be a non-empty string');
    }

    // Decode base64 to binary string
    const binary = atob(encoded);

    // Convert binary string to UTF-8 bytes
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    // Convert bytes to string
    return new TextDecoder().decode(bytes);
}

/**
 * Helper function to get hash as BigInt for use in zk circuits
 * @param {string} input - The string to hash
 * @returns {Promise<bigint>} - Promise that resolves to the hash as BigInt
 */
export async function encodeStringToBigInt(input) {
    const hashHex = await encodeString(input);
    // Remove '0x' prefix and convert to BigInt
    return BigInt(hashHex);
}

/**
 * Derives an encryption key from a seed/password using PBKDF2
 * @param {string} seed - The seed/password to derive key from
 * @returns {Promise<CryptoKey>} - The derived encryption key
 */
async function deriveEncryptionKey(seed) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(seed),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );

    const key = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: encoder.encode('xrpl-password-manager-salt'), // Fixed salt for consistency
            iterations: 100000,
            hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );

    return key;
}

/**
 * Encrypts a password using AES-GCM encryption (zk-friendly)
 * The encrypted data will look like a hash on the block explorer
 * 
 * @param {string} password - The password to encrypt
 * @param {string} seed - The encryption key seed (typically the wallet seed)
 * @returns {Promise<string>} - Promise that resolves to the encrypted data as hex string
 */
export async function encryptPassword(password, seed) {
    if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
    }
    if (!seed || typeof seed !== 'string') {
        throw new Error('Seed must be a non-empty string');
    }

    try {
        // Derive encryption key from seed
        const key = await deriveEncryptionKey(seed);

        // Convert password to bytes
        const encoder = new TextEncoder();
        const passwordBytes = encoder.encode(password);

        // Generate a random IV (initialization vector)
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Encrypt the password
        const encryptedData = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            key,
            passwordBytes
        );

        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encryptedData.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedData), iv.length);

        // Convert to hex string
        const hexString = Array.from(combined)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');

        return '0x' + hexString;
    } catch (error) {
        throw new Error(`Failed to encrypt password: ${error.message}`);
    }
}

/**
 * Decrypts an encrypted password using AES-GCM decryption
 * 
 * @param {string} encryptedHex - The encrypted data as hex string
 * @param {string} seed - The encryption key seed (typically the wallet seed)
 * @returns {Promise<string>} - Promise that resolves to the decrypted password
 */
export async function decryptPassword(encryptedHex, seed) {
    if (!encryptedHex || typeof encryptedHex !== 'string') {
        throw new Error('Encrypted hex must be a non-empty string');
    }
    if (!seed || typeof seed !== 'string') {
        throw new Error('Seed must be a non-empty string');
    }

    try {
        // Derive decryption key from seed
        const key = await deriveEncryptionKey(seed);

        // Remove 0x prefix if present
        const hexString = encryptedHex.startsWith('0x')
            ? encryptedHex.slice(2)
            : encryptedHex;

        // Convert hex to bytes
        const bytes = [];
        for (let i = 0; i < hexString.length; i += 2) {
            bytes.push(parseInt(hexString.substr(i, 2), 16));
        }
        const combined = new Uint8Array(bytes);

        // Extract IV (first 12 bytes) and encrypted data (rest)
        const iv = combined.slice(0, 12);
        const encryptedData = combined.slice(12);

        // Decrypt the data
        const decryptedData = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
            },
            key,
            encryptedData
        );

        // Convert decrypted bytes to string
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (error) {
        throw new Error(`Failed to decrypt password: ${error.message}`);
    }
}

