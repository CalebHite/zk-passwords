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
 * Helper function to get hash as BigInt for use in zk circuits
 * @param {string} input - The string to hash
 * @returns {Promise<bigint>} - Promise that resolves to the hash as BigInt
 */
export async function encodeStringToBigInt(input) {
    const hashHex = await encodeString(input);
    // Remove '0x' prefix and convert to BigInt
    return BigInt(hashHex);
}

