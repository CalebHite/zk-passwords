import { poseidon } from 'circomlib';
import * as snarkjs from 'snarkjs';

/**
 * Encodes a string into a zk-friendly hash using Poseidon hash
 * @param {string} input - The string to encode
 * @returns {string} - The hash as a hexadecimal string
 */
export function encodeString(input) {
    if (!input || typeof input !== 'string') {
        throw new Error('Input must be a non-empty string');
    }

    // Convert string to array of bytes (UTF-8 encoding)
    const utf8Bytes = new TextEncoder().encode(input);

    // Convert bytes to BigInt array (Poseidon works with field elements)
    // We'll chunk the bytes into 31-byte chunks to fit in field elements
    const fieldElements = [];
    const chunkSize = 31; // Field elements are typically 254 bits, so 31 bytes is safe

    for (let i = 0; i < utf8Bytes.length; i += chunkSize) {
        const chunk = utf8Bytes.slice(i, i + chunkSize);
        let value = BigInt(0);

        // Convert chunk to BigInt
        for (let j = 0; j < chunk.length; j++) {
            value = value * BigInt(256) + BigInt(chunk[j]);
        }

        fieldElements.push(value);
    }

    // If no elements, add a zero element
    if (fieldElements.length === 0) {
        fieldElements.push(BigInt(0));
    }

    // Hash the field elements using Poseidon
    // Poseidon can hash multiple inputs, so we pass the array
    const hash = poseidon(fieldElements);

    // Convert BigInt hash to hex string
    return '0x' + hash.toString(16);
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
 * @returns {boolean} - True if the candidate string matches the hash
 */
export function decodeString(hash, candidate) {
    if (!hash || typeof hash !== 'string') {
        throw new Error('Hash must be a non-empty string');
    }

    if (!candidate || typeof candidate !== 'string') {
        throw new Error('Candidate must be a non-empty string');
    }

    // Encode the candidate string
    const candidateHash = encodeString(candidate);

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
 * @returns {bigint} - The hash as BigInt
 */
export function encodeStringToBigInt(input) {
    const utf8Bytes = new TextEncoder().encode(input);
    const fieldElements = [];
    const chunkSize = 31;

    for (let i = 0; i < utf8Bytes.length; i += chunkSize) {
        const chunk = utf8Bytes.slice(i, i + chunkSize);
        let value = BigInt(0);

        for (let j = 0; j < chunk.length; j++) {
            value = value * BigInt(256) + BigInt(chunk[j]);
        }

        fieldElements.push(value);
    }

    if (fieldElements.length === 0) {
        fieldElements.push(BigInt(0));
    }

    return poseidon(fieldElements);
}

