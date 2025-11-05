import { encodeString, encodeStringReversible, decodeStringReversible, decodeString } from './passwords.js';

// Session storage key
const SESSION_STORAGE_KEY = 'xrpl_session';

/**
 * Session management utilities
 * Uses chrome.storage.local if available, otherwise falls back to localStorage
 */
const storage = {
    async get(key) {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            return new Promise((resolve) => {
                chrome.storage.local.get([key], (result) => {
                    resolve(result[key]);
                });
            });
        }
        return localStorage.getItem(key) ? JSON.parse(localStorage.getItem(key)) : null;
    },
    async set(key, value) {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            return new Promise((resolve) => {
                chrome.storage.local.set({ [key]: value }, resolve);
            });
        }
        localStorage.setItem(key, JSON.stringify(value));
    },
    async remove(key) {
        if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
            return new Promise((resolve) => {
                chrome.storage.local.remove([key], resolve);
            });
        }
        localStorage.removeItem(key);
    }
};

/**
 * Gets the current logged-in session
 * @returns {Promise<Object|null>} - Session object with address and seed, or null if not logged in
 */
export async function getSession() {
    return await storage.get(SESSION_STORAGE_KEY);
}

/**
 * Sets the current session
 * @param {string} address - XRPL account address
 * @param {string} seed - XRPL account seed (private key)
 */
async function setSession(address, seed) {
    await storage.set(SESSION_STORAGE_KEY, { address, seed, loggedIn: true });
}

/**
 * Clears the current session (logout)
 */
export async function clearSession() {
    await storage.remove(SESSION_STORAGE_KEY);
}

/**
 * Checks if a user is currently logged in
 * @returns {Promise<boolean>} - True if logged in, false otherwise
 */
export async function isLoggedIn() {
    const session = await getSession();
    return session !== null && session.loggedIn === true;
}

/**
 * Creates a new XRPL account
 * Generates a new wallet with a seed phrase
 * 
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @returns {Promise<Object>} - Object containing the new account details
 * 
 * @example
 * const account = await createXRPLAccount();
 * console.log('Address:', account.address);
 * console.log('Seed:', account.seed); // Save this securely!
 */
export async function createXRPLAccount(serverUrl = 'wss://s.altnet.rippletest.net:51233') {
    // Dynamic import of xrpl library
    let xrpl;
    try {
        xrpl = await import('xrpl');
    } catch (error) {
        throw new Error(
            'xrpl library is not installed. Please install it using: npm install xrpl'
        );
    }

    try {
        // Generate a new wallet
        const wallet = xrpl.Wallet.generate();

        // Connect to XRPL server to fund the account (testnet only)
        const client = new xrpl.Client(serverUrl);
        await client.connect();

        // On testnet, fund the account automatically
        if (serverUrl.includes('testnet') || serverUrl.includes('altnet')) {
            try {
                await client.fundWallet(wallet);
            } catch (fundError) {
                // Funding might fail, but account is still created
                console.warn('Could not auto-fund account:', fundError.message);
            }
        }

        await client.disconnect();

        return {
            address: wallet.address,
            seed: wallet.seed,
            publicKey: wallet.publicKey,
            privateKey: wallet.privateKey,
        };
    } catch (error) {
        throw new Error(`Failed to create XRPL account: ${error.message}`);
    }
}

/**
 * Signs in to an existing XRPL account using a private key (seed)
 * 
 * @param {string} seed - The XRPL account seed (private key)
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @returns {Promise<Object>} - Object containing account details and verification status
 * 
 * @example
 * const session = await loginXRPLAccount('sYourSecretSeedHere');
 * console.log('Logged in as:', session.address);
 */
export async function loginXRPLAccount(seed, serverUrl = 'wss://s.altnet.rippletest.net:51233') {
    if (!seed || typeof seed !== 'string') {
        throw new Error('Seed must be a non-empty string');
    }

    // Dynamic import of xrpl library
    let xrpl;
    try {
        xrpl = await import('xrpl');
    } catch (error) {
        throw new Error(
            'xrpl library is not installed. Please install it using: npm install xrpl'
        );
    }

    try {
        // Generate wallet from seed
        const wallet = xrpl.Wallet.fromSeed(seed);

        // Verify the account exists on the ledger
        const client = new xrpl.Client(serverUrl);
        await client.connect();

        try {
            const accountInfo = await client.request({
                command: 'account_info',
                account: wallet.address,
            });

            // Account exists and is valid
            await setSession(wallet.address, seed);
            await client.disconnect();

            return {
                success: true,
                address: wallet.address,
                publicKey: wallet.publicKey,
                accountInfo: accountInfo.result.account_data,
            };
        } catch (accountError) {
            // Account might not exist yet, but seed is valid
            await setSession(wallet.address, seed);
            await client.disconnect();

            return {
                success: true,
                address: wallet.address,
                publicKey: wallet.publicKey,
                accountInfo: null,
                message: 'Account created but not yet activated on the ledger. Fund it first.',
            };
        }
    } catch (error) {
        throw new Error(`Failed to login to XRPL account: ${error.message}`);
    }
}

/**
 * Mints an NFT on XRPL with the hashed password stored in the URI field
 * Uses the currently logged-in account. Throws error if not logged in.
 * The password is hashed using SHA-256 and converted to hexadecimal format
 * 
 * @param {string} password - The password to hash and store in the NFT URI
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @param {number} taxon - Optional taxon for grouping NFTs (default: 0)
 * @param {number} flags - NFT flags (default: 8 for transferable)
 * @returns {Promise<Object>} - Promise that resolves to the transaction response
 * 
 * @example
 * await loginXRPLAccount('sYourSecretSeedHere');
 * const response = await mintPasswordNFT('mySecurePassword');
 */
export async function mintPasswordNFT(
    password,
    serverUrl = 'wss://s.altnet.rippletest.net:51233',
    taxon = 0,
    flags = 8
) {
    if (!password || typeof password !== 'string') {
        throw new Error('Password must be a non-empty string');
    }

    // Check if user is logged in
    const session = await getSession();
    if (!session || !session.loggedIn) {
        throw new Error('User must be logged in to mint NFTs. Please login using loginXRPLAccount() first.');
    }

    // Dynamic import of xrpl library
    let xrpl;
    try {
        xrpl = await import('xrpl');
    } catch (error) {
        throw new Error(
            'xrpl library is not installed. Please install it using: npm install xrpl'
        );
    }

    try {
        // Step 1: Encode the password using reversible encoding (not hash, so it can be decoded)
        const encodedPassword = encodeStringReversible(password);

        // Step 2: Convert the encoded password to hexadecimal format for XRPL URI
        // Remove '0x' prefix if present - XRPL expects hex without prefix
        const uriHex = encodedPassword.startsWith('0x')
            ? encodedPassword.slice(2).toUpperCase()
            : encodedPassword.toUpperCase();

        // Step 4: Connect to XRPL server
        const client = new xrpl.Client(serverUrl);
        await client.connect();

        // Step 5: Generate wallet from stored seed
        const wallet = xrpl.Wallet.fromSeed(session.seed);

        // Step 6: Prepare NFTokenMint transaction
        // According to XRPL docs: https://xrpl.org/docs/references/protocol/transactions/types/nftokenmint
        const transaction = {
            TransactionType: 'NFTokenMint',
            Account: wallet.address,
            URI: uriHex, // Hex-encoded data (max 256 bytes)
            Flags: flags, // 8 = transferable, 1 = burnable
            NFTokenTaxon: taxon, // Optional taxon for grouping
        };

        // Step 7: Autofill transaction fields
        const prepared = await client.autofill(transaction);

        // Step 8: Sign the transaction
        const signed = wallet.sign(prepared);

        // Step 9: Submit the transaction
        const txResponse = await client.submitAndWait(signed.tx_blob);

        // Step 10: Disconnect from server
        await client.disconnect();

        return {
            success: true,
            hash: txResponse.result.hash,
            account: wallet.address,
            uri: uriHex,
            transaction: txResponse.result,
        };
    } catch (error) {
        throw new Error(`Failed to mint NFT: ${error.message}`);
    }
}

/**
 * Alternative function that accepts password in hex format directly
 * Uses the currently logged-in account. Throws error if not logged in.
 * 
 * @param {string} passwordHex - The password hash in hexadecimal format
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @param {number} taxon - Optional taxon for grouping NFTs (default: 0)
 * @param {number} flags - NFT flags (default: 8 for transferable)
 * @returns {Promise<Object>} - Promise that resolves to the transaction response
 */
export async function mintPasswordNFTFromHex(
    passwordHex,
    serverUrl = 'wss://s.altnet.rippletest.net:51233',
    taxon = 0,
    flags = 8
) {
    if (!passwordHex || typeof passwordHex !== 'string') {
        throw new Error('Password hex must be a non-empty string');
    }

    // Check if user is logged in
    const session = await getSession();
    if (!session || !session.loggedIn) {
        throw new Error('User must be logged in to mint NFTs. Please login using loginXRPLAccount() first.');
    }

    // Dynamic import of xrpl library
    let xrpl;
    try {
        xrpl = await import('xrpl');
    } catch (error) {
        throw new Error(
            'xrpl library is not installed. Please install it using: npm install xrpl'
        );
    }

    try {
        // Clean the hex string (remove 0x prefix and convert to uppercase)
        const uriHex = passwordHex.startsWith('0x')
            ? passwordHex.slice(2).toUpperCase()
            : passwordHex.toUpperCase();

        // Connect to XRPL server
        const client = new xrpl.Client(serverUrl);
        await client.connect();

        // Generate wallet from stored seed
        const wallet = xrpl.Wallet.fromSeed(session.seed);

        // Prepare NFTokenMint transaction
        const transaction = {
            TransactionType: 'NFTokenMint',
            Account: wallet.address,
            URI: uriHex,
            Flags: flags,
            NFTokenTaxon: taxon,
        };

        // Autofill, sign, and submit
        const prepared = await client.autofill(transaction);
        const signed = wallet.sign(prepared);
        const txResponse = await client.submitAndWait(signed.tx_blob);

        await client.disconnect();

        return {
            success: true,
            hash: txResponse.result.hash,
            account: wallet.address,
            uri: uriHex,
            transaction: txResponse.result,
        };
    } catch (error) {
        throw new Error(`Failed to mint NFT: ${error.message}`);
    }
}

/**
 * Retrieves all NFTs for a given XRPL address
 * If no address is provided, uses the currently logged-in account
 * 
 * @param {string} address - Optional XRPL account address (defaults to logged-in account)
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @returns {Promise<Array>} - Array of NFT objects
 * 
 * @example
 * const nfts = await getAllNFTs();
 * console.log('Total NFTs:', nfts.length);
 */
export async function getAllNFTs(address = null, serverUrl = 'wss://s.altnet.rippletest.net:51233') {
    // Dynamic import of xrpl library
    let xrpl;
    try {
        xrpl = await import('xrpl');
    } catch (error) {
        throw new Error(
            'xrpl library is not installed. Please install it using: npm install xrpl'
        );
    }

    try {
        // If no address provided, use logged-in account
        if (!address) {
            const session = await getSession();
            if (!session || !session.loggedIn) {
                throw new Error('No address provided and user is not logged in.');
            }
            address = session.address;
        }

        // Connect to XRPL server
        const client = new xrpl.Client(serverUrl);
        await client.connect();

        // Request all NFTs for the account
        const response = await client.request({
            command: 'account_nfts',
            account: address,
        });

        await client.disconnect();

        return response.result.account_nfts || [];
    } catch (error) {
        throw new Error(`Failed to retrieve NFTs: ${error.message}`);
    }
}

/**
 * Helper function to convert XRPL URI to hex string
 * XRPL may return URI in different formats (hex string, base64, etc.)
 */
function convertXRPLUriToHex(uri) {
    if (!uri) return '';

    // If it's already a string hex representation
    if (typeof uri === 'string') {
        // Remove any whitespace and convert to lowercase
        let hexString = uri.trim().toLowerCase();
        // Remove 0x prefix if present
        hexString = hexString.startsWith('0x') ? hexString.slice(2) : hexString;
        return hexString;
    }

    // If it's a Uint8Array or Array, convert to hex
    if (uri instanceof Uint8Array || Array.isArray(uri)) {
        return Array.from(new Uint8Array(uri))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // Try to convert to string
    return String(uri).trim().toLowerCase().replace(/^0x/, '');
}

/**
 * Retrieves all NFTs for the logged-in account and decodes their URIs
 * Attempts to decode using both reversible and hash verification methods
 * 
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @returns {Promise<Array>} - Array of decoded NFT objects with password attempts
 * 
 * @example
 * const decodedNFTs = await getAllNFTsAndDecode();
 * decodedNFTs.forEach(nft => {
 *   console.log('NFT ID:', nft.NFTokenID);
 *   console.log('Decoded password (reversible):', nft.decodedPassword);
 *   console.log('Is valid hash:', nft.isValidHash);
 * });
 */
export async function getAllNFTsAndDecode(serverUrl = 'wss://s.altnet.rippletest.net:51233') {
    try {
        // Get all NFTs
        const nfts = await getAllNFTs(null, serverUrl);

        // Decode each NFT's URI
        const decodedNFTs = await Promise.all(
            nfts.map(async (nft) => {
                let uri = nft.URI || nft.uri || '';

                // Convert hex URI to string format
                let decodedPassword = null;
                let isValidHash = false;
                let hexValue = null;

                try {
                    // Try to decode as reversible encoding
                    if (uri) {
                        // Convert XRPL URI to hex string format
                        let hexString = convertXRPLUriToHex(uri);

                        // Ensure hex string has even length (each byte is 2 hex chars)
                        if (hexString.length % 2 !== 0) {
                            hexString = '0' + hexString;
                        }

                        // Validate hex string contains only valid hex characters
                        if (!/^[0-9a-f]+$/.test(hexString)) {
                            throw new Error('Invalid hex string format');
                        }

                        // Add 0x prefix for decoding
                        hexValue = '0x' + hexString;
                        decodedPassword = decodeStringReversible(hexValue);
                    }
                } catch (error) {
                    // If reversible decoding fails, it might be a hash or invalid format
                    decodedPassword = null;
                    console.warn('Failed to decode NFT URI:', error.message, 'URI:', uri, 'Hex:', hexValue);
                }

                // If we have a hash, note that we can't decode it directly
                // but we can verify if a candidate password matches
                if (uri && !decodedPassword) {
                    // It's likely a hash, mark as such
                    isValidHash = true;
                }

                return {
                    ...nft,
                    uriHex: typeof uri === 'string' ? uri : hexValue?.slice(2) || '',
                    decodedPassword: decodedPassword, // Will be null if it's a hash
                    isReversible: decodedPassword !== null,
                    isValidHash: isValidHash || false,
                    hexValue: hexValue,
                };
            })
        );

        return decodedNFTs;
    } catch (error) {
        throw new Error(`Failed to retrieve and decode NFTs: ${error.message}`);
    }
}

/**
 * Verifies if a candidate password matches an NFT's URI hash
 * Useful for verifying passwords stored as hashes in NFT URIs
 * 
 * @param {string} nftTokenID - The NFT token ID
 * @param {string} candidatePassword - The password to verify
 * @param {string} serverUrl - The XRPL server URL (default: testnet)
 * @returns {Promise<boolean>} - True if the password matches the hash in the NFT URI
 * 
 * @example
 * const isValid = await verifyPasswordFromNFT('00080000...', 'myPassword');
 */
export async function verifyPasswordFromNFT(nftTokenID, candidatePassword, serverUrl = 'wss://s.altnet.rippletest.net:51233') {
    if (!nftTokenID || typeof nftTokenID !== 'string') {
        throw new Error('NFT Token ID must be a non-empty string');
    }

    if (!candidatePassword || typeof candidatePassword !== 'string') {
        throw new Error('Candidate password must be a non-empty string');
    }

    // Dynamic import of xrpl library
    let xrpl;
    try {
        xrpl = await import('xrpl');
    } catch (error) {
        throw new Error(
            'xrpl library is not installed. Please install it using: npm install xrpl'
        );
    }

    try {
        // Connect to XRPL server
        const client = new xrpl.Client(serverUrl);
        await client.connect();

        // Get NFT info
        const response = await client.request({
            command: 'nft_info',
            nft_id: nftTokenID,
        });

        await client.disconnect();

        const uri = response.result.nft.URI || response.result.nft.uri || '';

        if (!uri) {
            throw new Error('NFT URI is empty');
        }

        // Convert URI hex to hash format (with 0x prefix)
        const hashHex = uri.startsWith('0x') ? uri.toLowerCase() : '0x' + uri.toLowerCase();

        // Verify the password matches the hash
        return await decodeString(hashHex, candidatePassword);
    } catch (error) {
        throw new Error(`Failed to verify password from NFT: ${error.message}`);
    }
}
