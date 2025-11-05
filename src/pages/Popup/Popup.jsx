import React, { useState, useEffect } from 'react';
import {
  createXRPLAccount,
  loginXRPLAccount,
  clearSession,
  getSession,
  isLoggedIn,
  mintPasswordNFT,
  getAllNFTsAndDecode,
} from '../../scripts/xrpl';
import './Popup.css';

const Popup = () => {
  const [isLoggedInState, setIsLoggedInState] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [accountAddress, setAccountAddress] = useState('');
  const [accountSeed, setAccountSeed] = useState('');
  const [loginSeed, setLoginSeed] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [savedPasswords, setSavedPasswords] = useState([]);
  const [newAccountDetails, setNewAccountDetails] = useState(null);
  const [showSeed, setShowSeed] = useState(false);

  // Check login status on mount
  useEffect(() => {
    checkLoginStatus();
  }, []);

  // Load saved passwords when logged in
  useEffect(() => {
    if (isLoggedInState) {
      loadSavedPasswords();
    }
  }, [isLoggedInState]);

  const checkLoginStatus = async () => {
    try {
      const loggedIn = await isLoggedIn();
      setIsLoggedInState(loggedIn);
      if (loggedIn) {
        const session = await getSession();
        setAccountAddress(session.address);
        setAccountSeed(session.seed);
      }
    } catch (err) {
      setError('Failed to check login status: ' + err.message);
    }
  };

  const loadSavedPasswords = async () => {
    setLoading(true);
    setError('');
    try {
      const nfts = await getAllNFTsAndDecode();
      setSavedPasswords(nfts);
    } catch (err) {
      setError('Failed to load passwords: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateWallet = async () => {
    setLoading(true);
    setError('');
    setSuccess('');
    setNewAccountDetails(null);
    try {
      const account = await createXRPLAccount();
      setNewAccountDetails(account);
      setSuccess('Wallet created successfully! Please save your seed securely.');

      // Auto-login after creating wallet
      await loginXRPLAccount(account.seed);
      await checkLoginStatus();
    } catch (err) {
      setError('Failed to create wallet: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!loginSeed.trim()) {
      setError('Please enter your seed/private key');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const result = await loginXRPLAccount(loginSeed.trim());
      setSuccess('Logged in successfully!');
      setAccountAddress(result.address);
      const session = await getSession();
      setAccountSeed(session.seed);
      setIsLoggedInState(true);
      setLoginSeed('');
      await loadSavedPasswords();
    } catch (err) {
      setError('Failed to login: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      await clearSession();
      setIsLoggedInState(false);
      setAccountAddress('');
      setAccountSeed('');
      setSavedPasswords([]);
      setNewAccountDetails(null);
      setShowSeed(false);
      setSuccess('Logged out successfully');
    } catch (err) {
      setError('Failed to logout: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSavePassword = async () => {
    if (!newPassword.trim()) {
      setError('Please enter a password to save');
      return;
    }

    setLoading(true);
    setError('');
    setSuccess('');
    try {
      await mintPasswordNFT(newPassword.trim());
      setSuccess('Password saved successfully as NFT!');
      setNewPassword('');
      await loadSavedPasswords();
    } catch (err) {
      setError('Failed to save password: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setSuccess('Copied to clipboard!');
      setTimeout(() => setSuccess(''), 2000);
    });
  };

  const formatAddress = (address) => {
    if (!address) return '';
    return `${address.slice(0, 8)}...${address.slice(-8)}`;
  };

  return (
    <div className="App">
      <header className="App-header">
        <div className="password-hash-container">
          <h2>XRPL Password Manager</h2>

          {/* Error/Success Messages */}
          {error && <div className="message error">{error}</div>}
          {success && <div className="message success">{success}</div>}

          {/* Not Logged In Section */}
          {!isLoggedInState && (
            <>
              {/* Create Wallet Section */}
              <div className="section">
                <h3>Create New Wallet</h3>
                <p className="section-description">
                  Generate a new XRPL wallet to store your passwords securely as NFTs
                </p>
                <button
                  onClick={handleCreateWallet}
                  disabled={loading}
                  className="btn btn-primary"
                >
                  {loading ? 'Creating...' : 'Create New Wallet'}
                </button>

                {newAccountDetails && (
                  <div className="account-details">
                    <div className="detail-item">
                      <label>Address:</label>
                      <div className="detail-value">
                        {newAccountDetails.address}
                        <button
                          onClick={() => copyToClipboard(newAccountDetails.address)}
                          className="btn-copy"
                        >
                          Copy
                        </button>
                      </div>
                    </div>
                    <div className="detail-item">
                      <label>Seed (Private Key):</label>
                      <div className="detail-value">
                        {showSeed ? (
                          <>
                            {newAccountDetails.seed}
                            <button
                              onClick={() => copyToClipboard(newAccountDetails.seed)}
                              className="btn-copy"
                            >
                              Copy
                            </button>
                          </>
                        ) : (
                          <>
                            {'•'.repeat(40)}
                            <button
                              onClick={() => setShowSeed(true)}
                              className="btn-copy"
                            >
                              Show
                            </button>
                          </>
                        )}
                      </div>
                      <div className="warning-text">
                        ⚠️ Save this seed securely! You'll need it to access your wallet.
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Login Section */}
              <div className="section">
                <h3>Login to Existing Wallet</h3>
                <p className="section-description">
                  Enter your seed/private key to access your saved passwords
                </p>
                <input
                  type="password"
                  placeholder="Enter your seed/private key"
                  value={loginSeed}
                  onChange={(e) => setLoginSeed(e.target.value)}
                  className="password-input"
                  onKeyPress={(e) => e.key === 'Enter' && handleLogin()}
                />
                <button
                  onClick={handleLogin}
                  disabled={loading || !loginSeed.trim()}
                  className="btn btn-secondary"
                >
                  {loading ? 'Logging in...' : 'Login'}
                </button>
              </div>
            </>
          )}

          {/* Logged In Section */}
          {isLoggedInState && (
            <>
              {/* Account Info */}
              <div className="section account-info">
                <h3>Wallet Connected</h3>
                <div className="account-address">
                  <label>Address:</label>
                  <div className="address-value">
                    {formatAddress(accountAddress)}
                    <button
                      onClick={() => copyToClipboard(accountAddress)}
                      className="btn-copy"
                    >
                      Copy
                    </button>
                  </div>
                </div>
                <div className="account-address">
                  <label>Seed (Private Key):</label>
                  <div className="address-value">
                    {showSeed ? (
                      <>
                        {accountSeed}
                        <button
                          onClick={() => copyToClipboard(accountSeed)}
                          className="btn-copy"
                        >
                          Copy
                        </button>
                      </>
                    ) : (
                      <>
                        {'•'.repeat(40)}
                        <button
                          onClick={() => setShowSeed(true)}
                          className="btn-copy"
                        >
                          Show
                        </button>
                      </>
                    )}
                  </div>
                </div>
                <button onClick={handleLogout} className="btn btn-logout">
                  Logout
                </button>
              </div>

              {/* Save New Password Section */}
              <div className="section">
                <h3>Save New Password</h3>
                <input
                  type="password"
                  placeholder="Enter password to save"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="password-input"
                  onKeyPress={(e) => e.key === 'Enter' && handleSavePassword()}
                />
                <button
                  onClick={handleSavePassword}
                  disabled={loading || !newPassword.trim()}
                  className="btn btn-primary"
                >
                  {loading ? 'Saving...' : 'Save Password as NFT'}
                </button>
              </div>

              {/* Saved Passwords Section */}
              <div className="section">
                <h3>Saved Passwords</h3>
                <button
                  onClick={loadSavedPasswords}
                  disabled={loading}
                  className="btn btn-refresh"
                >
                  {loading ? 'Loading...' : '🔄 Refresh'}
                </button>

                {loading && savedPasswords.length === 0 ? (
                  <div className="loading-text">Loading passwords...</div>
                ) : savedPasswords.length === 0 ? (
                  <div className="empty-state">No passwords saved yet</div>
                ) : (
                  <div className="passwords-list">
                    {savedPasswords.map((nft, index) => (
                      <div key={nft.NFTokenID || index} className="password-item">
                        <div className="password-item-header">
                          <span className="password-number">#{index + 1}</span>
                          {nft.decodedPassword ? (
                            <div className="password-decoded">
                              <label>Password:</label>
                              <div className="password-value">
                                {nft.decodedPassword}
                                <button
                                  onClick={() => copyToClipboard(nft.decodedPassword)}
                                  className="btn-copy-small"
                                >
                                  Copy
                                </button>
                              </div>
                            </div>
                          ) : (
                            <div className="password-hash-info">
                              <span className="hash-badge">Hash</span>
                              <span className="hash-note">
                                Password stored as hash (verify with verifyPasswordFromNFT)
                              </span>
                            </div>
                          )}
                        </div>
                        <div className="password-item-footer">
                          <div className="nft-id">
                            NFT ID: {formatAddress(nft.NFTokenID)}
                          </div>
                          {nft.decodedPassword && (
                            <button
                              onClick={() => copyToClipboard(nft.decodedPassword)}
                              className="btn-copy-small"
                            >
                              Copy Password
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </header>
    </div>
  );
};

export default Popup;
