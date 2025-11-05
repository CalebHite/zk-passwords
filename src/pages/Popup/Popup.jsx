import React, { useState, useEffect } from 'react';
import { encodeStringReversible, decodeStringReversible } from '../../scripts/passwords';
import './Popup.css';

const Popup = () => {
  const [password, setPassword] = useState('');
  const [hash, setHash] = useState('');
  const [encodedHash, setEncodedHash] = useState('');
  const [decodedString, setDecodedString] = useState('');

  useEffect(() => {
    if (password) {
      try {
        const hashed = encodeStringReversible(password);
        setHash(hashed);
      } catch (error) {
        setHash('Error: ' + error.message);
      }
    } else {
      setHash('');
    }
  }, [password]);

  useEffect(() => {
    if (encodedHash) {
      try {
        const decoded = decodeStringReversible(encodedHash);
        setDecodedString(decoded);
      } catch (error) {
        setDecodedString('Error: ' + error.message);
      }
    } else {
      setDecodedString('');
    }
  }, [encodedHash]);

  return (
    <div className="App">
      <header className="App-header">
        <div className="password-hash-container">
          <h2>Password Hasher</h2>

          {/* Encode Section */}
          <div className="section">
            <h3>Encode</h3>
            <input
              type="password"
              placeholder="Enter password to hash"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="password-input"
            />
            {hash && (
              <div className="hash-output">
                <label>Hash:</label>
                <div className="hash-value">{hash}</div>
              </div>
            )}
          </div>

          {/* Decode Section */}
          <div className="section">
            <h3>Decode</h3>
            <input
              type="text"
              placeholder="Enter encoded hex string (0x...)"
              value={encodedHash}
              onChange={(e) => setEncodedHash(e.target.value)}
              className="password-input"
            />
            {decodedString && (
              <div className="hash-output">
                <label>Decoded:</label>
                <div className="hash-value">{decodedString}</div>
              </div>
            )}
          </div>
        </div>
      </header>
    </div>
  );
};

export default Popup;
