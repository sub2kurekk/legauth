const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');

const KEY_DIR = path.join(config.DATA_DIR, 'keys');
const PRIV_PATH = path.join(KEY_DIR, 'private.pem');
const PUB_PATH = path.join(KEY_DIR, 'public.pem');

function ensureKeys() {
  if (!fs.existsSync(KEY_DIR)) fs.mkdirSync(KEY_DIR, { recursive: true });
  if (fs.existsSync(PRIV_PATH) && fs.existsSync(PUB_PATH)) {
    return {
      privateKey: fs.readFileSync(PRIV_PATH, 'utf8'),
      publicKey: fs.readFileSync(PUB_PATH, 'utf8'),
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  fs.writeFileSync(PRIV_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUB_PATH, publicKey, { mode: 0o644 });
  return { privateKey, publicKey };
}

// Per the Yggdrasil spec, property values are signed with SHA1withRSA (PKCS#1).
function signValue(privateKey, value) {
  const signer = crypto.createSign('RSA-SHA1');
  signer.update(value, 'utf8');
  signer.end();
  return signer.sign(privateKey).toString('base64');
}

module.exports = { ensureKeys, signValue };
