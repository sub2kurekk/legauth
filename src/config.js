require('dotenv').config();
const path = require('path');

const PORT = parseInt(process.env.PORT || '3000', 10);

module.exports = {
  PORT,
  PUBLIC_URL: (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, ''),
  SITE_NAME: process.env.SITE_NAME || 'Legauth',
  SESSION_SECRET: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  ADMIN_EMAIL: (process.env.ADMIN_EMAIL || 'admin@localhost').toLowerCase(),
  TOKEN_EXPIRY_MS: parseInt(process.env.TOKEN_EXPIRY_DAYS || '15', 10) * 24 * 60 * 60 * 1000,
  MAX_TOKENS_PER_USER: parseInt(process.env.MAX_TOKENS_PER_USER || '10', 10),
  NAME_CHANGE_COOLDOWN_MS: parseInt(process.env.NAME_CHANGE_COOLDOWN_HOURS || '24', 10) * 60 * 60 * 1000,
  ALLOW_REGISTRATION: (process.env.ALLOW_REGISTRATION || 'true').toLowerCase() !== 'false',
  DATA_DIR: path.join(__dirname, '..', 'data'),
  TEXTURES_DIR: path.join(__dirname, '..', 'data', 'textures'),
};
