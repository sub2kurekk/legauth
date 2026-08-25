// Lightweight JSON-file data store. No native/compiled dependencies, so the
// project runs anywhere Node.js runs. Fine for a personal/friends-scale
// server; swap this module out for a real database if you need more scale.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('./config');

const DB_PATH = path.join(config.DATA_DIR, 'db.json');

function load() {
  if (!fs.existsSync(config.DATA_DIR)) fs.mkdirSync(config.DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    const initial = { users: {}, profiles: {}, tokens: {}, servers: {} };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2));
    return initial;
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

const db = load();

function persist() {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

function newId() {
  return crypto.randomUUID().replace(/-/g, '');
}

// ---------- Users ----------

function findUserByEmail(emailLower) {
  return Object.values(db.users).find(u => u.email === emailLower) || null;
}

function getUser(id) {
  return db.users[id] || null;
}

function listUsers() {
  return Object.values(db.users).sort((a, b) => a.createdAt - b.createdAt);
}

function createUser({ email, passwordHash, isAdmin = false, createdByAdminId = null }) {
  const id = newId();
  const user = {
    id,
    email: email.toLowerCase(),
    passwordHash,
    isAdmin,
    createdAt: Date.now(),
    createdByAdminId,
  };
  db.users[id] = user;
  persist();
  return user;
}

function saveUser(user) {
  db.users[user.id] = user;
  persist();
}

function deleteUser(id) {
  delete db.users[id];
  for (const uuid of Object.keys(db.profiles)) {
    if (db.profiles[uuid].userId === id) delete db.profiles[uuid];
  }
  for (const at of Object.keys(db.tokens)) {
    if (db.tokens[at].userId === id) delete db.tokens[at];
  }
  for (const sid of Object.keys(db.servers)) {
    if (db.servers[sid].userId === id) delete db.servers[sid];
  }
  persist();
}

function anyAdminExists() {
  return Object.values(db.users).some(u => u.isAdmin);
}

// ---------- Profiles (Minecraft "characters") ----------

function getProfile(uuid) {
  return db.profiles[uuid] || null;
}

function findProfileByNameLower(nameLower) {
  return Object.values(db.profiles).find(p => p.nameLower === nameLower) || null;
}

function getProfilesByUser(userId) {
  return Object.values(db.profiles).filter(p => p.userId === userId);
}

function createProfile({ uuid, userId, name }) {
  const profile = {
    uuid,
    userId,
    name,
    nameLower: name.toLowerCase(),
    skinHash: null,
    skinModel: 'default',
    capeHash: null,
    createdAt: Date.now(),
    nameChangedAt: null,
  };
  db.profiles[uuid] = profile;
  persist();
  return profile;
}

function saveProfile(profile) {
  profile.nameLower = profile.name.toLowerCase();
  db.profiles[profile.uuid] = profile;
  persist();
}

// ---------- Tokens ----------

function getToken(accessToken) {
  return db.tokens[accessToken] || null;
}

function isTokenExpired(token) {
  return Date.now() - token.issuedAt > config.TOKEN_EXPIRY_MS;
}

function isTokenUsable(token) {
  return !!token && token.valid && !isTokenExpired(token);
}

function createToken({ userId, clientToken, profileUuid }) {
  // Enforce a max-tokens-per-user limit by revoking the oldest first.
  const userTokens = Object.values(db.tokens)
    .filter(t => t.userId === userId && t.valid)
    .sort((a, b) => a.issuedAt - b.issuedAt);
  while (userTokens.length >= config.MAX_TOKENS_PER_USER) {
    const oldest = userTokens.shift();
    if (oldest) db.tokens[oldest.accessToken].valid = false;
  }
  const accessToken = crypto.randomBytes(24).toString('hex');
  const token = {
    accessToken,
    clientToken,
    userId,
    profileUuid: profileUuid || null,
    issuedAt: Date.now(),
    valid: true,
  };
  db.tokens[accessToken] = token;
  persist();
  return token;
}

function invalidateToken(accessToken) {
  const t = db.tokens[accessToken];
  if (t) {
    t.valid = false;
    persist();
  }
}

function invalidateAllUserTokens(userId) {
  let changed = false;
  for (const t of Object.values(db.tokens)) {
    if (t.userId === userId && t.valid) {
      t.valid = false;
      changed = true;
    }
  }
  if (changed) persist();
}

// ---------- Registered servers (lightweight "server hosting" directory) ----------

function listServers() {
  return Object.values(db.servers).sort((a, b) => a.addedAt - b.addedAt);
}

function listServersByUser(userId) {
  return listServers().filter(s => s.userId === userId);
}

function createServer({ userId, name, address }) {
  const id = newId();
  const server = { id, userId, name, address, addedAt: Date.now() };
  db.servers[id] = server;
  persist();
  return server;
}

function deleteServer(id, userId) {
  const s = db.servers[id];
  if (s && (s.userId === userId || getUser(userId)?.isAdmin)) {
    delete db.servers[id];
    persist();
    return true;
  }
  return false;
}

module.exports = {
  db,
  findUserByEmail,
  getUser,
  listUsers,
  createUser,
  saveUser,
  deleteUser,
  anyAdminExists,
  getProfile,
  findProfileByNameLower,
  getProfilesByUser,
  createProfile,
  saveProfile,
  getToken,
  isTokenExpired,
  isTokenUsable,
  createToken,
  invalidateToken,
  invalidateAllUserTokens,
  listServers,
  listServersByUser,
  createServer,
  deleteServer,
};
