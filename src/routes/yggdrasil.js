// Implements the Yggdrasil API + authlib-injector extension API, per:
// https://github.com/yushijinhun/authlib-injector/wiki (Server Specifications)

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const config = require('../config');
const store = require('../store');
const { signValue } = require('../keys');
const { processTexture } = require('../util/textures');

const upload = multer({ storage: multer.memoryStorage() });

function buildRouter({ privateKey, publicKey }) {
  const router = express.Router();

  // Both the auth endpoints (brute-force) and signout (password oracle)
  // need rate limiting per the spec's security notes.
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'ForbiddenOperationException', errorMessage: 'Too many attempts. Try again later.' },
  });

  function ygError(res, status, error, errorMessage, cause) {
    const body = { error, errorMessage };
    if (cause) body.cause = cause;
    return res.status(status).json(body);
  }

  function serializeUser(user) {
    return {
      id: user.id,
      properties: [{ name: 'preferredLanguage', value: 'en' }],
    };
  }

  function serializeProfile(profile, { includeProperties = false, unsigned = true } = {}) {
    const base = { id: profile.uuid, name: profile.name };
    if (!includeProperties) return base;

    const texturesPayload = {
      timestamp: Date.now(),
      profileId: profile.uuid,
      profileName: profile.name,
      textures: {},
    };
    if (profile.skinHash) {
      texturesPayload.textures.SKIN = { url: `${config.PUBLIC_URL}/textures/${profile.skinHash}` };
      if (profile.skinModel === 'slim') {
        texturesPayload.textures.SKIN.metadata = { model: 'slim' };
      }
    }
    if (profile.capeHash) {
      texturesPayload.textures.CAPE = { url: `${config.PUBLIC_URL}/textures/${profile.capeHash}` };
    }

    const texturesB64 = Buffer.from(JSON.stringify(texturesPayload), 'utf8').toString('base64');
    const properties = [{ name: 'textures', value: texturesB64 }];
    if (!unsigned) properties[0].signature = signValue(privateKey, texturesB64);
    properties.push({ name: 'uploadableTextures', value: 'skin,cape' });

    base.properties = properties;
    return base;
  }

  function requireBearer(req, res, next) {
    const auth = req.headers.authorization || '';
    const m = auth.match(/^Bearer (.+)$/);
    if (!m) return res.status(401).end();
    const token = store.getToken(m[1]);
    if (!store.isTokenUsable(token)) return res.status(401).end();
    req.tokenUser = store.getUser(token.userId);
    if (!req.tokenUser) return res.status(401).end();
    next();
  }

  // ---------------- Extension API: metadata / service discovery ----------------

  router.get('/', (req, res) => {
    let host;
    try {
      host = new URL(config.PUBLIC_URL).host;
    } catch {
      host = 'localhost';
    }
    res.json({
      meta: {
        serverName: config.SITE_NAME,
        implementationName: 'mojang-style-yggdrasil',
        implementationVersion: '1.0.0',
        links: {
          homepage: `${config.PUBLIC_URL}/`,
          register: `${config.PUBLIC_URL}/register`,
        },
        'feature.non_email_login': true,
        'feature.enable_profile_key': false,
        'feature.username_check': false,
        'feature.no_mojang_namespace': false,
        'feature.enable_mojang_anti_features': false,
      },
      skinDomains: [host, `.${host}`],
      signaturePublickey: publicKey,
    });
  });

  // ---------------- User (authserver) section ----------------

  router.post('/authserver/authenticate', authLimiter, (req, res) => {
    const { username, password, clientToken, requestUser, agent } = req.body || {};
    if (!username || !password || !agent) {
      return ygError(res, 400, 'IllegalArgumentException', 'username, password and agent are required.');
    }

    let user = store.findUserByEmail(String(username).toLowerCase());
    let loginProfile = null;
    if (!user) {
      // Support logging in with a character/profile name too
      // (feature.non_email_login, advertised in the meta response).
      const profile = store.findProfileByNameLower(String(username).toLowerCase());
      if (profile) {
        user = store.getUser(profile.userId);
        loginProfile = profile;
      }
    }

    if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return ygError(res, 403, 'ForbiddenOperationException', 'Invalid credentials. Invalid username or password.');
    }

    const ct = clientToken || crypto.randomUUID().replace(/-/g, '');
    const profiles = store.getProfilesByUser(user.id);
    let selected = loginProfile || (profiles.length === 1 ? profiles[0] : null);

    const token = store.createToken({ userId: user.id, clientToken: ct, profileUuid: selected ? selected.uuid : null });

    const body = {
      accessToken: token.accessToken,
      clientToken: ct,
      availableProfiles: profiles.map(p => serializeProfile(p, { includeProperties: false })),
    };
    if (selected) body.selectedProfile = serializeProfile(selected, { includeProperties: false });
    if (requestUser) body.user = serializeUser(user);
    res.json(body);
  });

  router.post('/authserver/refresh', (req, res) => {
    const { accessToken, clientToken, requestUser, selectedProfile } = req.body || {};
    if (!accessToken) return ygError(res, 400, 'IllegalArgumentException', 'accessToken is required.');

    const token = store.getToken(accessToken);
    if (!store.isTokenUsable(token) || (clientToken && token.clientToken !== clientToken)) {
      return ygError(res, 403, 'ForbiddenOperationException', 'Invalid token.');
    }

    let boundUuid = token.profileUuid;
    if (selectedProfile) {
      if (boundUuid) {
        return ygError(res, 400, 'IllegalArgumentException', 'Access token already has a profile assigned.');
      }
      const p = store.getProfile(selectedProfile.id);
      if (!p || p.userId !== token.userId) {
        return ygError(res, 403, 'ForbiddenOperationException', 'Invalid profile.');
      }
      boundUuid = p.uuid;
    }

    store.invalidateToken(accessToken);
    const newToken = store.createToken({ userId: token.userId, clientToken: token.clientToken, profileUuid: boundUuid });
    const user = store.getUser(token.userId);

    const body = { accessToken: newToken.accessToken, clientToken: newToken.clientToken };
    if (boundUuid) {
      const p = store.getProfile(boundUuid);
      if (p) body.selectedProfile = serializeProfile(p, { includeProperties: false });
    }
    if (requestUser && user) body.user = serializeUser(user);
    res.json(body);
  });

  router.post('/authserver/validate', (req, res) => {
    const { accessToken, clientToken } = req.body || {};
    const token = store.getToken(accessToken);
    if (!store.isTokenUsable(token) || (clientToken && token.clientToken !== clientToken)) {
      return ygError(res, 403, 'ForbiddenOperationException', 'Invalid token.');
    }
    res.status(204).end();
  });

  router.post('/authserver/invalidate', (req, res) => {
    const { accessToken } = req.body || {};
    if (accessToken) store.invalidateToken(accessToken);
    res.status(204).end();
  });

  router.post('/authserver/signout', authLimiter, (req, res) => {
    const { username, password } = req.body || {};
    const user = store.findUserByEmail(String(username || '').toLowerCase());
    if (!user || !bcrypt.compareSync(password || '', user.passwordHash)) {
      return ygError(res, 403, 'ForbiddenOperationException', 'Invalid credentials. Invalid username or password.');
    }
    store.invalidateAllUserTokens(user.id);
    res.status(204).end();
  });

  // ---------------- Session section ----------------
  // Join records are short-lived (30s) by spec, so an in-memory map is fine.
  const joinRecords = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of joinRecords) {
      if (v.expiresAt < now) joinRecords.delete(k);
    }
  }, 15000).unref();

  router.post('/sessionserver/session/minecraft/join', (req, res) => {
    const { accessToken, selectedProfile, serverId } = req.body || {};
    const token = store.getToken(accessToken);
    if (!store.isTokenUsable(token) || !selectedProfile || token.profileUuid !== selectedProfile || !serverId) {
      return ygError(res, 403, 'ForbiddenOperationException', 'Invalid token.');
    }
    joinRecords.set(serverId, {
      profileUuid: selectedProfile,
      accessToken,
      ip: req.ip,
      expiresAt: Date.now() + 30000,
    });
    res.status(204).end();
  });

  router.get('/sessionserver/session/minecraft/hasJoined', (req, res) => {
    const { username, serverId } = req.query;
    const record = serverId && joinRecords.get(serverId);
    if (!record) return res.status(204).end();
    const profile = store.getProfile(record.profileUuid);
    if (!profile || profile.nameLower !== String(username || '').toLowerCase()) {
      return res.status(204).end();
    }
    joinRecords.delete(serverId); // one-time use
    res.json(serializeProfile(profile, { includeProperties: true, unsigned: false }));
  });

  // ---------------- Roles (profile) section ----------------

  router.get('/sessionserver/session/minecraft/profile/:uuid', (req, res) => {
    const profile = store.getProfile(req.params.uuid);
    if (!profile) return res.status(204).end();
    const unsigned = req.query.unsigned !== 'false';
    res.json(serializeProfile(profile, { includeProperties: true, unsigned }));
  });

  router.post('/api/profiles/minecraft', express.json(), (req, res) => {
    const names = Array.isArray(req.body) ? req.body.slice(0, 10) : [];
    const results = names
      .map(n => store.findProfileByNameLower(String(n).toLowerCase()))
      .filter(Boolean)
      .map(p => serializeProfile(p, { includeProperties: false }));
    res.json(results);
  });

  // ---------------- Texture upload ----------------

  router.put('/api/user/profile/:uuid/:textureType', requireBearer, upload.single('file'), async (req, res) => {
    const { uuid, textureType } = req.params;
    if (!['skin', 'cape'].includes(textureType)) return res.status(404).end();

    const profile = store.getProfile(uuid);
    if (!profile || profile.userId !== req.tokenUser.id) return res.status(401).end();
    if (!req.file) return ygError(res, 400, 'IllegalArgumentException', 'file is required.');

    try {
      const { data, hash } = await processTexture(req.file.buffer, textureType);
      fs.writeFileSync(path.join(config.TEXTURES_DIR, hash), data);
      if (textureType === 'skin') {
        profile.skinHash = hash;
        profile.skinModel = req.body.model === 'slim' ? 'slim' : 'default';
      } else {
        profile.capeHash = hash;
      }
      store.saveProfile(profile);
      res.status(204).end();
    } catch (e) {
      ygError(res, 400, 'IllegalArgumentException', e.message);
    }
  });

  router.delete('/api/user/profile/:uuid/:textureType', requireBearer, (req, res) => {
    const { uuid, textureType } = req.params;
    const profile = store.getProfile(uuid);
    if (!profile || profile.userId !== req.tokenUser.id) return res.status(401).end();
    if (textureType === 'skin') profile.skinHash = null;
    else if (textureType === 'cape') profile.capeHash = null;
    else return res.status(404).end();
    store.saveProfile(profile);
    res.status(204).end();
  });

  return { router, serializeProfile };
}

module.exports = { buildRouter };
