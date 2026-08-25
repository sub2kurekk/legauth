const express = require('express');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const config = require('../config');
const store = require('../store');
const { offlineUuid, dashUuid } = require('../util/uuid');
const { processTexture } = require('../util/textures');
const { requireLogin } = require('../middleware/webAuth');

const upload = multer({ storage: multer.memoryStorage() });
const NAME_RE = /^[A-Za-z0-9_]{3,16}$/;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

function buildRouter() {
  const router = express.Router();

  router.use(express.urlencoded({ extended: false }));

  function render(req, res, view, locals = {}) {
    res.render(view, { siteName: config.SITE_NAME, error: null, notice: null, ...locals });
  }

  // ---------------- Home ----------------

  router.get('/', (req, res) => {
    // ALI (API Address Indication) lets authlib-injector auto-discover the
    // real Yggdrasil API root just from this domain.
    res.set('X-Authlib-Injector-API-Location', '/api/yggdrasil/');
    if (req.currentUser) return res.redirect('/account');
    res.redirect('/login');
  });

  // ---------------- Login / logout ----------------

  router.get('/login', (req, res) => {
    if (req.currentUser) return res.redirect('/account');
    render(req, res, 'login', { notice: req.query.registered ? 'Account created. You can log in now.' : null });
  });

  router.post('/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;
    const user = store.findUserByEmail(String(email || '').toLowerCase());
    if (!user || !bcrypt.compareSync(password || '', user.passwordHash)) {
      return render(req, res, 'login', { error: 'Incorrect e-mail address or password.' });
    }
    req.session.userId = user.id;
    res.redirect('/account');
  });

  router.post('/logout', (req, res) => {
    req.session = null;
    res.redirect('/login');
  });

  // ---------------- Registration ----------------

  router.get('/register', (req, res) => {
    if (!config.ALLOW_REGISTRATION) return res.status(403).render('error', { siteName: config.SITE_NAME, message: 'Registration is currently disabled on this server.' });
    if (req.currentUser) return res.redirect('/account');
    render(req, res, 'register');
  });

  router.post('/register', loginLimiter, (req, res) => {
    if (!config.ALLOW_REGISTRATION) return res.status(403).render('error', { siteName: config.SITE_NAME, message: 'Registration is currently disabled on this server.' });
    const { email, password, passwordConfirm } = req.body;
    const emailLower = String(email || '').trim().toLowerCase();
    if (!emailLower || !/^\S+@\S+\.\S+$/.test(emailLower)) {
      return render(req, res, 'register', { error: 'Please enter a valid e-mail address.' });
    }
    if (!password || password.length < 8) {
      return render(req, res, 'register', { error: 'Password must be at least 8 characters long.' });
    }
    if (password !== passwordConfirm) {
      return render(req, res, 'register', { error: 'Passwords do not match.' });
    }
    if (store.findUserByEmail(emailLower)) {
      return render(req, res, 'register', { error: 'An account with that e-mail address already exists.' });
    }
    store.createUser({ email: emailLower, passwordHash: bcrypt.hashSync(password, 10) });
    res.redirect('/login?registered=1');
  });

  // ---------------- Account page ----------------

  router.get('/account', requireLogin, (req, res) => {
    const profiles = store.getProfilesByUser(req.currentUser.id);
    render(req, res, 'account', {
      profiles,
      dashUuid,
      publicUrl: config.PUBLIC_URL,
    });
  });

  router.get('/account/password', requireLogin, (req, res) => {
    render(req, res, 'password');
  });

  router.post('/account/password', requireLogin, (req, res) => {
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;
    if (!bcrypt.compareSync(currentPassword || '', req.currentUser.passwordHash)) {
      return render(req, res, 'password', { error: 'Current password is incorrect.' });
    }
    if (!newPassword || newPassword.length < 8) {
      return render(req, res, 'password', { error: 'New password must be at least 8 characters long.' });
    }
    if (newPassword !== newPasswordConfirm) {
      return render(req, res, 'password', { error: 'New passwords do not match.' });
    }
    req.currentUser.passwordHash = bcrypt.hashSync(newPassword, 10);
    store.saveUser(req.currentUser);
    store.invalidateAllUserTokens(req.currentUser.id);
    render(req, res, 'password', { notice: 'Password changed. You have been logged out of all game sessions.' });
  });

  // ---------------- Choose / change profile name ----------------

  router.get('/account/choose-name', requireLogin, (req, res) => {
    const profiles = store.getProfilesByUser(req.currentUser.id);
    if (profiles.length > 0) return res.redirect('/account');
    render(req, res, 'choose-name');
  });

  router.post('/account/choose-name', requireLogin, (req, res) => {
    const profiles = store.getProfilesByUser(req.currentUser.id);
    if (profiles.length > 0) return res.redirect('/account');

    const name = String(req.body.name || '').trim();
    if (!NAME_RE.test(name)) {
      return render(req, res, 'choose-name', { error: 'Names must be 3-16 characters: letters, numbers and underscores only.', name });
    }
    if (store.findProfileByNameLower(name.toLowerCase())) {
      return render(req, res, 'choose-name', { error: 'That name is already taken.', name });
    }
    const uuid = offlineUuid(name);
    if (store.getProfile(uuid)) {
      return render(req, res, 'choose-name', { error: 'That name is already taken.', name });
    }
    store.createProfile({ uuid, userId: req.currentUser.id, name });
    res.redirect('/account');
  });

  router.get('/account/change-name/:uuid', requireLogin, (req, res) => {
    const profile = store.getProfile(req.params.uuid);
    if (!profile || profile.userId !== req.currentUser.id) return res.status(404).render('error', { siteName: config.SITE_NAME, message: 'Profile not found.' });
    render(req, res, 'change-name', { profile });
  });

  router.post('/account/change-name/:uuid', requireLogin, (req, res) => {
    const profile = store.getProfile(req.params.uuid);
    if (!profile || profile.userId !== req.currentUser.id) return res.status(404).render('error', { siteName: config.SITE_NAME, message: 'Profile not found.' });

    if (profile.nameChangedAt && Date.now() - profile.nameChangedAt < config.NAME_CHANGE_COOLDOWN_MS) {
      const hoursLeft = Math.ceil((config.NAME_CHANGE_COOLDOWN_MS - (Date.now() - profile.nameChangedAt)) / 3600000);
      return render(req, res, 'change-name', { profile, error: `You can change your name again in about ${hoursLeft}h.` });
    }

    const name = String(req.body.name || '').trim();
    if (!NAME_RE.test(name)) {
      return render(req, res, 'change-name', { profile, error: 'Names must be 3-16 characters: letters, numbers and underscores only.' });
    }
    const existing = store.findProfileByNameLower(name.toLowerCase());
    if (existing && existing.uuid !== profile.uuid) {
      return render(req, res, 'change-name', { profile, error: 'That name is already taken.' });
    }

    profile.name = name;
    profile.nameChangedAt = Date.now();
    store.saveProfile(profile);
    res.redirect('/account');
  });

  // ---------------- Skin / cape upload ----------------

  router.get('/account/skin/:uuid', requireLogin, (req, res) => {
    const profile = store.getProfile(req.params.uuid);
    if (!profile || profile.userId !== req.currentUser.id) return res.status(404).render('error', { siteName: config.SITE_NAME, message: 'Profile not found.' });
    render(req, res, 'skin', { profile, publicUrl: config.PUBLIC_URL });
  });

  router.post('/account/skin/:uuid', requireLogin, upload.fields([{ name: 'skin', maxCount: 1 }, { name: 'cape', maxCount: 1 }]), async (req, res) => {
    const profile = store.getProfile(req.params.uuid);
    if (!profile || profile.userId !== req.currentUser.id) return res.status(404).render('error', { siteName: config.SITE_NAME, message: 'Profile not found.' });

    try {
      const skinFile = req.files?.skin?.[0];
      const capeFile = req.files?.cape?.[0];

      if (skinFile) {
        const { data, hash } = await processTexture(skinFile.buffer, 'skin');
        fs.writeFileSync(path.join(config.TEXTURES_DIR, hash), data);
        profile.skinHash = hash;
        profile.skinModel = req.body.model === 'slim' ? 'slim' : 'default';
      }
      if (capeFile) {
        const { data, hash } = await processTexture(capeFile.buffer, 'cape');
        fs.writeFileSync(path.join(config.TEXTURES_DIR, hash), data);
        profile.capeHash = hash;
      }
      store.saveProfile(profile);
      render(req, res, 'skin', { profile, publicUrl: config.PUBLIC_URL, notice: 'Texture updated.' });
    } catch (e) {
      render(req, res, 'skin', { profile, publicUrl: config.PUBLIC_URL, error: e.message });
    }
  });

  router.post('/account/skin/:uuid/clear/:type', requireLogin, (req, res) => {
    const profile = store.getProfile(req.params.uuid);
    if (!profile || profile.userId !== req.currentUser.id) return res.status(404).render('error', { siteName: config.SITE_NAME, message: 'Profile not found.' });
    if (req.params.type === 'skin') profile.skinHash = null;
    else if (req.params.type === 'cape') profile.capeHash = null;
    store.saveProfile(profile);
    res.redirect(`/account/skin/${profile.uuid}`);
  });

  // ---------------- Registered servers (lightweight "server hosting" directory) ----------------

  router.get('/servers', requireLogin, (req, res) => {
    render(req, res, 'servers', {
      myServers: store.listServersByUser(req.currentUser.id),
      allServers: store.listServers(),
    });
  });

  router.post('/servers', requireLogin, (req, res) => {
    const name = String(req.body.name || '').trim().slice(0, 64);
    const address = String(req.body.address || '').trim().slice(0, 128);
    if (name && address) {
      store.createServer({ userId: req.currentUser.id, name, address });
    }
    res.redirect('/servers');
  });

  router.post('/servers/:id/delete', requireLogin, (req, res) => {
    store.deleteServer(req.params.id, req.currentUser.id);
    res.redirect('/servers');
  });

  return router;
}

module.exports = { buildRouter };
