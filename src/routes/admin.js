const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const config = require('../config');
const store = require('../store');
const { offlineUuid } = require('../util/uuid');
const { requireAdmin } = require('../middleware/adminAuth');

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

  router.get('/login', (req, res) => {
    if (req.currentUser && req.currentUser.isAdmin) return res.redirect('/admin');
    render(req, res, 'admin/login');
  });

  router.post('/login', loginLimiter, (req, res) => {
    const { email, password } = req.body;
    const user = store.findUserByEmail(String(email || '').toLowerCase());
    if (!user || !user.isAdmin || !bcrypt.compareSync(password || '', user.passwordHash)) {
      return render(req, res, 'admin/login', { error: 'Incorrect e-mail address or password, or this account is not an admin.' });
    }
    req.session.userId = user.id;
    res.redirect('/admin');
  });

  router.post('/logout', (req, res) => {
    req.session = null;
    res.redirect('/admin/login');
  });

  router.use(requireAdmin);

  router.get('/', (req, res) => {
    const users = store.listUsers().map(u => ({
      ...u,
      profiles: store.getProfilesByUser(u.id),
    }));
    render(req, res, 'admin/dashboard', { users });
  });

  // Admin directly creates a new account (no e-mail verification / self
  // registration needed) — this is the "create other accounts from the
  // same admin login" feature.
  router.post('/users/create', (req, res) => {
    const users = () => store.listUsers().map(u => ({ ...u, profiles: store.getProfilesByUser(u.id) }));

    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const profileName = String(req.body.profileName || '').trim();
    const makeAdmin = req.body.isAdmin === 'on';

    if (!email || !/^\S+@\S+\.\S+$/.test(email)) {
      return render(req, res, 'admin/dashboard', { users: users(), error: 'Please enter a valid e-mail address.' });
    }
    if (store.findUserByEmail(email)) {
      return render(req, res, 'admin/dashboard', { users: users(), error: 'An account with that e-mail already exists.' });
    }
    if (!password || password.length < 8) {
      return render(req, res, 'admin/dashboard', { users: users(), error: 'Password must be at least 8 characters.' });
    }
    if (profileName && !NAME_RE.test(profileName)) {
      return render(req, res, 'admin/dashboard', { users: users(), error: 'Profile name must be 3-16 characters: letters, numbers, underscores.' });
    }
    if (profileName && store.findProfileByNameLower(profileName.toLowerCase())) {
      return render(req, res, 'admin/dashboard', { users: users(), error: 'That profile name is already taken.' });
    }

    const newUser = store.createUser({
      email,
      passwordHash: bcrypt.hashSync(password, 10),
      isAdmin: makeAdmin,
      createdByAdminId: req.currentUser.id,
    });

    if (profileName) {
      store.createProfile({ uuid: offlineUuid(profileName), userId: newUser.id, name: profileName });
    }

    render(req, res, 'admin/dashboard', { users: users(), notice: `Account ${email} created.` });
  });

  router.post('/users/:id/reset-password', (req, res) => {
    const target = store.getUser(req.params.id);
    if (!target) return res.redirect('/admin');
    const newPassword = crypto.randomBytes(9).toString('base64url');
    target.passwordHash = bcrypt.hashSync(newPassword, 10);
    store.saveUser(target);
    store.invalidateAllUserTokens(target.id);
    const users = store.listUsers().map(u => ({ ...u, profiles: store.getProfilesByUser(u.id) }));
    render(req, res, 'admin/dashboard', { users, notice: `New password for ${target.email}: ${newPassword} (shown once — share it securely).` });
  });

  router.post('/users/:id/toggle-admin', (req, res) => {
    const target = store.getUser(req.params.id);
    if (target) {
      if (target.id === req.currentUser.id && target.isAdmin) {
        // don't allow removing your own last admin flag by accident via this route
        const otherAdmins = store.listUsers().filter(u => u.isAdmin && u.id !== target.id);
        if (otherAdmins.length === 0) {
          const users = store.listUsers().map(u => ({ ...u, profiles: store.getProfilesByUser(u.id) }));
          return render(req, res, 'admin/dashboard', { users, error: 'You cannot remove admin rights from the only remaining admin account.' });
        }
      }
      target.isAdmin = !target.isAdmin;
      store.saveUser(target);
    }
    res.redirect('/admin');
  });

  router.post('/users/:id/delete', (req, res) => {
    const target = store.getUser(req.params.id);
    if (target) {
      if (target.isAdmin) {
        const otherAdmins = store.listUsers().filter(u => u.isAdmin && u.id !== target.id);
        if (otherAdmins.length === 0) {
          const users = store.listUsers().map(u => ({ ...u, profiles: store.getProfilesByUser(u.id) }));
          return render(req, res, 'admin/dashboard', { users, error: 'You cannot delete the only remaining admin account.' });
        }
      }
      store.deleteUser(target.id);
    }
    res.redirect('/admin');
  });

  return router;
}

module.exports = { buildRouter };
