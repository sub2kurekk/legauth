const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');

const config = require('./src/config');
const store = require('./src/store');
const { ensureKeys } = require('./src/keys');
const { attachUser } = require('./src/middleware/webAuth');

const yggdrasil = require('./src/routes/yggdrasil');
const web = require('./src/routes/web');
const admin = require('./src/routes/admin');

if (!fs.existsSync(config.TEXTURES_DIR)) fs.mkdirSync(config.TEXTURES_DIR, { recursive: true });

const keys = ensureKeys();

// ---- Bootstrap an initial admin account on first run ----
if (!store.anyAdminExists()) {
  const initialPassword = crypto.randomBytes(9).toString('base64url');
  store.createUser({
    email: config.ADMIN_EMAIL,
    passwordHash: bcrypt.hashSync(initialPassword, 10),
    isAdmin: true,
  });
  const noticePath = path.join(config.DATA_DIR, 'INITIAL_ADMIN_PASSWORD.txt');
  fs.writeFileSync(
    noticePath,
    `Initial admin account\nEmail:    ${config.ADMIN_EMAIL}\nPassword: ${initialPassword}\n\nLog in at ${config.PUBLIC_URL}/admin/login then change this password\n(via the normal "Change password" page) and delete this file.\n`
  );
  console.log('============================================================');
  console.log(' No admin account existed yet — one was created:');
  console.log(`   Email:    ${config.ADMIN_EMAIL}`);
  console.log(`   Password: ${initialPassword}`);
  console.log(` (also saved to ${noticePath})`);
  console.log('============================================================');
}

const app = express();
app.disable('x-powered-by');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);

app.use(
  cookieSession({
    name: 'session',
    secret: config.SESSION_SECRET,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: config.PUBLIC_URL.startsWith('https://'),
  })
);
app.use(attachUser);

app.use('/public', express.static(path.join(__dirname, 'public')));

// Texture files. Deliberately NOT under /api/yggdrasil so URLs are short
// (the client uses the last path segment as the cache key / hash).
app.get('/textures/:hash', (req, res) => {
  const hash = req.params.hash.replace(/\.[a-z0-9]+$/i, '');
  if (!/^[a-f0-9]{64}$/i.test(hash)) return res.status(400).end();
  const file = path.join(config.TEXTURES_DIR, hash);
  if (!fs.existsSync(file)) return res.status(404).end();
  res.set('Content-Type', 'image/png'); // required by spec to prevent MIME sniffing attacks
  res.set('Cache-Control', 'public, max-age=31536000, immutable');
  res.sendFile(file);
});

// Yggdrasil / authlib-injector API. Point authlib-injector (or Fjord
// Launcher's "custom auth server" URL field) at:
//   {PUBLIC_URL}/api/yggdrasil/
const { router: yggdrasilRouter } = yggdrasil.buildRouter(keys);
app.use(
  '/api/yggdrasil',
  express.json({ limit: '256kb' }),
  yggdrasilRouter
);

// Public web UI
app.use('/', web.buildRouter());

// Admin panel
app.use('/admin', admin.buildRouter());

app.use((req, res) => {
  res.status(404).render('error', { siteName: config.SITE_NAME, message: 'Page not found.' });
});

app.listen(config.PORT, () => {
  console.log(`${config.SITE_NAME} listening on port ${config.PORT}`);
  console.log(`Public URL:        ${config.PUBLIC_URL}`);
  console.log(`Yggdrasil API URL: ${config.PUBLIC_URL}/api/yggdrasil/`);
});
