const store = require('../store');

function attachUser(req, res, next) {
  req.currentUser = null;
  if (req.session && req.session.userId) {
    const user = store.getUser(req.session.userId);
    if (user) req.currentUser = user;
    else req.session = null;
  }
  res.locals.currentUser = req.currentUser;
  next();
}

function requireLogin(req, res, next) {
  if (!req.currentUser) return res.redirect('/login');
  next();
}

module.exports = { attachUser, requireLogin };
