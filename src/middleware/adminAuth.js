function requireAdmin(req, res, next) {
  if (!req.currentUser || !req.currentUser.isAdmin) {
    return res.redirect('/admin/login');
  }
  next();
}

module.exports = { requireAdmin };
