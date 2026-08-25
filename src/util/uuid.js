const crypto = require('crypto');

// Same algorithm Minecraft itself uses for offline-mode UUIDs:
// UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(UTF_8))
// Using it here means a server can switch between offline mode and this
// auth server (or back) without players losing their world data/stats,
// as recommended by the authlib-injector server spec.
function offlineUuid(name) {
  const hash = crypto.createHash('md5').update('OfflinePlayer:' + name, 'utf8').digest();
  hash[6] = (hash[6] & 0x0f) | 0x30; // version 3
  hash[8] = (hash[8] & 0x3f) | 0x80; // variant
  return hash.toString('hex'); // unsigned (undashed) UUID
}

function dashUuid(u) {
  return `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;
}

module.exports = { offlineUuid, dashUuid };
