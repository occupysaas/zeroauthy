// The AD/LDAP Connector's own mock LDAP server (auth0/ad-ldap-connector
// v8.0.5, mock-ldap/mock-ldap-server.js and its data), run unchanged inside
// the connector's container (make e2e-ad, Plan 38a). Two handlers are
// added because the mock has none: an anonymous bind (the connector's
// heartbeat binds anonymously with ANONYMOUS_SEARCH_ENABLED) and modify of
// userPassword (the connector's change_password with ENABLE_WRITE_BACK).
'use strict';
const root = process.argv[2] || '/work';
const ldap = require(`${root}/node_modules/ldapjs`);
const db = require(`${root}/mock-ldap/mock_ldap_data.json`);
const { createServer } = require(`${root}/mock-ldap/mock-ldap-server.js`);
const BASE_DN = 'dc=example,dc=org';
const server = createServer();
server.bind('', function (req, res, next) {
  const dn = req.dn.format({ skipSpace: true });
  if (!req.credentials) {
    if (dn !== '') return next(new ldap.InvalidCredentialsError());
    res.end();
    return next();
  }
  const entry = db[dn];
  if (!entry) return next(new ldap.NoSuchObjectError(dn));
  if (entry.userPassword !== req.credentials) return next(new ldap.InvalidCredentialsError());
  res.end();
  return next();
});
server.modify(BASE_DN, function (req, res, next) {
  const dn = req.dn.format({ skipSpace: true });
  if (!db[dn]) return next(new ldap.NoSuchObjectError(dn));
  for (const change of req.changes) {
    const mod = change.modification;
    if (change.operation === 'replace' && mod && String(mod.type).toLowerCase() === 'userpassword') {
      db[dn].userPassword = String(mod.vals[0]);
    } else {
      return next(new ldap.UnwillingToPerformError('only userPassword replace is supported'));
    }
  }
  console.log('mock-ldap: password changed for ' + dn);
  res.end();
  return next();
});
server.listen(4444, '127.0.0.1', function () {
  console.log('mock-ldap: listening on 4444');
});
