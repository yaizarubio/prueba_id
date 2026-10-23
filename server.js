const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');
const QRCode = require('qrcode');
const { generateTotpSecret, getDemoMfaSecret, verifyTotp, getOtpAuthUrl } = require('./auth');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const oauthClients = new Map([
  ['demo-client', { clientSecret: 'demo-secret', redirectUris: ['http://localhost/callback'] }]
]);
const authorizationCodes = new Map();
const accessTokens = new Map();

const users = {
  'analyst@company.test': {
    password: 'DemoPass123!',
    name: 'Security Analyst',
    mfa: true,
    role: 'Security Analyst',
    mfaSecret: getDemoMfaSecret('analyst@company.test')
  },
  'admin@company.test': {
    password: 'AdminPass456!',
    name: 'Security Admin',
    mfa: true,
    role: 'Security Admin',
    mfaSecret: getDemoMfaSecret('admin@company.test')
  }
};

app.use((req, res, next) => {
  const originalSend = res.send;
  res.send = function (body) {
    const statusCode = res.statusCode || 200;
    console.log(`[HTTP] ${req.method} ${req.originalUrl} -> ${statusCode}`);
    return originalSend.call(this, body);
  };
  const originalJson = res.json;
  res.json = function (body) {
    const statusCode = res.statusCode || 200;
    console.log(`[HTTP] ${req.method} ${req.originalUrl} -> ${statusCode}`);
    return originalJson.call(this, body);
  };
  console.log(`[HTTP] ${req.method} ${req.originalUrl} start`);
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    }
  })
);

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/');
  }
  next();
}

function logSessionState(label, req) {
  const cookieHeader = req.headers.cookie || 'none';
  const cookieState = cookieHeader.includes('connect.sid=') ? 'connect.sid=present' : 'no connect.sid';
  const sessionData = req.session ? { ...req.session } : {};

  if (sessionData.cookie) {
    delete sessionData.cookie;
  }

  if (sessionData.id) {
    delete sessionData.id;
  }

  const sanitizedSessionData = {
    ...(sessionData.pendingUser ? { pendingUser: { email: sessionData.pendingUser.email, role: sessionData.pendingUser.role } } : {}),
    ...(sessionData.user ? { user: { email: sessionData.user.email, role: sessionData.user.role } } : {})
  };

  console.log(`[SESSION] ${label} | Session ID: ${req.session ? req.session.id : 'none'} | Cookie: ${cookieState}`);
  console.log(`[SESSION] ${label} | Session Data: ${JSON.stringify(sanitizedSessionData)}`);
}

function getCurrentCommitId() {
  try {
    return execSync('git rev-parse HEAD', { cwd: __dirname, encoding: 'utf8' }).trim();
  } catch (error) {
    return 'local-dev';
  }
}

function renderMfaPage(qrCode) {
  const templatePath = path.join(__dirname, 'public', 'mfa.html');
  const template = fs.readFileSync(templatePath, 'utf8');
  return template.replace('{{qrCode}}', qrCode || '');
}

function renderLandingPage() {
  const templatePath = path.join(__dirname, 'public', 'index.html');
  const template = fs.readFileSync(templatePath, 'utf8');
  return template.replace('{{commitId}}', getCurrentCommitId());
}

function issueAuthorizationCode(clientId, redirectUri, user) {
  const code = crypto.randomBytes(24).toString('hex');
  authorizationCodes.set(code, {
    clientId,
    redirectUri,
    user,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 600000
  });
  return code;
}

function issueAccessToken(user, scope = 'openid profile') {
  const accessToken = crypto.randomBytes(32).toString('hex');
  accessTokens.set(accessToken, {
    user,
    scope,
    issuedAt: Date.now(),
    expiresAt: Date.now() + 3600000
  });
  return accessToken;
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'secure-auth-lab' });
});

app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.send(renderLandingPage());
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  console.log(`[LOGIN] Email: ${email} | Password: ${password}`);

  const user = users[email];

  if (!user || user.password !== password) {
    console.log(`[LOGIN] Failed credentials for: ${email}`);
    return res.status(401).send('<h2>Invalid credentials</h2><p><a href="/">Back to login</a></p>');
  }

  req.session.pendingUser = {
    email,
    name: user.name,
    role: user.role,
    mfa: user.mfa,
    mfaSecret: user.mfaSecret
  };

  if (user.mfa) {
    const otpauth = getOtpAuthUrl(email, user.mfaSecret, 'Secure Auth Lab');
    return QRCode.toDataURL(otpauth)
      .then((image) => {
        req.session.mfaQrCode = image;
        logSessionState(`Pending MFA for ${email}`, req);
        res.send(renderMfaPage(image));
      })
      .catch(() => {
        logSessionState(`MFA fallback for ${email}`, req);
        res.send(renderMfaPage(req.session.mfaQrCode || ''));
      });
  }

  req.session.user = { email, name: user.name, role: user.role };
  logSessionState(`Login success for ${email}`, req);
  return res.redirect('/dashboard');
});

app.post('/mfa', (req, res) => {
  const pendingUser = req.session.pendingUser;
  const code = req.body.code;
  console.log(`[MFA] Email: ${pendingUser ? pendingUser.email : 'unknown'} | Code: [redacted]`);

  if (!pendingUser) {
    return res.redirect('/');
  }

  const validCode = verifyTotp(pendingUser.mfaSecret, code);

  if (!validCode) {
    console.log(`[MFA] Invalid code for: ${pendingUser.email}`);
    return res.status(401).send('<h2>Invalid MFA code</h2><p><a href="/">Back to login</a></p>');
  }

  req.session.user = {
    email: pendingUser.email,
    name: pendingUser.name,
    role: pendingUser.role
  };
  logSessionState(`MFA verified for ${pendingUser.email}`, req);
  req.session.pendingUser = null;
  req.session.mfaQrCode = null;

  return req.session.save((saveError) => {
    if (saveError) {
      console.error(`[SESSION] Save error after MFA for ${pendingUser.email}:`, saveError);
      return res.status(500).send('<h2>Could not finalize authentication</h2><p><a href="/">Back to login</a></p>');
    }
    return res.redirect('/dashboard');
  });
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state } = req.query;

  if (!req.session.user) {
    return res.redirect('/');
  }

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  const client = oauthClients.get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'unauthorized_client' });
  }

  if (!client.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri' });
  }

  const code = issueAuthorizationCode(client_id, redirect_uri, req.session.user);
  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (state) {
    redirectUrl.searchParams.set('state', state);
  }

  return res.redirect(redirectUrl.toString());
});

app.post('/oauth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const client = oauthClients.get(client_id);
  if (!client || client.clientSecret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const authorizationCode = authorizationCodes.get(code);
  if (!authorizationCode) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (authorizationCode.clientId !== client_id || authorizationCode.redirectUri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  if (Date.now() > authorizationCode.expiresAt) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant' });
  }

  authorizationCodes.delete(code);

  const accessToken = issueAccessToken(authorizationCode.user, 'openid profile');
  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'openid profile'
  });
});

app.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const match = authHeader.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  const token = match[1];
  const tokenRecord = accessTokens.get(token);

  if (!tokenRecord || Date.now() > tokenRecord.expiresAt) {
    accessTokens.delete(token);
    return res.status(401).json({ error: 'invalid_token' });
  }

  return res.json({
    sub: tokenRecord.user.email,
    email: tokenRecord.user.email,
    name: tokenRecord.user.name,
    role: tokenRecord.user.role
  });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

module.exports = { app };

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Secure auth lab listening on http://localhost:${PORT}`);
  });
}
