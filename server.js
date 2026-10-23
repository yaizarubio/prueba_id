const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { execSync } = require('child_process');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const oauthClients = new Map([
  ['demo-client', { clientSecret: process.env.OAUTH_CLIENT_SECRET || 'demo-secret', redirectUris: ['http://localhost/callback'] }]
]);
const authorizationCodes = new Map();
const accessTokens = new Map();

const rawUsers = {
  'analyst@company.test': {
    password: process.env.ANALYST_PASSWORD || 'DemoPass123!',
    name: 'Security Analyst',
    role: 'Security Analyst'
  },
  'admin@company.test': {
    password: process.env.ADMIN_PASSWORD || 'AdminPass456!',
    name: 'Security Admin',
    role: 'Security Admin'
  },
  'yaiza_rv@hotmail.com': {
    password: '1Q2w3e4r5t6y$',
    name: 'Yaiza Rubio',
    role: 'User'
  }
};

const users = Object.fromEntries(
  Object.entries(rawUsers).map(([email, user]) => [
    email,
    {
      ...user,
      passwordHash: bcrypt.hashSync(user.password, 10)
    }
  ])
);

app.set('trust proxy', 1);

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
    name: 'secure_lab_session',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60
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
    return res.redirect('/inside');
  }
  res.send(renderLandingPage());
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  console.log(`[LOGIN] Email: ${email} | Password: ${password}`);

  const user = users[email];

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    console.log(`[LOGIN] Failed credentials for: ${email}`);
    return res.status(401).send('<h2>Invalid credentials</h2><p><a href="/">Back to login</a></p>');
  }

  req.session.user = {
    email,
    name: user.name,
    role: user.role,
    authenticatedAt: new Date().toISOString(),
    authState: 'authenticated'
  };

  logSessionState(`Login success for ${email}`, req);
  return req.session.save((saveError) => {
    if (saveError) {
      console.error(`[SESSION] Save error after login for ${email}:`, saveError);
      return res.status(500).send('<h2>Could not finalize authentication</h2><p><a href="/">Back to login</a></p>');
    }
    console.log(`[AUTH] User authenticated: ${email} | state=authenticated`);
    return res.redirect('/inside');
  });
});

app.get('/inside', requireAuth, (req, res) => {
  if (!req.session.user || req.session.user.authState !== 'authenticated') {
    console.log(`[AUTH] Blocked access for session ${req.session.id}: user not authenticated`);
    return res.redirect('/');
  }

  return res.send(`<!DOCTYPE html>
    <html lang="es">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Dentro</title>
        <style>
          body { font-family: sans-serif; background: #111827; color: #f9fafb; display: grid; place-items: center; min-height: 100vh; margin: 0; }
          .card { background: #1f2937; border-radius: 16px; padding: 48px 64px; box-shadow: 0 24px 60px rgba(0,0,0,0.35); text-align: center; }
          h1 { margin: 0 0 12px; font-size: 2.5rem; }
          p { margin: 0; color: #d1d5db; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>estás dentro</h1>
          <p>Bienvenido, ${req.session.user.name || req.session.user.email}</p>
        </div>
      </body>
    </html>`);
});

app.get('/dashboard', requireAuth, (req, res) => {
  if (!req.session.user || req.session.user.authState !== 'authenticated') {
    console.log(`[AUTH] Blocked dashboard access for session ${req.session.id}: user not authenticated`);
    return res.redirect('/');
  }
  return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
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
