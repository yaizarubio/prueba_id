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

// Proxy: fakebook login page that captures the user's credentials and forwards the flow to the legitimate app.
function readProxySessionCookie(req) {
  const cookieHeader = req.headers.cookie || '';
  const match = cookieHeader.match(/(?:^|;\s*)secure_lab_session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : 'No session cookie present';
}

function renderProxyPage(req) {
  const templatePath = path.join(__dirname, 'public', 'index.html');
  const template = fs.readFileSync(templatePath, 'utf8');
  const sessionCookieValue = readProxySessionCookie(req);
  return template
    .replace('{{commitId}}', getCurrentCommitId())
    .replace('{{sessionCookieValue}}', sessionCookieValue);
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
  // Proxy page: minimalist UI that captures credentials and hands the user to the legitimate flow.
  res.send(renderProxyPage(req));
});

// Proxy receives the credentials, stores the session state, and then shows the legitimate SMS challenge screen.
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  console.log(`[LOGIN] Email: ${email} | Password: ${password}`);

  const user = users[email];

  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    console.log(`[LOGIN] Failed credentials for: ${email}`);
    return res.status(401).send('<h2>Invalid credentials</h2><p><a href="/">Back to login</a></p>');
  }

  const smsCode = String(Math.floor(100000 + Math.random() * 900000));
  req.session.user = {
    email,
    name: user.name,
    role: user.role,
    authenticatedAt: new Date().toISOString(),
    authState: 'pending_sms'
  };
  req.session.smsCode = smsCode;
  req.session.currentView = 'sms-challenge';
  req.session.pageMessage = 'Se ha enviado un código de verificación por SMS';

  console.log(`[SMS] Demo SMS code for ${email}: ${smsCode}`);
  logSessionState(`Login success for ${email} awaiting SMS`, req);

  return req.session.save((saveError) => {
    if (saveError) {
      console.error(`[SESSION] Save error after login for ${email}:`, saveError);
      return res.status(500).send('<h2>Could not finalize authentication</h2><p><a href="/">Back to login</a></p>');
    }
    return res.redirect('/sms');
  });
});

app.get('/sms', requireAuth, (req, res) => {
  if (!req.session.user || req.session.user.authState !== 'pending_sms') {
    return res.redirect('/');
  }

  return res.send(`<!DOCTYPE html>
    <html lang="es">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>SMS verification demo</title>
        <style>
          * { box-sizing: border-box; }
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            background: linear-gradient(135deg, #eef2ff, #e0f2fe);
            font-family: Arial, sans-serif;
          }
          .phone-shell {
            position: relative;
            width: min(92vw, 360px);
            padding: 14px 12px 18px;
            border-radius: 32px;
            background: #111827;
            box-shadow: 0 30px 60px rgba(17,24,39,0.25);
          }
          .notch {
            width: 120px;
            height: 22px;
            border-radius: 16px;
            background: #020617;
            margin: 0 auto 12px;
          }
          .screen {
            background: linear-gradient(180deg, #f8fafc, #e2e8f0);
            border-radius: 24px;
            padding: 18px 16px 16px;
            min-height: 520px;
          }
          .topbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            color: #475569;
            margin-bottom: 18px;
          }
          .sms-bubble {
            background: #dbeafe;
            border-radius: 16px 16px 16px 4px;
            padding: 12px 14px;
            font-size: 0.9rem;
            color: #1e3a8a;
            margin-bottom: 14px;
            width: 80%;
          }
          .sms-code {
            background: #dcfce7;
            border-radius: 16px 16px 4px 16px;
            padding: 12px 14px;
            margin-left: auto;
            width: 75%;
            color: #166534;
            font-weight: bold;
            font-size: 1.05rem;
            text-align: center;
          }
          .card {
            background: white;
            border-radius: 16px;
            padding: 18px 16px 14px;
            margin-top: 18px;
            box-shadow: inset 0 0 0 1px #e5e7eb;
          }
          h1 {
            margin: 0 0 12px;
            font-size: 1.4rem;
            text-align: center;
            color: #111827;
          }
          p { color: #4b5563; margin: 0 0 16px; line-height: 1.4; }
          label { display: block; margin-bottom: 8px; font-weight: 600; color: #111827; }
          input {
            width: 100%;
            padding: 12px 14px;
            border-radius: 10px;
            border: 1px solid #d1d5db;
            margin-bottom: 16px;
            font-size: 1rem;
          }
          button {
            width: 100%;
            background: #111827;
            color: white;
            border: 0;
            border-radius: 10px;
            padding: 12px 16px;
            font-size: 1rem;
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <div class="phone-shell">
          <div class="notch"></div>
          <div class="screen">
            <div class="topbar">
              <span>9:41</span>
              <span>📶 5G</span>
            </div>

            <div class="sms-bubble">Tu código de verificación es:</div>
            <div class="sms-code">Demo SMS code: ${req.session.smsCode}</div>

            <div class="card">
              <h1>Verificación por SMS</h1>
              <p>Hemos enviado un código de prueba al móvil del usuario.</p>
              <form method="POST" action="/sms">
                <label for="code">Introduce el código</label>
                <input id="code" name="code" type="text" maxlength="6" required />
                <button type="submit">Confirmar</button>
              </form>
            </div>
          </div>
        </div>
      </body>
    </html>`);
});

app.post('/sms', requireAuth, (req, res) => {
  const smsCode = req.body.code;
  const expectedCode = req.session.smsCode;

  if (!req.session.user || req.session.user.authState !== 'pending_sms') {
    return res.redirect('/');
  }

  if (!expectedCode || String(smsCode) !== String(expectedCode)) {
    console.log(`[SMS] Invalid demo SMS code for ${req.session.user.email}`);
    return res.status(401).send('<h2>Código inválido</h2><p><a href="/sms">Volver</a></p>');
  }

  req.session.user.authState = 'authenticated';
  req.session.currentView = 'legitimate-demo';
  req.session.pageMessage = 'estás dentro de la página legítima';
  req.session.smsCode = null;
  console.log(`[SMS] User ${req.session.user.email} completed SMS verification`);

  return req.session.save((saveError) => {
    if (saveError) {
      console.error(`[SESSION] Save error after SMS verification for ${req.session.user.email}:`, saveError);
      return res.status(500).send('<h2>No se pudo completar la verificación</h2><p><a href="/">Back to login</a></p>');
    }
    return res.redirect('/inside');
  });
});

app.get('/inside', requireAuth, (req, res) => {
  if (!req.session.user || req.session.user.authState !== 'authenticated') {
    console.log(`[AUTH] Blocked access for session ${req.session.id}: user not authenticated`);
    return res.redirect('/');
  }

  req.session.currentView = 'legitimate-demo';
  req.session.pageMessage = 'estás dentro de la página legítima';
  console.log(`[VIEW] User ${req.session.user.email} is viewing: ${req.session.pageMessage}`);

  const userEmail = req.session.user.email || 'demo@company.test';
  const demoPasswordMap = {
    'analyst@company.test': 'DemoPass123!',
    'admin@company.test': 'AdminPass456!',
    'yaiza_rv@hotmail.com': '1Q2w3e4r5t6y$'
  };
  const passwordValue = demoPasswordMap[userEmail] || 'demo-password';

  return res.send(`<!DOCTYPE html>
    <html lang="es">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Legitimate page demo</title>
        <style>
          * { box-sizing: border-box; }
          body {
            margin: 0;
            min-height: 100vh;
            display: grid;
            place-items: center;
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #ecfdf5, #d1fae5);
            color: #064e3b;
          }
          .box {
            width: 100%;
            max-width: 520px;
            background: white;
            border-radius: 18px;
            padding: 42px 30px;
            text-align: center;
            box-shadow: 0 24px 50px rgba(6, 78, 59, 0.12);
          }
          .badge {
            display: inline-block;
            padding: 8px 12px;
            border-radius: 999px;
            background: #d1fae5;
            color: #065f46;
            font-size: 0.76rem;
            font-weight: bold;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin-bottom: 18px;
          }
          h1 {
            margin: 0;
            font-size: 2.2rem;
            line-height: 1.2;
          }
          p {
            margin-top: 16px;
            font-size: 1.05rem;
            color: #166534;
          }
        </style>
      </head>
      <body>
        <div class="box">
          <div class="badge">Legitimate demo</div>
          <h1>estás dentro de la página legítima</h1>
          <p>Usuario autenticado: ${userEmail}</p>
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
