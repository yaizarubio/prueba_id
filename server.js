const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const { execSync } = require('child_process');
const QRCode = require('qrcode');
const { generateTotpSecret, getDemoMfaSecret, verifyTotp, getOtpAuthUrl } = require('./auth');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';

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
  console.log(`[LOGIN] Email: ${email} | Password: [redacted]`);

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

  return res.redirect('/dashboard');
});

app.get('/dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.listen(PORT, () => {
  console.log(`Secure auth lab listening on http://localhost:${PORT}`);
});
