const express = require('express');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const MFA_CODE = process.env.MFA_CODE || '123456';

const users = {
  'analyst@company.test': {
    password: 'DemoPass123!',
    name: 'Security Analyst',
    mfa: true,
    role: 'Security Analyst'
  },
  'admin@company.test': {
    password: 'AdminPass456!',
    name: 'Security Admin',
    mfa: true,
    role: 'Security Admin'
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
      secure: false,
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

app.get('/health', (req, res) => {
  res.json({ status: 'ok', app: 'secure-auth-lab' });
});

app.get('/', (req, res) => {
  if (req.session.user) {
    return res.redirect('/dashboard');
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = users[email];

  if (!user || user.password !== password) {
    return res.status(401).send('<h2>Invalid credentials</h2><p><a href="/">Back to login</a></p>');
  }

  req.session.pendingUser = {
    email,
    name: user.name,
    role: user.role,
    mfa: user.mfa
  };

  if (user.mfa) {
    return res.sendFile(path.join(__dirname, 'public', 'mfa.html'));
  }

  req.session.user = { email, name: user.name, role: user.role };
  return res.redirect('/dashboard');
});

app.post('/mfa', (req, res) => {
  const pendingUser = req.session.pendingUser;
  const code = req.body.code;

  if (!pendingUser) {
    return res.redirect('/');
  }

  if (code !== MFA_CODE) {
    return res.status(401).send('<h2>Invalid MFA code</h2><p><a href="/">Back to login</a></p>');
  }

  req.session.user = {
    email: pendingUser.email,
    name: pendingUser.name,
    role: pendingUser.role
  };
  req.session.pendingUser = null;

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
