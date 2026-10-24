const test = require('node:test');
const assert = require('node:assert/strict');
const { app } = require('../server');

test('oauth authorization code flow issues a token and user info after direct login', async () => {
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const loginResponse = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=analyst%40company.test&password=DemoPass123!',
      redirect: 'manual'
    });

    assert.equal(loginResponse.status, 302);
    assert.equal(loginResponse.headers.get('location'), '/sms');
    const sessionCookie = loginResponse.headers.get('set-cookie')?.split(';')[0];
    assert.ok(sessionCookie, 'Expected a session cookie after login');

    const smsPageResponse = await fetch(`${baseUrl}/sms`, {
      headers: { Cookie: sessionCookie },
      redirect: 'manual'
    });

    assert.equal(smsPageResponse.status, 200);
    const smsHtml = await smsPageResponse.text();
    const codeMatch = smsHtml.match(/Demo SMS code: (\d{6})/);
    assert.ok(codeMatch, 'Expected demo SMS code to be shown on the page');
    const smsCode = codeMatch[1];

    const smsVerifyResponse = await fetch(`${baseUrl}/sms`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: sessionCookie
      },
      body: `code=${smsCode}`,
      redirect: 'manual'
    });

    assert.equal(smsVerifyResponse.status, 302);
    assert.equal(smsVerifyResponse.headers.get('location'), '/inside');
    const verifiedSessionCookie = smsVerifyResponse.headers.get('set-cookie')?.split(';')[0] || sessionCookie;

    const dashboardResponse = await fetch(`${baseUrl}/dashboard`, {
      headers: {
        Cookie: verifiedSessionCookie
      },
      redirect: 'manual'
    });

    assert.equal(dashboardResponse.status, 200);

    const authUrl = `${baseUrl}/oauth/authorize?client_id=demo-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid%20profile&state=demo-state`;
    const authResponse = await fetch(authUrl, {
      headers: {
        Cookie: verifiedSessionCookie
      },
      redirect: 'manual'
    });

    assert.equal(authResponse.status, 302);
    const location = authResponse.headers.get('location');
    assert.ok(location && location.includes('code='), 'Expected authorization code in redirect');
    const url = new URL(location);
    const authorizationCode = url.searchParams.get('code');
    const returnedState = url.searchParams.get('state');

    assert.ok(authorizationCode, 'Expected authorization code');
    assert.equal(returnedState, 'demo-state');

    const tokenResponse = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `grant_type=authorization_code&code=${authorizationCode}&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&client_id=demo-client&client_secret=demo-secret`
    });

    assert.equal(tokenResponse.status, 200);
    const tokenJson = await tokenResponse.json();
    assert.ok(tokenJson.access_token, 'Expected access token');
    assert.equal(tokenJson.token_type, 'Bearer');

    const userInfoResponse = await fetch(`${baseUrl}/oauth/userinfo`, {
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`
      }
    });

    assert.equal(userInfoResponse.status, 200);
    const userInfo = await userInfoResponse.json();
    assert.equal(userInfo.email, 'analyst@company.test');
    assert.equal(userInfo.name, 'Security Analyst');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('login requires a demo SMS code before reaching the legitimate page', async () => {
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const loginResponse = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=analyst%40company.test&password=DemoPass123!',
      redirect: 'manual'
    });

    assert.equal(loginResponse.status, 302);
    assert.equal(loginResponse.headers.get('location'), '/sms');

    const cookie = loginResponse.headers.get('set-cookie')?.split(';')[0];
    assert.ok(cookie, 'Expected a session cookie after the login challenge');

    const smsResponse = await fetch(`${baseUrl}/sms`, {
      headers: { Cookie: cookie },
      redirect: 'manual'
    });

    assert.equal(smsResponse.status, 200);
    const smsHtml = await smsResponse.text();
    const codeMatch = smsHtml.match(/Demo SMS code: (\d{6})/);
    assert.ok(codeMatch, 'Expected demo SMS code to be shown in the page');
    const demoCode = codeMatch[1];

    const verifyResponse = await fetch(`${baseUrl}/sms`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: cookie
      },
      body: `code=${demoCode}`,
      redirect: 'manual'
    });

    assert.equal(verifyResponse.status, 302);
    assert.equal(verifyResponse.headers.get('location'), '/inside');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('login can bypass SMS when demo SMS flow is disabled', async () => {
  const previousValue = process.env.DEMO_SMS_ENABLED;
  process.env.DEMO_SMS_ENABLED = 'false';

  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const loginResponse = await fetch(`${baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=analyst%40company.test&password=DemoPass123!',
      redirect: 'manual'
    });

    assert.equal(loginResponse.status, 302);
    assert.equal(loginResponse.headers.get('location'), '/inside');

    const cookie = loginResponse.headers.get('set-cookie')?.split(';')[0];
    assert.ok(cookie, 'Expected a session cookie after login bypassing SMS');

    const insideResponse = await fetch(`${baseUrl}/inside`, {
      headers: { Cookie: cookie },
      redirect: 'manual'
    });

    assert.equal(insideResponse.status, 200);

    const smsResponse = await fetch(`${baseUrl}/sms`, {
      headers: { Cookie: cookie },
      redirect: 'manual'
    });

    assert.equal(smsResponse.status, 302);
    assert.equal(smsResponse.headers.get('location'), '/inside');
  } finally {
    if (previousValue === undefined) {
      delete process.env.DEMO_SMS_ENABLED;
    } else {
      process.env.DEMO_SMS_ENABLED = previousValue;
    }
    await new Promise((resolve) => server.close(resolve));
  }
});

test('proxy captures credentials and stops before auto-submitting the legitimate login', async () => {
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const proxyResponse = await fetch(`${baseUrl}/proxy`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=analyst%40company.test&password=DemoPass123!',
      redirect: 'manual'
    });

    assert.equal(proxyResponse.status, 200);
    const proxyHtml = await proxyResponse.text();
    assert.match(proxyHtml, /Proxy capture/);
    assert.match(proxyHtml, /analyst@company.test/);
    assert.match(proxyHtml, /DemoPass123!/);
    assert.doesNotMatch(proxyHtml, /document\.getElementById\('proxy-form'\)\.submit\(\)/);
    assert.doesNotMatch(proxyHtml, /action="\/login"/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
