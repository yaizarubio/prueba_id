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
    assert.equal(loginResponse.headers.get('location'), '/inside');
    const sessionCookie = loginResponse.headers.get('set-cookie')?.split(';')[0];
    assert.ok(sessionCookie, 'Expected a session cookie after login');

    const dashboardResponse = await fetch(`${baseUrl}/dashboard`, {
      headers: {
        Cookie: sessionCookie
      },
      redirect: 'manual'
    });

    assert.equal(dashboardResponse.status, 200);

    const authUrl = `${baseUrl}/oauth/authorize?client_id=demo-client&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&response_type=code&scope=openid%20profile&state=demo-state`;
    const authResponse = await fetch(authUrl, {
      headers: {
        Cookie: sessionCookie
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
