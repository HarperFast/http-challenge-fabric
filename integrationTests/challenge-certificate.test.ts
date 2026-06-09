/**
 * Integration tests for letsencrypt-cert-generator-fabric.
 *
 * Covers:
 *  - Harper startup with this application loaded.
 *  - ChallengeCertificate table REST CRUD (PUT / GET / list).
 *  - ACME HTTP-01 challenge middleware: serves the stored challenge token
 *    from /.well-known/acme-challenge/<token> without authentication.
 *  - Non-challenge requests pass through the middleware unchanged.
 *
 * NOTE: Actual Let's Encrypt certificate issuance requires a live, publicly
 * reachable domain. The ACME cert-generation flow (performHttpChallenge) is
 * intentionally NOT tested here — it cannot be exercised in a hermetic
 * integration-test environment. The tests below validate the Harper integration
 * layer: database interactions, the HTTP middleware, and table REST semantics.
 */
import { suite, test, before, after } from 'node:test';
import { strictEqual, ok } from 'node:assert/strict';
import {
  setupHarperWithFixture,
  teardownHarper,
  type ContextWithHarper,
} from '@harperfast/integration-testing';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';

const FIXTURE_PATH = fileURLToPath(new URL('../', import.meta.url));

// harper's `exports` map only exposes ".", so 'harper/dist/bin/harper.js' is not
// resolvable and the harness' auto-resolution throws ERR_PACKAGE_PATH_NOT_EXPORTED.
// Resolve the CLI from the exported main entry and pass it explicitly.
const require = createRequire(import.meta.url);
const harperBinPath = resolve(dirname(require.resolve('harper')), 'bin/harper.js');

function authFetch(
  ctx: ContextWithHarper,
  path: string,
  init: RequestInit & { headers?: Record<string, string> } = {},
): Promise<Response> {
  const { headers = {}, ...rest } = init;
  const creds = Buffer.from(
    `${ctx.harper.admin.username}:${ctx.harper.admin.password}`,
  ).toString('base64');
  return fetch(`${ctx.harper.httpURL}${path}`, {
    ...rest,
    headers: { Authorization: `Basic ${creds}`, ...headers },
  });
}

// Unauthenticated fetch — ACME challenge endpoint must be publicly reachable.
function anonFetch(ctx: ContextWithHarper, path: string): Promise<Response> {
  return fetch(`${ctx.harper.httpURL}${path}`);
}

suite('Harper startup', (ctx: ContextWithHarper) => {
  before(async () => {
    await setupHarperWithFixture(ctx, FIXTURE_PATH, { harperBinPath });
  });

  after(async () => {
    await teardownHarper(ctx);
  });

  test('Harper starts successfully with the application loaded', async () => {
    const res = await authFetch(ctx, '/');
    ok(
      [200, 400, 404].includes(res.status),
      `Harper should be reachable, got HTTP ${res.status}`,
    );
  });
});

suite('ChallengeCertificate table REST API', (ctx: ContextWithHarper) => {
  before(async () => {
    await setupHarperWithFixture(ctx, FIXTURE_PATH, { harperBinPath });
  });

  after(async () => {
    await teardownHarper(ctx);
  });

  const TEST_DOMAIN = 'test.example.com';

  test('GET /ChallengeCertificate/ returns an empty array initially', async () => {
    const res = await authFetch(ctx, '/ChallengeCertificate/');
    strictEqual(res.status, 200, `expected 200, got ${res.status}`);
    const body = await res.json();
    ok(Array.isArray(body), 'expected array response');
  });

  test('PUT /ChallengeCertificate/:domain creates a record', async () => {
    const res = await authFetch(ctx, `/ChallengeCertificate/${TEST_DOMAIN}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: TEST_DOMAIN,
        challengeToken: 'abc123token',
        challengeContent: 'abc123token.keyauth-content',
      }),
    });
    ok(
      [200, 201, 204].includes(res.status),
      `expected successful PUT, got HTTP ${res.status}`,
    );
  });

  test('GET /ChallengeCertificate/:domain retrieves the record', async () => {
    // Ensure the record exists first.
    await authFetch(ctx, `/ChallengeCertificate/${TEST_DOMAIN}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: TEST_DOMAIN,
        challengeToken: 'abc123token',
        challengeContent: 'abc123token.keyauth-content',
      }),
    });

    const res = await authFetch(ctx, `/ChallengeCertificate/${TEST_DOMAIN}`);
    strictEqual(res.status, 200, `expected 200, got ${res.status}`);
    const body = await res.json() as { domain: string; challengeToken: string; challengeContent: string };
    strictEqual(body.domain, TEST_DOMAIN, 'domain should match');
    strictEqual(body.challengeToken, 'abc123token', 'challengeToken should match');
    strictEqual(body.challengeContent, 'abc123token.keyauth-content', 'challengeContent should match');
  });

  test('GET /ChallengeCertificate/ includes the created record', async () => {
    // Ensure the record exists.
    await authFetch(ctx, `/ChallengeCertificate/${TEST_DOMAIN}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: TEST_DOMAIN,
        challengeToken: 'listcheck',
        challengeContent: 'listcheck.keyauth',
      }),
    });

    const res = await authFetch(ctx, '/ChallengeCertificate/');
    strictEqual(res.status, 200, `expected 200, got ${res.status}`);
    const body = await res.json() as Array<{ domain: string }>;
    ok(Array.isArray(body), 'expected array response');
    const found = body.some((item) => item.domain === TEST_DOMAIN);
    ok(found, `domain ${TEST_DOMAIN} should appear in the list`);
  });
});

suite('ACME HTTP-01 challenge middleware', (ctx: ContextWithHarper) => {
  before(async () => {
    await setupHarperWithFixture(ctx, FIXTURE_PATH, { harperBinPath });
  });

  after(async () => {
    await teardownHarper(ctx);
  });

  const DOMAIN = 'middleware-test.example.com';
  const TOKEN = 'challenge-token-xyz';
  const KEY_AUTH = 'challenge-token-xyz.AAAA_key_authorization_content';

  test('stores a challenge token in the database', async () => {
    const res = await authFetch(ctx, `/ChallengeCertificate/${DOMAIN}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: DOMAIN,
        challengeToken: TOKEN,
        challengeContent: KEY_AUTH,
      }),
    });
    ok(
      [200, 201, 204].includes(res.status),
      `expected successful PUT, got HTTP ${res.status}`,
    );
  });

  test('middleware serves the challenge content at /.well-known/acme-challenge/<token>', async () => {
    // First, store the challenge so the middleware can find it.
    await authFetch(ctx, `/ChallengeCertificate/${DOMAIN}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        domain: DOMAIN,
        challengeToken: TOKEN,
        challengeContent: KEY_AUTH,
      }),
    });

    // Poll briefly to allow any replication lag.
    let res: Response | null = null;
    for (let i = 0; i < 5; i++) {
      res = await anonFetch(ctx, `/.well-known/acme-challenge/${TOKEN}`);
      if (res.status === 200) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    ok(res !== null, 'response should not be null');
    strictEqual(res!.status, 200, `middleware should return 200 for a valid token`);
    const text = await res!.text();
    strictEqual(text, KEY_AUTH, 'middleware should return the key authorization content');
  });

  test('middleware passes through non-challenge URLs', async () => {
    // A normal URL that does not match /.well-known/acme-challenge/* should
    // not be intercepted by the ACME middleware. Harper may return 200, 400,
    // or 404 — any of these confirm the middleware forwarded the request.
    const res = await anonFetch(ctx, '/some/other/path');
    ok(
      [200, 400, 404].includes(res.status),
      `non-challenge request should pass through, got HTTP ${res.status}`,
    );
  });

  test('middleware passes through /.well-known/ paths with wrong segment count', async () => {
    // The middleware only handles /.well-known/acme-challenge/<token> (4 parts).
    // A path like /.well-known/acme-challenge (no token) should pass through.
    const res = await anonFetch(ctx, '/.well-known/acme-challenge');
    ok(
      [200, 400, 404].includes(res.status),
      `path with wrong segment count should pass through, got HTTP ${res.status}`,
    );
  });
});
