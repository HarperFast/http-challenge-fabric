/**
 * Integration tests for letsencrypt-cert-generator-fabric.
 *
 * Covers:
 *  - Harper startup with this application loaded.
 *  - ChallengeCertificate table operations via the Harper Operations API (the table
 *    is not REST-exported; @export is not present in schema.graphql, so it is an
 *    internal table accessed only through Harper's ops layer and the application code).
 *  - ACME HTTP-01 challenge middleware: serves the stored challenge content
 *    at /.well-known/acme-challenge/<token> without authentication.
 *  - Non-challenge requests pass through the middleware unchanged.
 *
 * NOTE: Actual Let's Encrypt certificate issuance requires a live, publicly
 * reachable domain. The ACME cert-generation flow (performHttpChallenge) is
 * intentionally NOT tested here — it cannot be exercised in a hermetic
 * integration-test environment. The tests below validate the Harper integration
 * layer: the Operations API for DB interactions and the HTTP middleware behavior.
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

// POST an operation to the Harper Operations API with admin Basic auth.
async function op<T = unknown>(
  ctx: ContextWithHarper,
  operation: Record<string, unknown>,
): Promise<{ status: number; body: T }> {
  const { operationsAPIURL, admin } = ctx.harper;
  const creds = Buffer.from(`${admin.username}:${admin.password}`).toString('base64');
  const res = await fetch(operationsAPIURL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${creds}`,
    },
    body: JSON.stringify(operation),
  });
  const body = (await res.json()) as T;
  return { status: res.status, body };
}

// Unauthenticated fetch — ACME challenge endpoint must be publicly reachable.
function anonFetch(ctx: ContextWithHarper, path: string): Promise<Response> {
  return fetch(`${ctx.harper.httpURL}${path}`);
}

// Authenticated fetch for the REST API.
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

  test('ChallengeCertificate table is created in the data database', async () => {
    // Verify the table exists by searching it via the Operations API.
    const { status, body } = await op<unknown[]>(ctx, {
      operation: 'search_by_conditions',
      database: 'data',
      table: 'ChallengeCertificate',
      operator: 'and',
      get_attributes: ['domain'],
      conditions: [
        { search_attribute: 'domain', search_type: 'contains', search_value: '' },
      ],
    });
    strictEqual(status, 200, `Operations API search should succeed, got ${status}: ${JSON.stringify(body)}`);
    ok(Array.isArray(body), 'expected array result from search');
  });
});

suite('ChallengeCertificate table via Operations API', (ctx: ContextWithHarper) => {
  before(async () => {
    await setupHarperWithFixture(ctx, FIXTURE_PATH, { harperBinPath });
  });

  after(async () => {
    await teardownHarper(ctx);
  });

  const TEST_DOMAIN = 'test.example.com';

  test('upsert inserts a new ChallengeCertificate record', async () => {
    const { status, body } = await op(ctx, {
      operation: 'upsert',
      database: 'data',
      table: 'ChallengeCertificate',
      records: [
        {
          domain: TEST_DOMAIN,
          challengeToken: 'abc123token',
          challengeContent: 'abc123token.keyauth-content',
        },
      ],
    });
    strictEqual(status, 200, `upsert should succeed, got ${status}: ${JSON.stringify(body)}`);
  });

  test('search_by_id retrieves the inserted record', async () => {
    // Insert the record first.
    await op(ctx, {
      operation: 'upsert',
      database: 'data',
      table: 'ChallengeCertificate',
      records: [
        {
          domain: TEST_DOMAIN,
          challengeToken: 'abc123token',
          challengeContent: 'abc123token.keyauth-content',
        },
      ],
    });

    const { status, body } = await op<Array<{ domain: string; challengeToken: string; challengeContent: string }>>(ctx, {
      operation: 'search_by_id',
      database: 'data',
      table: 'ChallengeCertificate',
      ids: [TEST_DOMAIN],
      get_attributes: ['domain', 'challengeToken', 'challengeContent'],
    });
    strictEqual(status, 200, `search_by_id should succeed, got ${status}: ${JSON.stringify(body)}`);
    ok(Array.isArray(body), 'expected array response');
    strictEqual(body.length, 1, 'expected exactly one record');
    strictEqual(body[0].domain, TEST_DOMAIN, 'domain should match');
    strictEqual(body[0].challengeToken, 'abc123token', 'challengeToken should match');
    strictEqual(body[0].challengeContent, 'abc123token.keyauth-content', 'challengeContent should match');
  });

  test('search_by_conditions lists all records in the table', async () => {
    // Insert a record.
    await op(ctx, {
      operation: 'upsert',
      database: 'data',
      table: 'ChallengeCertificate',
      records: [
        {
          domain: TEST_DOMAIN,
          challengeToken: 'listcheck',
          challengeContent: 'listcheck.keyauth',
        },
      ],
    });

    const { status, body } = await op<Array<{ domain: string }>>(ctx, {
      operation: 'search_by_conditions',
      database: 'data',
      table: 'ChallengeCertificate',
      operator: 'and',
      get_attributes: ['domain'],
      conditions: [
        { search_attribute: 'domain', search_type: 'contains', search_value: 'example.com' },
      ],
    });
    strictEqual(status, 200, `search should succeed, got ${status}: ${JSON.stringify(body)}`);
    ok(Array.isArray(body), 'expected array response');
    const found = body.some((item) => item.domain === TEST_DOMAIN);
    ok(found, `domain ${TEST_DOMAIN} should appear in the search results`);
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

  test('upserts a challenge token into the database via Operations API', async () => {
    const { status, body } = await op(ctx, {
      operation: 'upsert',
      database: 'data',
      table: 'ChallengeCertificate',
      records: [
        {
          domain: DOMAIN,
          challengeToken: TOKEN,
          challengeContent: KEY_AUTH,
        },
      ],
    });
    strictEqual(status, 200, `upsert should succeed, got ${status}: ${JSON.stringify(body)}`);
  });

  test('middleware serves the challenge content at /.well-known/acme-challenge/<token>', async () => {
    // Store the challenge via the Operations API so the middleware can find it.
    await op(ctx, {
      operation: 'upsert',
      database: 'data',
      table: 'ChallengeCertificate',
      records: [
        {
          domain: DOMAIN,
          challengeToken: TOKEN,
          challengeContent: KEY_AUTH,
        },
      ],
    });

    // Poll briefly to allow any replication/write visibility lag.
    let res: Response | null = null;
    for (let i = 0; i < 10; i++) {
      res = await anonFetch(ctx, `/.well-known/acme-challenge/${TOKEN}`);
      if (res.status === 200) break;
      await new Promise((r) => setTimeout(r, 300));
    }
    ok(res !== null, 'response should not be null');
    strictEqual(res!.status, 200, `middleware should return 200 for a valid token, got ${res!.status}`);
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
