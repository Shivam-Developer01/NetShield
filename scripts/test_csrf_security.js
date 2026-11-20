/**
 * Phase 20: Comprehensive CSRF and HTTP Security Header Audit
 * Verifies double-submit cookie enforcement across all state-altering routes,
 * safe method exemption, public route exemption, and Helmet headers.
 */

const request = require('../backend/node_modules/supertest');
const fs = require('fs');
const path = require('path');
const app = require('../backend/src/app');

async function runCsrfAudit() {
  console.log('='.repeat(80));
  console.log('PHASE 20: CSRF & HTTP SECURITY HEADERS AUDIT');
  console.log('='.repeat(80));

  const results = {
    timestamp: new Date().toISOString(),
    tests: [],
    allPassed: true
  };

  function record(name, passed, details) {
    console.log(`[${passed ? 'PASS' : 'FAIL'}] ${name}`);
    if (details) console.log(`       Details: ${JSON.stringify(details)}`);
    results.tests.push({ name, passed, details });
    if (!passed) results.allPassed = false;
  }

  // 1. Initial GET request receives XSRF-TOKEN cookie
  const initRes = await request(app).get('/health');
  const cookies = initRes.headers['set-cookie'] || [];
  const xsrfCookie = cookies.find(c => c.startsWith('XSRF-TOKEN='));
  record('Healthcheck issues XSRF-TOKEN cookie', !!xsrfCookie, { setCookie: xsrfCookie });

  let validToken = null;
  if (xsrfCookie) {
    validToken = xsrfCookie.split(';')[0].split('=')[1];
  } else {
    validToken = 'test_token_1234567890abcdef1234567890abcdef';
  }

  // 2. Safe GET method is exempt from CSRF
  const getRes = await request(app).get('/health');
  record('GET /health exempt from CSRF requirement', getRes.statusCode === 200, { status: getRes.statusCode });

  // 3. Public state-changing route (login) is exempt from CSRF header
  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'fake@example.com', password: 'bad_password' });
  // Should return 401 (auth failure), NOT 403 CSRF_ERROR
  record(
    'POST /api/auth/login is exempt from CSRF requirement (returns 401 auth error, not 403 CSRF)',
    loginRes.statusCode === 401 && loginRes.body?.error?.code !== 'CSRF_ERROR',
    { status: loginRes.statusCode, code: loginRes.body?.error?.code }
  );

  // 4. Public state-changing route (register) is exempt from CSRF header
  const regRes = await request(app)
    .post('/api/auth/register')
    .send({ email: 'fake@example.com', username: 'fake', password: '123' });
  // Should return 400 (validation error), NOT 403 CSRF_ERROR
  record(
    'POST /api/auth/register is exempt from CSRF requirement (returns 400 validation error, not 403 CSRF)',
    regRes.statusCode === 400 && regRes.body?.error?.code !== 'CSRF_ERROR',
    { status: regRes.statusCode, code: regRes.body?.error?.code }
  );

  // 5. POST /api/predictions without CSRF token -> REJECTED with HTTP 403 CSRF_ERROR
  const postNoCsrf = await request(app)
    .post('/api/predictions')
    .set('Cookie', [`XSRF-TOKEN=${validToken}`])
    .send({ datasetType: 'nsl_kdd', inputData: {} });
  record(
    'POST /api/predictions missing X-XSRF-TOKEN header rejected with HTTP 403 CSRF_ERROR',
    postNoCsrf.statusCode === 403 && postNoCsrf.body?.error?.code === 'CSRF_ERROR',
    { status: postNoCsrf.statusCode, body: postNoCsrf.body }
  );

  // 6. POST /api/predictions with mismatched token -> REJECTED with HTTP 403 CSRF_ERROR
  const postMismatchCsrf = await request(app)
    .post('/api/predictions')
    .set('Cookie', [`XSRF-TOKEN=${validToken}`])
    .set('X-XSRF-TOKEN', 'completely_wrong_token')
    .send({ datasetType: 'nsl_kdd', inputData: {} });
  record(
    'POST /api/predictions with mismatched X-XSRF-TOKEN header rejected with HTTP 403 CSRF_ERROR',
    postMismatchCsrf.statusCode === 403 && postMismatchCsrf.body?.error?.code === 'CSRF_ERROR',
    { status: postMismatchCsrf.statusCode, body: postMismatchCsrf.body }
  );

  // 7. POST /api/predictions with matching token -> passes CSRF protection (returns 401 unauthenticated or other downstream error, NOT CSRF_ERROR)
  const postMatchingCsrf = await request(app)
    .post('/api/predictions')
    .set('Cookie', [`XSRF-TOKEN=${validToken}`])
    .set('X-XSRF-TOKEN', validToken)
    .send({ datasetType: 'nsl_kdd', inputData: {} });
  record(
    'POST /api/predictions with matching X-XSRF-TOKEN header passes CSRF check (proceeds to auth/validation)',
    postMatchingCsrf.statusCode !== 403 || postMatchingCsrf.body?.error?.code !== 'CSRF_ERROR',
    { status: postMatchingCsrf.statusCode, code: postMatchingCsrf.body?.error?.code }
  );

  // 8. PUT /api/settings without CSRF -> REJECTED with HTTP 403 CSRF_ERROR
  const putNoCsrf = await request(app)
    .put('/api/settings')
    .set('Cookie', [`XSRF-TOKEN=${validToken}`])
    .send({ alertThreshold: 0.5 });
  record(
    'PUT /api/settings missing X-XSRF-TOKEN header rejected with HTTP 403 CSRF_ERROR',
    putNoCsrf.statusCode === 403 && putNoCsrf.body?.error?.code === 'CSRF_ERROR',
    { status: putNoCsrf.statusCode, body: putNoCsrf.body }
  );

  // 9. DELETE /api/alerts/123 without CSRF -> REJECTED with HTTP 403 CSRF_ERROR
  const delNoCsrf = await request(app)
    .delete('/api/alerts/507f1f77bcf86cd799439011')
    .set('Cookie', [`XSRF-TOKEN=${validToken}`]);
  record(
    'DELETE /api/alerts/:id missing X-XSRF-TOKEN header rejected with HTTP 403 CSRF_ERROR',
    delNoCsrf.statusCode === 403 && delNoCsrf.body?.error?.code === 'CSRF_ERROR',
    { status: delNoCsrf.statusCode, body: delNoCsrf.body }
  );

  // 10. Security Headers Verification (Helmet)
  const headers = initRes.headers;
  record('Security Header: X-Frame-Options is DENY', headers['x-frame-options'] === 'DENY', { value: headers['x-frame-options'] });
  record('Security Header: X-Content-Type-Options is nosniff', headers['x-content-type-options'] === 'nosniff', { value: headers['x-content-type-options'] });
  record('Security Header: Referrer-Policy configured', !!headers['referrer-policy'], { value: headers['referrer-policy'] });

  const outPath = path.resolve(__dirname, 'csrf_security_results.json');
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log(`\nAudit completed. Results saved to: ${outPath}`);
  console.log(`All security tests passed: ${results.allPassed}`);
}

runCsrfAudit().catch(err => {
  console.error('Fatal audit error:', err);
  process.exit(1);
});
