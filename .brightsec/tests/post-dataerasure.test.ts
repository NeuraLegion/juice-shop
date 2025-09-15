import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /dataerasure', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['test/api/erasureRequestApiSpec.ts', 'test/cypress/e2e/dataErasure.spec.ts'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/dataerasure/`,
      body: {
        email: 'bjoern.kimminich@gmail.com',
        securityAnswer: 'Name of your favorite pet?',
        layout: null
      },
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
      auth: process.env.BRIGHT_AUTH_ID
    });
});