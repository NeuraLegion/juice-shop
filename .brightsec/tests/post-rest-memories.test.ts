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

test('POST /rest/memories', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'stored_xss', 'csrf', 'osi', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: { databases: ['SQLite'] }
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/rest/memories`,
      headers: { 'Content-Type': 'multipart/form-data' },
      body: `--boundary\r\nContent-Disposition: form-data; name="caption"\r\n\r\nA day at the beach\r\n--boundary\r\nContent-Disposition: form-data; name="image"; filename="beach.png"\r\nContent-Type: image/png\r\n\r\n<binary data>\r\n--boundary--\r\n`,
      auth: process.env.BRIGHT_AUTH_ID
    });
});