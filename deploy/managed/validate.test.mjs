import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import test from 'node:test';
test('validator requires a digest and never prints private values', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gateway-managed-'));
  try {
    const file = join(dir, 'env'); await writeFile(file, 'BITCALL_GATEWAY_IMAGE=repo:tag\nSEAT_CONTROL_TOKEN=super-secret\n');
    assert.throws(() => execFileSync(process.execPath, ['deploy/managed/validate.mjs', file], { cwd: process.cwd(), encoding: 'utf8', stdio: 'pipe' }), error => !String(error.stderr).includes('super-secret'));
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('validator accepts disabled managed mode and rejects unsafe conditional inputs', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gateway-managed-'));
  const token = 'A'.repeat(43), secret = 'B'.repeat(43);
  const base = join(dir, 'gateway.env'), managed = join(dir, 'managed.env'), compose = join(dir, 'compose.env');
  const command = () => execFileSync(process.execPath, ['deploy/managed/validate.mjs', compose],
    { cwd: process.cwd(), encoding: 'utf8', stdio: 'pipe' });
  try {
    await writeFile(base, 'DOMAIN=gateway.example.test\n'); await chmod(base, 0o600);
    const managedEnv = extras => `SEAT_DOMAIN=seats.example.test\nSEAT_CONTROL_TOKEN=${token}\nSEAT_CALL_EVENTS=0\nSEAT_MANAGED_ADMISSION_ENABLED=0\nSEAT_RECORDING_ENABLED=0\nSEAT_MEDIA_ENABLED=0\n${extras || ''}`;
    await writeFile(managed, managedEnv()); await chmod(managed, 0o600);
    const composeEnv = extras => `BITCALL_GATEWAY_IMAGE=registry.test/gateway@sha256:${'a'.repeat(64)}\nGATEWAY_ENV_FILE=${base}\nMANAGED_ENV_FILE=${managed}\nSEAT_STATE_HOST_DIR=/srv/state\nRECORDING_SPOOL_HOST_DIR=/srv/spool\nRECORDING_OUTPUT_HOST_DIR=/srv/output\nTLS_CERT=/private/cert\nTLS_KEY=/private/key\nKAMAILIO_CONFIG=/private/kamailio.cfg\nACME_WEBROOT=/srv/acme\n${extras || ''}`;
    await writeFile(compose, composeEnv());
    assert.match(command(), /"ok":true/);
    const cases = [
      ['placeholder token', async () => writeFile(managed, managedEnv('SEAT_CONTROL_TOKEN=REPLACE_ME\n')), /SEAT_CONTROL_TOKEN invalid/],
      ['recording dependencies', async () => writeFile(managed, managedEnv('SEAT_RECORDING_ENABLED=1\n')), /recording needs call events/],
      ['managed admission dependencies', async () => writeFile(managed, managedEnv('SEAT_MANAGED_ADMISSION_ENABLED=1\nSEAT_CALL_EVENTS=1\n')), /managed endpoint invalid/],
      ['overlapping durable paths', async () => writeFile(compose, composeEnv('RECORDING_OUTPUT_HOST_DIR=/srv/spool\n')), /durable host mounts must be distinct/],
      ['private env mode', async () => { await writeFile(compose, composeEnv()); await writeFile(managed, managedEnv()); await chmod(managed, 0o644); }, /MANAGED_ENV_FILE must be regular mode 0600/],
    ];
    for (const [, arrange, expected] of cases) {
      await chmod(managed, 0o600); await writeFile(compose, composeEnv()); await writeFile(managed, managedEnv());
      await arrange();
      assert.throws(command, error => expected.test(String(error.stderr)) && !String(error.stderr).includes(token));
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
