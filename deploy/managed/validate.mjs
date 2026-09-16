#!/usr/bin/env node
import { lstat, readFile } from 'node:fs/promises';
const composePath = process.argv[2];
if (!composePath || process.argv.length !== 3) throw new Error('Usage: validate.mjs /private/managed-gateway-compose.env');
const parse = async path => Object.fromEntries((await readFile(path, 'utf8')).split(/\r?\n/).filter(line => line && !line.startsWith('#')).map(line => { const i = line.indexOf('='); if (i < 1) throw new Error('invalid env syntax'); return [line.slice(0, i), line.slice(i + 1)]; }));
const placeholder = value => !value || /REPLACE|example\.invalid/i.test(value);
const compose = await parse(composePath), errors = [];
const required = ['BITCALL_GATEWAY_IMAGE', 'GATEWAY_ENV_FILE', 'MANAGED_ENV_FILE', 'SEAT_STATE_HOST_DIR', 'RECORDING_SPOOL_HOST_DIR', 'RECORDING_OUTPUT_HOST_DIR', 'TLS_CERT', 'TLS_KEY', 'KAMAILIO_CONFIG', 'ACME_WEBROOT'];
for (const key of required) if (placeholder(compose[key])) errors.push(`missing ${key}`);
if (!/@sha256:[a-f0-9]{64}$/i.test(compose.BITCALL_GATEWAY_IMAGE || '')) errors.push('image digest invalid');
for (const key of ['SEAT_STATE_HOST_DIR', 'RECORDING_SPOOL_HOST_DIR', 'RECORDING_OUTPUT_HOST_DIR']) if (!String(compose[key] || '').startsWith('/')) errors.push(`${key} must be absolute`);
if (new Set(['SEAT_STATE_HOST_DIR', 'RECORDING_SPOOL_HOST_DIR', 'RECORDING_OUTPUT_HOST_DIR'].map(key => compose[key])).size !== 3) errors.push('durable host mounts must be distinct');
for (const key of ['GATEWAY_ENV_FILE', 'MANAGED_ENV_FILE']) try { const info = await lstat(compose[key]); if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o777) !== 0o600) errors.push(`${key} must be regular mode 0600`); } catch { errors.push(`${key} unavailable`); }
let env;
try { const info = await lstat(compose.MANAGED_ENV_FILE); if (info.isSymbolicLink() || !info.isFile() || (info.mode & 0o777) !== 0o600) errors.push('private env must be regular mode 0600'); else env = await parse(compose.MANAGED_ENV_FILE); } catch { errors.push('private env unavailable'); }
if (env) {
  if (!/^[a-z0-9.-]+$/.test(env.SEAT_DOMAIN || '')) errors.push('SEAT_DOMAIN invalid');
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(env.SEAT_CONTROL_TOKEN || '') || placeholder(env.SEAT_CONTROL_TOKEN)) errors.push('SEAT_CONTROL_TOKEN invalid');
  for (const key of ['SEAT_CALL_EVENTS', 'SEAT_MANAGED_ADMISSION_ENABLED', 'SEAT_RECORDING_ENABLED', 'SEAT_MEDIA_ENABLED']) if (!['0', '1'].includes(env[key] || '0')) errors.push(`${key} invalid`);
  if (env.SEAT_MANAGED_ADMISSION_ENABLED === '1') {
    if (env.SEAT_CALL_EVENTS !== '1') errors.push('managed admission needs call events');
    if (!/^https:\/\//.test(env.SEAT_MANAGED_ADMISSION_ENDPOINT || '') || placeholder(env.SEAT_MANAGED_ADMISSION_ENDPOINT)) errors.push('managed endpoint invalid');
    if (!/^[A-Za-z0-9_-]{43,256}$/.test(env.SEAT_MANAGED_ADMISSION_SECRET || '') || placeholder(env.SEAT_MANAGED_ADMISSION_SECRET)) errors.push('managed secret invalid');
  }
  if (env.SEAT_RECORDING_ENABLED === '1') {
    if (env.SEAT_CALL_EVENTS !== '1') errors.push('recording needs call events');
    if (!/^https:\/\//.test(env.SEAT_RECORDING_GATEWAY_ID || '') || placeholder(env.SEAT_RECORDING_GATEWAY_ID)) errors.push('recording gateway invalid');
    if (!['pcap', 'subscription'].includes(env.SEAT_RECORDING_CAPTURE_MODE || '')) errors.push('recording capture mode invalid');
  }
}
if (errors.length) { process.stderr.write(`managed overlay invalid: ${errors.join('; ')}\n`); process.exitCode = 2; }
else process.stdout.write(JSON.stringify({ ok: true, imagePinned: true, privateEnvChecked: true }) + '\n');
