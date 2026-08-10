import assert from 'node:assert/strict';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateFakeSentinel } from '../src/constants.js';
import { startFakeSshServer } from '../src/fake-ssh-server.mjs';
import { startFakeFtpServer } from '../src/fake-ftp-server.mjs';
import {
  loadPolicy,
  validatePolicy,
  withBind,
  withSessionTarget,
  PolicyValidationError,
} from '../src/policy.js';
import {
  startSshSessionBroker,
  SshSessionBrokerError,
  MAX_SSH_SESSION_BROKERS,
} from '../src/ssh-session-broker.mjs';
import {
  startFtpSessionBroker,
  FtpSessionBrokerError,
  MAX_FTP_SESSION_BROKERS,
} from '../src/ftp-session-broker.mjs';
import { BrokerError, startBroker } from '../src/broker.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'policies');

function assertNoSecret(label, value, secrets) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of secrets) {
    if (!secret || secret.length < 8) continue;
    assert.ok(!text.includes(secret), `${label} must not contain secret`);
  }
}

describe('phase16 ssh/ftp policy', () => {
  it('loads sample ssh and ftp policies and rejects bad targets', async () => {
    const ssh = await loadPolicy(path.join(root, 'sample-fake-ssh.json'));
    assert.equal(ssh.version, 7);
    assert.equal(ssh.credential_class, 'ssh');
    const ftp = await loadPolicy(path.join(root, 'sample-fake-ftp.json'));
    assert.equal(ftp.version, 8);
    assert.equal(ftp.credential_class, 'ftp');

    assert.throws(
      () => validatePolicy({ ...ssh, target_host: 'example.com', allowed_commands: [...ssh.allowed_commands] }),
      PolicyValidationError,
    );
    assert.throws(
      () => validatePolicy({
        ...ftp,
        allowed_ops: [...ftp.allowed_ops],
        allowed_paths: [...ftp.allowed_paths],
        target_host: '10.0.0.1',
      }),
      PolicyValidationError,
    );
  });

  it('rejects ssh/ftp on the HTTP startBroker path', async () => {
    const ssh = await loadPolicy(path.join(root, 'sample-fake-ssh.json'));
    await assert.rejects(
      () => startBroker({ policy: ssh, credentials: { username: 'user_abcdefgh', password: generateFakeSentinel() } }),
      (error) => error instanceof BrokerError && error.code === 'wrong_broker',
    );
  });
});

describe('phase16 ssh session broker', () => {
  it('authenticates, executes allow-listed commands, and keeps secrets off surfaces', async () => {
    const username = 'user_sshdemo';
    const password = generateFakeSentinel();
    const secrets = [username, password];
    const fake = await startFakeSshServer({
      credentials: { username, password },
      allowedCommands: ['uname', 'whoami'],
    });
    const logs = [];
    let broker;
    try {
      const policy = withSessionTarget(
        withBind(await loadPolicy(path.join(root, 'sample-fake-ssh.json')), 'http://127.0.0.1:0'),
        { host: fake.host, port: fake.port },
      );
      broker = await startSshSessionBroker({
        policy,
        credentials: { username, password },
        log: (entry) => logs.push(entry),
      });
      assert.equal(broker.logged_in, true);
      const status = await fetch(broker.replayUrl);
      assert.equal(status.status, 200);
      const statusBody = await status.text();
      assertNoSecret('status', statusBody, secrets);

      const exec = await fetch(new URL('/exec', broker.baseUrl), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ command: 'uname' }),
      });
      assert.equal(exec.status, 200);
      const execBody = await exec.text();
      assert.match(execBody, /FakeOS/);
      assertNoSecret('exec', execBody, secrets);

      const denied = await fetch(new URL('/exec', broker.baseUrl), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ command: 'rm' }),
      });
      assert.equal(denied.status, 403);
      assertNoSecret('denied', await denied.text(), secrets);
      assertNoSecret('logs', logs, secrets);
      assertNoSecret('handle', {
        session_id: broker.session_id,
        baseUrl: broker.baseUrl,
      }, secrets);
    } finally {
      if (broker) await broker.close();
      await fake.close();
    }
  });

  it('rejects when the session cap is exceeded', async () => {
    const username = 'user_sshlock';
    const password = generateFakeSentinel();
    const fake = await startFakeSshServer({ credentials: { username, password } });
    const policy = withSessionTarget(
      withBind(await loadPolicy(path.join(root, 'sample-fake-ssh.json')), 'http://127.0.0.1:0'),
      { host: fake.host, port: fake.port },
    );
    const brokers = [];
    try {
      for (let i = 0; i < MAX_SSH_SESSION_BROKERS; i += 1) {
        brokers.push(await startSshSessionBroker({
          policy,
          credentials: { username, password },
        }));
      }
      await assert.rejects(
        () => startSshSessionBroker({
          policy,
          credentials: { username, password },
        }),
        (error) => error instanceof SshSessionBrokerError &&
          error.code === 'concurrent_session_forbidden',
      );
    } finally {
      for (const broker of brokers) await broker.close();
      await fake.close();
    }

    const fake2 = await startFakeSshServer({ credentials: { username, password } });
    const badPolicy = withSessionTarget(
      withBind(await loadPolicy(path.join(root, 'sample-fake-ssh.json')), 'http://127.0.0.1:0'),
      { host: fake2.host, port: fake2.port },
    );
    try {
      await assert.rejects(
        () => startSshSessionBroker({
          policy: badPolicy,
          credentials: { username, password: generateFakeSentinel() },
        }),
        (error) => error instanceof SshSessionBrokerError && error.code === 'auth_failed',
      );
    } finally {
      await fake2.close();
    }
  });
});

describe('phase16 ftp session broker', () => {
  it('lists and retrieves allow-listed paths without leaking credentials', async () => {
    const username = 'user_ftpdemo';
    const password = generateFakeSentinel();
    const secrets = [username, password];
    const fake = await startFakeFtpServer({ credentials: { username, password } });
    let broker;
    try {
      const policy = withSessionTarget(
        withBind(await loadPolicy(path.join(root, 'sample-fake-ftp.json')), 'http://127.0.0.1:0'),
        { host: fake.host, port: fake.port },
      );
      broker = await startFtpSessionBroker({
        policy,
        credentials: { username, password },
      });
      const status = await fetch(broker.replayUrl);
      assert.equal(status.status, 200);
      assertNoSecret('status', await status.text(), secrets);

      const list = await fetch(new URL('/list', broker.baseUrl), { method: 'POST' });
      assert.equal(list.status, 200);
      const listBody = await list.text();
      assert.match(listBody, /readme\.txt/);
      assertNoSecret('list', listBody, secrets);

      const retr = await fetch(new URL('/retr', broker.baseUrl), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: '/readme.txt' }),
      });
      assert.equal(retr.status, 200);
      assertNoSecret('retr', await retr.text(), secrets);

      const denied = await fetch(new URL('/retr', broker.baseUrl), {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: '/etc/passwd' }),
      });
      assert.equal(denied.status, 403);
      assertNoSecret('denied', await denied.text(), secrets);
    } finally {
      if (broker) await broker.close();
      await fake.close();
    }
  });

  it('rejects when the session cap is exceeded', async () => {
    const username = 'user_ftplock';
    const password = generateFakeSentinel();
    const fake = await startFakeFtpServer({ credentials: { username, password } });
    const policy = withSessionTarget(
      withBind(await loadPolicy(path.join(root, 'sample-fake-ftp.json')), 'http://127.0.0.1:0'),
      { host: fake.host, port: fake.port },
    );
    const brokers = [];
    try {
      for (let i = 0; i < MAX_FTP_SESSION_BROKERS; i += 1) {
        brokers.push(await startFtpSessionBroker({
          policy,
          credentials: { username, password },
        }));
      }
      await assert.rejects(
        () => startFtpSessionBroker({
          policy,
          credentials: { username, password },
        }),
        (error) => error instanceof FtpSessionBrokerError &&
          error.code === 'concurrent_session_forbidden',
      );
    } finally {
      for (const broker of brokers) await broker.close();
      await fake.close();
    }
  });
});
