import net from 'node:net';
import { validateBasicCredentials } from './basic-credentials.js';

const MAX_LINE = 8192;
const DEFAULT_FILES = Object.freeze({
  '/readme.txt': 'fake-ftp-readme',
  '/data/ok.txt': 'fake-ftp-ok',
});

/**
 * Loopback fake FTP surface (JSON-line protocol, not wire FTP).
 *
 * @param {{
 *   credentials: import('./basic-credentials.js').BasicCredentials,
 *   files?: Record<string, string>,
 *   host?: string,
 * }} options
 */
export async function startFakeFtpServer(options) {
  const credentials = validateBasicCredentials(options.credentials);
  const host = options.host ?? '127.0.0.1';
  const files = Object.freeze({ ...(options.files ?? DEFAULT_FILES) });

  const server = net.createServer((socket) => {
    let authed = false;
    let buffer = '';
    socket.setEncoding('utf8');
    socket.write(`${JSON.stringify({ ok: true, proto: 'ftp-fake-1' })}\n`);
    socket.on('data', (chunk) => {
      buffer += chunk;
      if (buffer.length > MAX_LINE * 4) {
        socket.destroy();
        return;
      }
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (line.length < 1 || line.length > MAX_LINE) {
          writeLine(socket, { ok: false, code: 'invalid_frame' });
          socket.destroy();
          return;
        }
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          writeLine(socket, { ok: false, code: 'invalid_json' });
          socket.destroy();
          return;
        }
        if (msg === null || typeof msg !== 'object' || Array.isArray(msg)) {
          writeLine(socket, { ok: false, code: 'invalid_json' });
          socket.destroy();
          return;
        }
        if (msg.op === 'auth') {
          if (authed) {
            writeLine(socket, { ok: false, code: 'already_authed' });
            continue;
          }
          if (msg.username === credentials.username &&
              msg.password === credentials.password) {
            authed = true;
            writeLine(socket, { ok: true, code: 'authenticated' });
          } else {
            writeLine(socket, { ok: false, code: 'auth_failed' });
            socket.destroy();
          }
          continue;
        }
        if (!authed) {
          writeLine(socket, { ok: false, code: 'not_authenticated' });
          socket.destroy();
          return;
        }
        if (msg.op === 'list') {
          writeLine(socket, {
            ok: true,
            code: 'list_ok',
            entries: Object.keys(files).sort(),
          });
          continue;
        }
        if (msg.op === 'retr') {
          if (typeof msg.path !== 'string' || !Object.prototype.hasOwnProperty.call(files, msg.path)) {
            writeLine(socket, { ok: false, code: 'path_denied' });
            continue;
          }
          const body = files[msg.path];
          writeLine(socket, {
            ok: true,
            code: 'retr_ok',
            path: msg.path,
            size: body.length,
            body,
          });
          continue;
        }
        if (msg.op === 'quit') {
          writeLine(socket, { ok: true, code: 'bye' });
          socket.end();
          return;
        }
        writeLine(socket, { ok: false, code: 'unknown_op' });
      }
    });
  });

  await listen(server, host);
  const address = server.address();
  if (address === null || typeof address === 'string') {
    await closeServer(server);
    throw new Error('fake_ftp_bind_failed');
  }

  return {
    host,
    port: address.port,
    paths: Object.freeze(Object.keys(files)),
    async close() {
      await closeServer(server);
    },
  };
}

function writeLine(socket, obj) {
  socket.write(`${JSON.stringify(obj)}\n`);
}

function listen(server, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, host, () => {
      server.off('error', reject);
      resolve(undefined);
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => {
    server.close(() => resolve(undefined));
  });
}
