import net from 'node:net';

const MAX_RESPONSE = 65536;

/**
 * One JSON-line request/response against a fake loopback SSH/FTP server.
 * @param {{ host: string, port: number, messages: object[], timeoutMs?: number }} options
 * @returns {Promise<object[]>}
 */
export async function exchangeJsonLines(options) {
  const timeoutMs = options.timeoutMs ?? 5000;
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: options.host,
      port: options.port,
    });
    let buffer = '';
    /** @type {object[]} */
    const replies = [];
    let settled = false;
    const timer = setTimeout(() => {
      fail(new Error('timeout'));
    }, timeoutMs);

    function finish(value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(value);
    }
    function fail(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      reject(error);
    }

    socket.setEncoding('utf8');
    socket.on('error', fail);
    socket.on('data', (chunk) => {
      buffer += chunk;
      if (buffer.length > MAX_RESPONSE) {
        fail(new Error('oversized'));
        return;
      }
      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line) continue;
        try {
          replies.push(JSON.parse(line));
        } catch {
          fail(new Error('invalid_json'));
          return;
        }
        // Hello + one reply per outbound message (auth + ops + optional quit).
        if (replies.length >= 1 + options.messages.length) {
          finish(replies);
        }
      }
    });
    socket.on('close', () => {
      if (!settled && replies.length >= 2) {
        finish(replies);
      } else if (!settled) {
        fail(new Error('closed_early'));
      }
    });
    socket.on('connect', () => {
      for (const message of options.messages) {
        socket.write(`${JSON.stringify(message)}\n`);
      }
    });
  });
}
