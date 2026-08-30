/**
 * osascript/JXA may prepend warnings. Recover the first JSON object.
 * Never logs the raw buffer (may contain a token).
 * @param {string} raw
 * @returns {unknown}
 */
export function parseOsascriptJson(raw) {
  if (typeof raw !== 'string' || raw.length < 2) {
    throw new Error('empty');
  }
  const start = raw.indexOf('{');
  const end = raw.lastIndexOf('}');
  if (start < 0 || end <= start) {
    throw new Error('no_object');
  }
  return JSON.parse(raw.slice(start, end + 1));
}
