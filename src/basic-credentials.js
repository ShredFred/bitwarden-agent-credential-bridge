const PRINTABLE_ASCII = /^[\x20-\x7e]+$/;

export const BASIC_USERNAME_MIN_LENGTH = 8;
export const BASIC_USERNAME_MAX_LENGTH = 256;
export const BASIC_PASSWORD_MIN_LENGTH = 8;
export const BASIC_PASSWORD_MAX_LENGTH = 1024;

/** @typedef {{ username: string, password: string }} BasicCredentials */

/**
 * Validate and copy an exact in-memory HTTP Basic credential bundle.
 * @param {unknown} raw
 * @returns {BasicCredentials}
 */
export function validateBasicCredentials(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('credentials must be an object');
  }

  const keys = Reflect.ownKeys(raw);
  if (
    keys.length !== 2 ||
    !keys.includes('username') ||
    !keys.includes('password')
  ) {
    throw new TypeError(
      'credentials must contain exactly username and password',
    );
  }

  const usernameDescriptor = Object.getOwnPropertyDescriptor(raw, 'username');
  const passwordDescriptor = Object.getOwnPropertyDescriptor(raw, 'password');
  if (
    usernameDescriptor === undefined ||
    passwordDescriptor === undefined ||
    !('value' in usernameDescriptor) ||
    !('value' in passwordDescriptor)
  ) {
    throw new TypeError('credentials fields must be explicit data values');
  }

  const username = usernameDescriptor.value;
  const password = passwordDescriptor.value;
  validateField(
    username,
    'username',
    BASIC_USERNAME_MIN_LENGTH,
    BASIC_USERNAME_MAX_LENGTH,
  );
  validateField(
    password,
    'password',
    BASIC_PASSWORD_MIN_LENGTH,
    BASIC_PASSWORD_MAX_LENGTH,
  );
  if (username.includes(':')) {
    throw new TypeError('credentials.username must not contain ":"');
  }

  return { username, password };
}

/**
 * @param {BasicCredentials} credentials
 * @returns {string}
 */
export function basicAuthorizationValue(credentials) {
  const payload = Buffer.from(
    `${credentials.username}:${credentials.password}`,
    'ascii',
  ).toString('base64');
  return `Basic ${payload}`;
}

/**
 * @param {unknown} value
 * @param {string} name
 * @param {number} minLength
 * @param {number} maxLength
 */
function validateField(value, name, minLength, maxLength) {
  if (typeof value !== 'string') {
    throw new TypeError(`credentials.${name} must be a string`);
  }
  if (value.length < minLength || value.length > maxLength) {
    throw new TypeError(
      `credentials.${name} length must be ${minLength}..${maxLength}`,
    );
  }
  if (!PRINTABLE_ASCII.test(value)) {
    throw new TypeError(
      `credentials.${name} must contain printable ASCII without controls`,
    );
  }
}
