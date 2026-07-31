import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  basicAuthorizationValue,
  BASIC_PASSWORD_MAX_LENGTH,
  BASIC_PASSWORD_MIN_LENGTH,
  BASIC_USERNAME_MAX_LENGTH,
  BASIC_USERNAME_MIN_LENGTH,
  validateBasicCredentials,
} from '../src/basic-credentials.js';

describe('HTTP Basic runtime bundle', () => {
  it('accepts both length boundaries and a colon in the password', () => {
    const minimum = {
      username: fakeValue(BASIC_USERNAME_MIN_LENGTH, 'u'),
      password: `${fakeValue(BASIC_PASSWORD_MIN_LENGTH - 1, 'p')}:`,
    };
    const maximum = {
      username: fakeValue(BASIC_USERNAME_MAX_LENGTH, 'U'),
      password: fakeValue(BASIC_PASSWORD_MAX_LENGTH, 'P'),
    };

    assert.deepEqual(validateBasicCredentials(minimum), minimum);
    assert.deepEqual(validateBasicCredentials(maximum), maximum);
  });

  it('rejects missing, extra, accessor, and non-string fields', () => {
    const valid = fakeCredentials();
    const withSymbol = { ...valid, [Symbol('extra')]: true };
    const withAccessor = {
      get username() {
        return valid.username;
      },
      password: valid.password,
    };
    for (const candidate of [
      undefined,
      null,
      [],
      {},
      { username: valid.username },
      { password: valid.password },
      { ...valid, extra: true },
      withSymbol,
      withAccessor,
      { ...valid, username: 123 },
      { ...valid, password: false },
    ]) {
      assert.throws(() => validateBasicCredentials(candidate));
    }
  });

  it('rejects out-of-bounds, control, non-ASCII, and colon username values', () => {
    const valid = fakeCredentials();
    const invalid = [
      { ...valid, username: fakeValue(BASIC_USERNAME_MIN_LENGTH - 1, 'u') },
      { ...valid, username: fakeValue(BASIC_USERNAME_MAX_LENGTH + 1, 'u') },
      { ...valid, password: fakeValue(BASIC_PASSWORD_MIN_LENGTH - 1, 'p') },
      { ...valid, password: fakeValue(BASIC_PASSWORD_MAX_LENGTH + 1, 'p') },
      { ...valid, username: `${fakeValue(7, 'u')}\n` },
      { ...valid, password: `${fakeValue(7, 'p')}\u007f` },
      { ...valid, username: `${fakeValue(7, 'u')}\u00e9` },
      { ...valid, password: `${fakeValue(7, 'p')}\u00e9` },
      { ...valid, username: `${fakeValue(8, 'u')}:suffix` },
    ];
    for (const candidate of invalid) {
      assert.throws(() => validateBasicCredentials(candidate));
    }
  });

  it('uses standard padded unwrapped Base64 for every modulo-3 input length', () => {
    const expectedPadding = new Map([
      [0, ''],
      [1, '=='],
      [2, '='],
    ]);

    for (const usernameLength of [8, 9, 10]) {
      const credentials = {
        username: fakeValue(usernameLength, 'u'),
        password: fakeValue(8, 'p'),
      };
      const joined = `${credentials.username}:${credentials.password}`;
      const expectedPayload = Buffer.from(joined, 'ascii').toString('base64');
      const authorization = basicAuthorizationValue(credentials);

      assert.equal(authorization, `Basic ${expectedPayload}`);
      assert.ok(
        expectedPayload.endsWith(expectedPadding.get(joined.length % 3) ?? ''),
      );
      assert.doesNotMatch(authorization, /[\r\n]/);
    }
  });
});

function fakeCredentials() {
  return {
    username: fakeValue(16, 'u'),
    password: fakeValue(24, 'p'),
  };
}

function fakeValue(length, character) {
  return character.repeat(length);
}
