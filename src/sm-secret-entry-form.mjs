/**
 * Pure schema for the agent-callable Windows SM secret-entry dialog.
 * Form JSON never contains secret values — only labels, keys, and constraints.
 *
 * Field sensitivity:
 * - `secret: true`  → written to SM; value NEVER returned to the agent
 * - `secret: false` → written to SM; value MAY be returned in `public_values`
 * Defaults: kind=password → secret; kind=text → public (usernames, labels).
 */

export class SmSecretEntryFormError extends Error {
  constructor(code) {
    super(`SM secret entry form rejected: ${code}`);
    this.name = 'SmSecretEntryFormError';
    this.code = code;
  }
}

const SECRET_KEY = /^[a-zA-Z][a-zA-Z0-9_.-]{0,127}$/;
const PROJECT_ALIASES = new Set(['mivia', 'private-hq', 'private_hq', 'privatehq']);
const FIELD_KINDS = new Set(['text', 'password']);
const MAX_FIELDS = 8;
const MAX_TITLE = 120;
const MAX_INFO = 800;
const MAX_LABEL = 80;
const MAX_HINT = 240;
const MAX_PUBLIC_VALUE = 256;

/**
 * @typedef {{
 *   sm_key: string,
 *   label: string,
 *   kind: 'text' | 'password',
 *   secret: boolean,
 *   required: boolean,
 *   min_length: number,
 *   max_length: number,
 *   hint: string | null,
 * }} SmSecretEntryField
 *
 * @typedef {{
 *   version: 1,
 *   project: string,
 *   title: string,
 *   info: string,
 *   fields: SmSecretEntryField[],
 * }} SmSecretEntryForm
 */

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Normalize and validate an agent-supplied form object.
 * @param {unknown} raw
 * @returns {SmSecretEntryForm}
 */
export function parseSmSecretEntryForm(raw) {
  if (!isPlainObject(raw)) {
    throw new SmSecretEntryFormError('form_not_object');
  }
  if (raw.version !== 1) {
    throw new SmSecretEntryFormError('unsupported_version');
  }
  if (typeof raw.project !== 'string' || !PROJECT_ALIASES.has(raw.project)) {
    throw new SmSecretEntryFormError('invalid_project');
  }
  const project =
    raw.project === 'private_hq' || raw.project === 'privatehq'
      ? 'private-hq'
      : raw.project;
  if (typeof raw.title !== 'string' || raw.title.trim().length < 1 || raw.title.length > MAX_TITLE) {
    throw new SmSecretEntryFormError('invalid_title');
  }
  if (typeof raw.info !== 'string' || raw.info.length > MAX_INFO) {
    throw new SmSecretEntryFormError('invalid_info');
  }
  if (!Array.isArray(raw.fields) || raw.fields.length < 1 || raw.fields.length > MAX_FIELDS) {
    throw new SmSecretEntryFormError('invalid_fields');
  }

  /** @type {SmSecretEntryField[]} */
  const fields = [];
  const seen = new Set();
  for (const entry of raw.fields) {
    if (!isPlainObject(entry)) {
      throw new SmSecretEntryFormError('invalid_field');
    }
    if (typeof entry.sm_key !== 'string' || !SECRET_KEY.test(entry.sm_key)) {
      throw new SmSecretEntryFormError('invalid_sm_key');
    }
    if (seen.has(entry.sm_key)) {
      throw new SmSecretEntryFormError('duplicate_sm_key');
    }
    seen.add(entry.sm_key);
    if (typeof entry.label !== 'string' || entry.label.trim().length < 1 || entry.label.length > MAX_LABEL) {
      throw new SmSecretEntryFormError('invalid_label');
    }
    const kind = entry.kind === undefined ? 'password' : entry.kind;
    if (!FIELD_KINDS.has(kind)) {
      throw new SmSecretEntryFormError('invalid_kind');
    }
    if (entry.secret !== undefined && typeof entry.secret !== 'boolean') {
      throw new SmSecretEntryFormError('invalid_secret_flag');
    }
    // password defaults to secret; text defaults to public (username / label).
    const secret = entry.secret === undefined ? kind === 'password' : entry.secret === true;
    if (kind === 'password' && secret !== true) {
      // Password boxes must stay secret — use kind=text for public fields.
      throw new SmSecretEntryFormError('password_must_be_secret');
    }
    const required = entry.required === undefined ? true : entry.required === true;
    if (entry.required !== undefined && typeof entry.required !== 'boolean') {
      throw new SmSecretEntryFormError('invalid_required');
    }
    const minLength =
      entry.min_length === undefined ? (required ? 1 : 0) : entry.min_length;
    const maxLength = entry.max_length === undefined
      ? (secret ? 4096 : MAX_PUBLIC_VALUE)
      : entry.max_length;
    if (!Number.isInteger(minLength) || minLength < 0 || minLength > 4096) {
      throw new SmSecretEntryFormError('invalid_min_length');
    }
    if (!Number.isInteger(maxLength) || maxLength < 1 || maxLength > 4096) {
      throw new SmSecretEntryFormError('invalid_max_length');
    }
    if (!secret && maxLength > MAX_PUBLIC_VALUE) {
      throw new SmSecretEntryFormError('public_value_too_long_bound');
    }
    if (minLength > maxLength) {
      throw new SmSecretEntryFormError('invalid_length_range');
    }
    let hint = null;
    if (entry.hint !== undefined && entry.hint !== null) {
      if (typeof entry.hint !== 'string' || entry.hint.length > MAX_HINT) {
        throw new SmSecretEntryFormError('invalid_hint');
      }
      hint = entry.hint;
    }
    fields.push({
      sm_key: entry.sm_key,
      label: entry.label.trim(),
      kind,
      secret,
      required,
      min_length: minLength,
      max_length: maxLength,
      hint,
    });
  }

  return Object.freeze({
    version: 1,
    project,
    title: raw.title.trim(),
    info: raw.info,
    fields: Object.freeze(fields),
  });
}

/**
 * Validate collected field values against the form (lengths only).
 * Never logs values.
 * @param {SmSecretEntryForm} form
 * @param {Record<string, string>} values
 * @returns {{ ok: true } | { ok: false, code: string, sm_key?: string }}
 */
export function validateSmSecretEntryValues(form, values) {
  if (!isPlainObject(values)) {
    return { ok: false, code: 'values_not_object' };
  }
  for (const field of form.fields) {
    if (!Object.prototype.hasOwnProperty.call(values, field.sm_key)) {
      if (field.required) {
        return { ok: false, code: 'missing_field', sm_key: field.sm_key };
      }
      continue;
    }
    const value = values[field.sm_key];
    if (typeof value !== 'string') {
      return { ok: false, code: 'invalid_value_type', sm_key: field.sm_key };
    }
    if (value.length === 0 && !field.required) {
      continue;
    }
    if (value.length < field.min_length || value.length > field.max_length) {
      return { ok: false, code: 'invalid_value_length', sm_key: field.sm_key };
    }
  }
  for (const key of Object.keys(values)) {
    if (!form.fields.some((field) => field.sm_key === key)) {
      return { ok: false, code: 'unexpected_field', sm_key: key };
    }
  }
  return { ok: true };
}

/**
 * Extract only non-secret field values for agent-visible stdout.
 * @param {SmSecretEntryForm} form
 * @param {Record<string, string>} values
 * @returns {Record<string, string>}
 */
export function extractSmSecretEntryPublicValues(form, values) {
  /** @type {Record<string, string>} */
  const out = {};
  if (!isPlainObject(values)) return out;
  for (const field of form.fields) {
    if (field.secret) continue;
    const value = values[field.sm_key];
    if (typeof value !== 'string' || value.length < 1) continue;
    if (value.length > MAX_PUBLIC_VALUE) continue;
    out[field.sm_key] = value;
  }
  return out;
}

/**
 * Sanitize a dialog payload's public_values against the form allow-list.
 * @param {SmSecretEntryForm} form
 * @param {unknown} raw
 * @returns {Record<string, string>}
 */
export function sanitizeSmSecretEntryPublicValues(form, raw) {
  if (!isPlainObject(raw)) return {};
  const allowed = new Set(
    form.fields.filter((field) => !field.secret).map((field) => field.sm_key),
  );
  /** @type {Record<string, string>} */
  const out = {};
  for (const [key, value] of Object.entries(raw)) {
    if (!allowed.has(key)) continue;
    if (typeof value !== 'string') continue;
    if (value.length < 1 || value.length > MAX_PUBLIC_VALUE) continue;
    out[key] = value;
  }
  return out;
}

export const SM_SECRET_ENTRY_MAX_PUBLIC_VALUE = MAX_PUBLIC_VALUE;
