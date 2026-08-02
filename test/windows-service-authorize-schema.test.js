import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  evaluateWindowsServiceAuthorizeSchema,
  WindowsServiceAuthorizeSchemaError,
} from '../src/windows-service-authorize-schema.mjs';

function validRequest(overrides = {}) {
  return {
    protocol_version: 1,
    request_id: 'req-' + 'a'.repeat(16),
    operation: 'apply_disposable_manifest',
    workspace: {
      platform: 'win32',
      root_digest: 'b'.repeat(64),
      marker_nonce: 'c'.repeat(64),
    },
    manifest_digest: 'd'.repeat(64),
    launcher: {
      sha256: 'e'.repeat(64),
      byte_length: 4096,
    },
    ...overrides,
  };
}

describe('Windows service authorize schema', () => {
  it('accepts a bounded request and always denies mutation', () => {
    const report = evaluateWindowsServiceAuthorizeSchema(validRequest());
    assert.deepEqual(report, {
      schema_version: 1,
      request_schema_valid: true,
      operation_recognized: true,
      different_principal_required: true,
      target_acl_evidence_complete: false,
      manifest_executor_absent: true,
      vault_client_absent: true,
      network_stack_absent: true,
      mutation_authorized: false,
      authorization_denied: true,
      terminal_code: 'authorize_schema_valid_denied',
    });
  });

  it('parses canonical JSON strings and rejects oversize or unknown ops', () => {
    const report = evaluateWindowsServiceAuthorizeSchema(JSON.stringify(validRequest()));
    assert.equal(report.request_schema_valid, true);
    assert.throws(
      () => evaluateWindowsServiceAuthorizeSchema(validRequest({ operation: 'run_shell' })),
      (error) => error instanceof WindowsServiceAuthorizeSchemaError,
    );
    assert.throws(
      () => evaluateWindowsServiceAuthorizeSchema('x'.repeat(65 * 1024)),
      (error) => error instanceof WindowsServiceAuthorizeSchemaError &&
        error.code === 'request_too_large',
    );
  });
});
