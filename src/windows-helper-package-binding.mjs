import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { types as utilTypes } from 'node:util';

/**
 * Phase 9f: package-bind the reviewed Windows helper sources, toolchain pins,
 * SCM/console entrypoint surface, and the OneCLI proxy supervisor entrypoint.
 *
 * Live collectors must publish through the binding-checked publish path. Binary
 * digests remain same-host publish outputs; source/toolchain pins are
 * cross-platform fail-closed gates. authorization_ready is never set here.
 */

export class WindowsHelperPackageBindingError extends Error {
  constructor(code = 'invalid_package_binding') {
    super(`Windows helper package binding rejected: ${code}`);
    this.name = 'WindowsHelperPackageBindingError';
    this.code = code;
  }
}

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const HELPER_SOURCE_DIR = path.join(ROOT, 'native', 'windows-helper-service');
const SHA256 = /^[0-9a-f]{64}$/;

export const WINDOWS_HELPER_SOURCE_DIR_RELATIVE = 'native/windows-helper-service';

export const WINDOWS_HELPER_TOOLCHAIN_PIN = Object.freeze({
  sdk_version: '8.0.423',
  runtime_framework_version: '8.0.29',
  roll_forward: 'LatestPatch',
  illink_version: '8.0.29',
  illink_nupkg_sha256: '5e75b0b31660410b04fbb17614de9ba40bf44976cae45227094b544df085dce2',
  runtime_identifier: 'win-x64',
  executable_name: 'BitwardenAgentCredentialBridgeHelper.exe',
  project_file: 'BridgeWindowsHelperService.csproj',
});

/** Exact reviewed helper tree (LF-normalized content digests). */
export const WINDOWS_HELPER_SOURCE_DIGESTS = Object.freeze({
  'AuthorizeSchemaProbe.cs':
    '066374fa0c6a437f5e23775275361b7fd7757763a1a8fabe24a343a76018684f',
  'BridgeWindowsHelperService.csproj':
    'f6a24b81fb4753ce93cd3e9dcd3a15bd5d2d10648860de1fe9224efc933543a3',
  'DenialPipeProbe.cs':
    'ba9bf2f198c5f36549ea749b72b55022a9ee47c2c2f7071461de2ddbe72c5190',
  'DisposableFirstInstallApply.cs':
    'db594878d0f8680075d610e69aad36366d6ba8cf5acd17dbd2624bf2c64b9c20',
  'NativeDenialPipeClient.cs':
    'a51de5cce21f13f61aff91f5944c08ae124b7cda4eb615049b6ab17295038d34',
  'NativeServerIdentityVerifier.cs':
    '3c18ad33c0080d87124c3dd0b05de81c85d91d45d4c9339c7869c68df4e09748',
  'NuGet.Config':
    '3464623cc172bb6066efd5718a8233637b36ca7f15f52a48dcd9cf16ed99d8db',
  'PipeSecurity.cs':
    '1fbee08fc4a6553ff17b2b2f156036950fccebc23c4607e153111f1dcc2a8ff7',
  'ProcessQueryAcl.cs':
    '4a607e0b6d3c20466a5a429a270ca52c4c47f8841346161cfbccac6bb80c3c19',
  'Program.cs':
    'f17f0b3b147124367b95db90ceff86cb458bd621a70899d54592d85bdc49850a',
  'global.json':
    '248c17bb46fd7ff31402c62dc1870e90005fc1d9bcbc9a31cefcc78691149d76',
});

export const WINDOWS_HELPER_SOURCE_BYTE_LENGTHS = Object.freeze({
  'AuthorizeSchemaProbe.cs': 2149,
  'BridgeWindowsHelperService.csproj': 916,
  'DenialPipeProbe.cs': 30006,
  'DisposableFirstInstallApply.cs': 8144,
  'NativeDenialPipeClient.cs': 17052,
  'NativeServerIdentityVerifier.cs': 17385,
  'NuGet.Config': 191,
  'PipeSecurity.cs': 6424,
  'ProcessQueryAcl.cs': 2816,
  'Program.cs': 9180,
  'global.json': 104,
});

export const WINDOWS_HELPER_PACKAGE_DIGEST =
  '84a683f798e0c27f7802738a55a1e8f52c6b4cc6eb2a5accdedf4d59ea56b3b1';

export const WINDOWS_HELPER_ENTRYPOINT_MODES = Object.freeze([
  '--self-test',
  '--self-test-authorize-schema',
  '--console-pipe-denial',
  '--self-test-pipe-client',
  '--self-test-pipe-server',
  '--verify-fixed-server-identity',
]);

export const WINDOWS_HELPER_SELF_TEST_KEYS = Object.freeze([
  'schema_version',
  'platform_win32',
  'service_name_bound',
  'scm_entrypoint_compiled',
  'scm_lifecycle_live_verified',
  'console_denial_pipe_compiled',
  'explicit_pipe_dacl_compiled',
  'server_identity_verifier_compiled',
  'service_identity_self_check_compiled',
  'service_pipe_activation_compiled',
  'service_pipe_activation_live_verified',
  'service_authorize_schema_compiled',
  'manifest_executor_absent',
  'network_stack_absent',
  'vault_client_absent',
  'install_gate_eligible',
]);

export const ONECLI_PROXY_SUPERVISOR_BINDING = Object.freeze({
  module_relative_path: 'src/onecli-proxy-runtime-supervisor.js',
  module_sha256: '023acd36f5a4b776bc004e2c9f18fc8db90915283420cb645059c9a8ce1be66c',
  module_byte_length: 8930,
  entrypoint_relative_path: 'scripts/run-onecli-proxy.mjs',
  entrypoint_sha256: '2630907212e09e3971755175b7893db7f8c8c1c15875815a1d0c7d81ffe23f89',
  entrypoint_byte_length: 3341,
  frame_relative_path: 'src/onecli-proxy-runtime-frame.js',
  frame_sha256: 'a5397b83c3ed9f78d143717d501c70760a6ad7e4fbfa01ff1e166088b2422bec',
  frame_byte_length: 5747,
  required_imports: Object.freeze([
    './agent-token.js',
    './onecli-proxy-runtime-frame.js',
    './policy.js',
  ]),
  fixed_runtime_entrypoint_basename: 'run-onecli-proxy.mjs',
});

const FILE_FACT_FIELDS = new Set(['path', 'sha256', 'byte_length']);
const VALID_REPORTS = new WeakSet();
const VALID_PUBLISH_BINDINGS = new WeakSet();

/**
 * Pure evaluator over injected LF-normalized source facts + toolchain pins.
 * Does not read the filesystem and never authorizes.
 */
export function evaluateWindowsHelperPackageBinding(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input) ||
      utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new WindowsHelperPackageBindingError('invalid_binding_input');
  }
  const keys = Reflect.ownKeys(input);
  const expectedKeys = new Set([
    'files', 'toolchain', 'entrypoint_modes_present', 'self_test_keys_present',
  ]);
  if (keys.length !== expectedKeys.size ||
      keys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))) {
    throw new WindowsHelperPackageBindingError('invalid_binding_input');
  }
  if (!Array.isArray(input.files) || input.files.length !==
      Object.keys(WINDOWS_HELPER_SOURCE_DIGESTS).length) {
    throw new WindowsHelperPackageBindingError('source_set_mismatch');
  }

  const seen = new Set();
  const normalized = [];
  for (const raw of input.files) {
    const file = exactPlainObject(raw, FILE_FACT_FIELDS, 'invalid_source_fact');
    if (typeof file.path !== 'string' || !Object.hasOwn(WINDOWS_HELPER_SOURCE_DIGESTS, file.path) ||
        seen.has(file.path) ||
        typeof file.sha256 !== 'string' || !SHA256.test(file.sha256) ||
        !Number.isSafeInteger(file.byte_length) || file.byte_length < 1) {
      throw new WindowsHelperPackageBindingError('invalid_source_fact');
    }
    if (file.sha256 !== WINDOWS_HELPER_SOURCE_DIGESTS[file.path] ||
        file.byte_length !== WINDOWS_HELPER_SOURCE_BYTE_LENGTHS[file.path]) {
      throw new WindowsHelperPackageBindingError('source_digest_mismatch');
    }
    seen.add(file.path);
    normalized.push({
      path: file.path,
      sha256: file.sha256,
      byte_length: file.byte_length,
    });
  }
  for (const required of Object.keys(WINDOWS_HELPER_SOURCE_DIGESTS).sort()) {
    if (!seen.has(required)) {
      throw new WindowsHelperPackageBindingError('source_set_mismatch');
    }
  }

  const toolchain = exactPlainObject(input.toolchain, new Set(Object.keys(WINDOWS_HELPER_TOOLCHAIN_PIN)),
    'toolchain_pin_mismatch');
  for (const [key, value] of Object.entries(WINDOWS_HELPER_TOOLCHAIN_PIN)) {
    if (toolchain[key] !== value) {
      throw new WindowsHelperPackageBindingError('toolchain_pin_mismatch');
    }
  }

  if (input.entrypoint_modes_present !== true || input.self_test_keys_present !== true) {
    throw new WindowsHelperPackageBindingError('entrypoint_surface_mismatch');
  }

  const packageDigest = digestCanonicalFileFacts(normalized);
  if (packageDigest !== WINDOWS_HELPER_PACKAGE_DIGEST) {
    throw new WindowsHelperPackageBindingError('package_digest_mismatch');
  }

  const report = Object.freeze({
    schema_version: 1,
    platform: 'win32',
    package_binding_verified: true,
    package_digest: packageDigest,
    source_files_bound: true,
    toolchain_pinned: true,
    entrypoint_surface_bound: true,
    helper_vault_free: true,
    personal_vault_forbidden: true,
    company_vault_forbidden: true,
    mutation_authorized: false,
    authorization_ready: false,
    terminal_code: 'windows_helper_package_bound',
  });
  VALID_REPORTS.add(report);
  return report;
}

export function isWindowsHelperPackageBindingReport(value) {
  return value !== null && typeof value === 'object' && VALID_REPORTS.has(value);
}

/**
 * Read the reviewed helper tree, LF-normalize, and evaluate the package binding.
 */
export async function verifyWindowsHelperReviewedSources(sourceDir = HELPER_SOURCE_DIR) {
  if (typeof sourceDir !== 'string' || sourceDir.length < 1) {
    throw new WindowsHelperPackageBindingError('invalid_source_dir');
  }
  const files = [];
  let programText = '';
  let csprojText = '';
  let globalText = '';
  for (const relative of Object.keys(WINDOWS_HELPER_SOURCE_DIGESTS).sort()) {
    let bytes;
    try {
      bytes = await fs.readFile(path.join(sourceDir, relative));
    } catch {
      throw new WindowsHelperPackageBindingError('source_read_failed');
    }
    const normalized = normalizeUtf8Lf(bytes);
    const sha256 = createHash('sha256').update(normalized).digest('hex');
    files.push({
      path: relative,
      sha256,
      byte_length: normalized.byteLength,
    });
    if (relative === 'Program.cs') programText = normalized.toString('utf8');
    if (relative === 'BridgeWindowsHelperService.csproj') csprojText = normalized.toString('utf8');
    if (relative === 'global.json') globalText = normalized.toString('utf8');
  }

  const entrypointModesPresent = WINDOWS_HELPER_ENTRYPOINT_MODES.every((mode) =>
    programText.includes(mode));
  const selfTestKeysPresent = WINDOWS_HELPER_SELF_TEST_KEYS.every((key) =>
    programText.includes(key));
  if (!programText.includes('ServiceMain') || !entrypointModesPresent || !selfTestKeysPresent) {
    throw new WindowsHelperPackageBindingError('entrypoint_surface_mismatch');
  }
  if (!csprojText.includes(`<RuntimeFrameworkVersion>${WINDOWS_HELPER_TOOLCHAIN_PIN.runtime_framework_version}</RuntimeFrameworkVersion>`) ||
      !csprojText.includes(`<RuntimeIdentifier>${WINDOWS_HELPER_TOOLCHAIN_PIN.runtime_identifier}</RuntimeIdentifier>`) ||
      !globalText.includes(`"version": "${WINDOWS_HELPER_TOOLCHAIN_PIN.sdk_version}"`)) {
    throw new WindowsHelperPackageBindingError('toolchain_pin_mismatch');
  }

  return evaluateWindowsHelperPackageBinding({
    files,
    toolchain: { ...WINDOWS_HELPER_TOOLCHAIN_PIN },
    entrypoint_modes_present: entrypointModesPresent,
    self_test_keys_present: selfTestKeysPresent,
  });
}

/**
 * Verify the fixed OneCLI proxy supervisor module, frame helper, and entrypoint.
 */
export async function verifyOneCliProxySupervisorPackageBinding(repoRoot = ROOT) {
  if (typeof repoRoot !== 'string' || repoRoot.length < 1) {
    throw new WindowsHelperPackageBindingError('invalid_repo_root');
  }
  const binding = ONECLI_PROXY_SUPERVISOR_BINDING;
  const moduleBytes = await readNormalized(path.join(repoRoot, binding.module_relative_path));
  const entryBytes = await readNormalized(path.join(repoRoot, binding.entrypoint_relative_path));
  const frameBytes = await readNormalized(path.join(repoRoot, binding.frame_relative_path));

  if (digest(moduleBytes) !== binding.module_sha256 ||
      moduleBytes.byteLength !== binding.module_byte_length) {
    throw new WindowsHelperPackageBindingError('supervisor_module_digest_mismatch');
  }
  if (digest(entryBytes) !== binding.entrypoint_sha256 ||
      entryBytes.byteLength !== binding.entrypoint_byte_length) {
    throw new WindowsHelperPackageBindingError('supervisor_entrypoint_digest_mismatch');
  }
  if (digest(frameBytes) !== binding.frame_sha256 ||
      frameBytes.byteLength !== binding.frame_byte_length) {
    throw new WindowsHelperPackageBindingError('supervisor_frame_digest_mismatch');
  }

  const moduleText = moduleBytes.toString('utf8');
  for (const spec of binding.required_imports) {
    if (!moduleText.includes(spec)) {
      throw new WindowsHelperPackageBindingError('supervisor_import_mismatch');
    }
  }
  if (!moduleText.includes(binding.fixed_runtime_entrypoint_basename)) {
    throw new WindowsHelperPackageBindingError('supervisor_entrypoint_mismatch');
  }

  return Object.freeze({
    schema_version: 1,
    supervisor_package_binding_verified: true,
    module_bound: true,
    entrypoint_bound: true,
    frame_bound: true,
    required_imports_bound: true,
    authorization_ready: false,
    terminal_code: 'onecli_proxy_supervisor_package_bound',
  });
}

/**
 * Brand a successful publish result after package binding verification.
 * Collectors must consume this branded object; clones are rejected.
 */
export function brandWindowsHelperPublishBinding(published) {
  if (published === null || typeof published !== 'object' || Array.isArray(published) ||
      utilTypes.isProxy(published) || Object.getPrototypeOf(published) !== Object.prototype) {
    throw new WindowsHelperPackageBindingError('invalid_publish_binding');
  }
  if (!(published.bytes instanceof Uint8Array) || published.bytes.byteLength < 1 ||
      typeof published.sha256 !== 'string' || !SHA256.test(published.sha256) ||
      !Number.isSafeInteger(published.byteLength) ||
      published.byteLength !== published.bytes.byteLength ||
      published.package_binding_verified !== true ||
      published.package_digest !== WINDOWS_HELPER_PACKAGE_DIGEST ||
      published.authorization_ready !== false) {
    throw new WindowsHelperPackageBindingError('invalid_publish_binding');
  }
  const digestHex = createHash('sha256').update(published.bytes).digest('hex');
  if (digestHex !== published.sha256) {
    throw new WindowsHelperPackageBindingError('binary_digest_mismatch');
  }
  const binding = Object.freeze({
    bytes: published.bytes,
    sha256: published.sha256,
    byteLength: published.byteLength,
    package_digest: WINDOWS_HELPER_PACKAGE_DIGEST,
    package_binding_verified: true,
    authorization_ready: false,
  });
  VALID_PUBLISH_BINDINGS.add(binding);
  return binding;
}

export function isWindowsHelperPublishBinding(value) {
  return value !== null && typeof value === 'object' && VALID_PUBLISH_BINDINGS.has(value);
}

export function requireWindowsHelperPublishBinding(value) {
  if (!isWindowsHelperPublishBinding(value)) {
    throw new WindowsHelperPackageBindingError('unbranded_publish_binding');
  }
  return value;
}

export function digestCanonicalFileFacts(files) {
  const sorted = [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const canonical = JSON.stringify(sorted.map((file) => ({
    path: file.path,
    sha256: file.sha256,
    byte_length: file.byte_length,
  })));
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function normalizeUtf8Lf(bytes) {
  if (!(bytes instanceof Uint8Array)) {
    throw new WindowsHelperPackageBindingError('invalid_source_bytes');
  }
  const text = Buffer.from(bytes).toString('utf8').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return Buffer.from(text, 'utf8');
}

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readNormalized(filePath) {
  try {
    return normalizeUtf8Lf(await fs.readFile(filePath));
  } catch {
    throw new WindowsHelperPackageBindingError('source_read_failed');
  }
}

function exactPlainObject(value, fields, code) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new WindowsHelperPackageBindingError(code);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.size ||
      keys.some((key) => typeof key !== 'string' || !fields.has(key))) {
    throw new WindowsHelperPackageBindingError(code);
  }
  const snapshot = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor) ||
        descriptor.get !== undefined || descriptor.set !== undefined) {
      throw new WindowsHelperPackageBindingError(code);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}
