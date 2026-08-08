import { types as utilTypes } from 'node:util';
import {
  buildIncompleteOperationalAuthorizationEvidence,
  composeWindowsOperationalAuthorization,
  isWindowsOperationalAuthorizationReport,
  WindowsOperationalAuthorizationError,
} from './windows-operational-authorization.mjs';

/**
 * Phase 10a: Day-2 authorization evidence refresh loop.
 *
 * Periodically re-collects branded 9b/9c/9d evidence (via injected collectors),
 * recomposes Phase 9e authorization, and emits a value-free snapshot. Does not
 * install/elevate/uninstall the LocalService helper. authorization_ready is
 * copied only from compose — never hardcoded true.
 *
 * Agent-readable surface non-disclosure remains the Phase 1–8 exposure contract;
 * this refresh does not strengthen memory isolation against a malicious
 * same-user agent.
 */

export class WindowsAuthorizationEvidenceRefreshError extends Error {
  constructor(code = 'invalid_authorization_evidence_refresh') {
    super(`Windows authorization evidence refresh rejected: ${code}`);
    this.name = 'WindowsAuthorizationEvidenceRefreshError';
    this.code = code;
  }
}

const DEFAULT_INTERVAL_MS = 60_000;
const MIN_INTERVAL_MS = 15_000;
const MAX_INTERVAL_MS = 3_600_000;

const SNAPSHOT_FIELDS = Object.freeze([
  'schema_version',
  'platform',
  'refresh_generation',
  'evidence_complete',
  'authorization_ready',
  'terminal_code',
  'helper_vault_free',
  'personal_vault_forbidden',
  'company_vault_forbidden',
  'mutation_authorized',
  'operational_bridge_unwired',
  'collector_error',
]);

/**
 * @typedef {{
 *   collectHandleBound: () => Promise<object>,
 *   collectTargetAcl: () => Promise<object>,
 *   collectPeer: (targetAclEvidence: object) => Promise<object>,
 *   buildInstallGateAndLayout: () => Promise<{ installGateReport: object, layoutPlan: object }>,
 * }} AuthorizationEvidenceCollectors
 */

/**
 * Clamp refresh interval to the fixed Phase 10a bounds.
 * @param {unknown} value
 * @returns {number}
 */
export function clampAuthorizationRefreshIntervalMs(value) {
  if (value === undefined || value === null) return DEFAULT_INTERVAL_MS;
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_interval_ms');
  }
  if (value < MIN_INTERVAL_MS) return MIN_INTERVAL_MS;
  if (value > MAX_INTERVAL_MS) return MAX_INTERVAL_MS;
  return value;
}

/**
 * Run one collect → compose cycle. Collector failures fail closed to incomplete.
 *
 * @param {AuthorizationEvidenceCollectors} collectors
 * @param {(evidence: object) => object} [compose]
 */
export async function refreshWindowsAuthorizationEvidenceOnce(collectors, compose = composeWindowsOperationalAuthorization) {
  assertCollectors(collectors);
  if (typeof compose !== 'function') {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_compose');
  }

  try {
    const foundation = await collectors.buildInstallGateAndLayout();
    if (foundation === null || typeof foundation !== 'object' || Array.isArray(foundation)) {
      throw new WindowsAuthorizationEvidenceRefreshError('invalid_foundation');
    }
    const handleBoundEvidence = await collectors.collectHandleBound();
    const targetAclEvidence = await collectors.collectTargetAcl();
    const peerEvidence = await collectors.collectPeer(targetAclEvidence);
    const evidence = Object.freeze({
      installGateReport: foundation.installGateReport,
      layoutPlan: foundation.layoutPlan,
      handleBoundEvidence,
      targetAclEvidence,
      peerEvidence,
    });
    const report = compose(evidence);
    if (!isWindowsOperationalAuthorizationReport(report)) {
      throw new WindowsAuthorizationEvidenceRefreshError('unbranded_compose_report');
    }
    return Object.freeze({
      evidence,
      report,
      collector_error: false,
    });
  } catch (error) {
    if (error instanceof WindowsAuthorizationEvidenceRefreshError) throw error;
    // Fail closed: incomplete branded fixtures → authorization_ready false.
    const incomplete = buildIncompleteOperationalAuthorizationEvidence();
    let report;
    try {
      report = compose(incomplete);
    } catch (composeError) {
      if (composeError instanceof WindowsOperationalAuthorizationError) {
        throw new WindowsAuthorizationEvidenceRefreshError(composeError.code);
      }
      throw composeError;
    }
    return Object.freeze({
      evidence: incomplete,
      report,
      collector_error: true,
      error_code: error && typeof error === 'object' && typeof error.code === 'string'
        ? error.code
        : 'collector_failed',
    });
  }
}

/**
 * Start a foreground refresh loop. Returns a handle with stop() and snapshot().
 *
 * @param {{
 *   collectors: AuthorizationEvidenceCollectors,
 *   intervalMs?: number,
 *   onSnapshot?: (snapshot: object, cycle: object) => void | Promise<void>,
 *   compose?: (evidence: object) => object,
 *   setIntervalFn?: typeof setInterval,
 *   clearIntervalFn?: typeof clearInterval,
 * }} options
 */
export function startWindowsAuthorizationEvidenceRefresh(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) ||
      utilTypes.isProxy(options)) {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_options');
  }
  const collectors = options.collectors;
  assertCollectors(collectors);
  const intervalMs = clampAuthorizationRefreshIntervalMs(options.intervalMs);
  const compose = options.compose ?? composeWindowsOperationalAuthorization;
  if (typeof compose !== 'function') {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_compose');
  }
  const onSnapshot = options.onSnapshot;
  if (onSnapshot !== undefined && typeof onSnapshot !== 'function') {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_on_snapshot');
  }
  const setIntervalFn = options.setIntervalFn ?? setInterval;
  const clearIntervalFn = options.clearIntervalFn ?? clearInterval;
  if (typeof setIntervalFn !== 'function' || typeof clearIntervalFn !== 'function') {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_timer_api');
  }

  let generation = 0;
  let lastSnapshot = null;
  let timer = null;
  let stopped = false;
  let chain = Promise.resolve();

  const emitSnapshot = async (cycle) => {
    generation += 1;
    const snapshot = Object.freeze({
      schema_version: 1,
      platform: 'win32',
      refresh_generation: generation,
      evidence_complete: cycle.report.authorization_ready === true,
      authorization_ready: cycle.report.authorization_ready === true,
      terminal_code: cycle.report.terminal_code,
      helper_vault_free: cycle.report.helper_vault_free === true,
      personal_vault_forbidden: cycle.report.personal_vault_forbidden === true,
      company_vault_forbidden: cycle.report.company_vault_forbidden === true,
      mutation_authorized: false,
      operational_bridge_unwired: cycle.report.operational_bridge_unwired === true,
      collector_error: cycle.collector_error === true,
    });
    assertSnapshotShape(snapshot);
    lastSnapshot = Object.freeze({ snapshot, cycle });
    if (onSnapshot !== undefined) {
      await onSnapshot(snapshot, cycle);
    }
    return snapshot;
  };

  const tick = () => {
    chain = chain.then(async () => {
      if (stopped) return null;
      const cycle = await refreshWindowsAuthorizationEvidenceOnce(collectors, compose);
      if (stopped) return null;
      return emitSnapshot(cycle);
    });
    return chain;
  };

  const api = {
    intervalMs,
    /** Run one refresh immediately (also used before the interval starts). */
    tick,
    snapshot() {
      return lastSnapshot === null ? null : lastSnapshot.snapshot;
    },
    lastCycle() {
      return lastSnapshot === null ? null : lastSnapshot.cycle;
    },
    async stop() {
      stopped = true;
      if (timer !== null) {
        clearIntervalFn(timer);
        timer = null;
      }
      await chain.catch(() => {});
    },
  };

  // First tick immediately, then interval. All ticks share one serial chain.
  void tick();

  timer = setIntervalFn(() => {
    if (stopped) return;
    void tick();
  }, intervalMs);
  if (typeof timer?.unref === 'function') timer.unref();

  return api;
}

function assertCollectors(collectors) {
  if (collectors === null || typeof collectors !== 'object' || Array.isArray(collectors) ||
      utilTypes.isProxy(collectors)) {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_collectors');
  }
  for (const key of [
    'collectHandleBound',
    'collectTargetAcl',
    'collectPeer',
    'buildInstallGateAndLayout',
  ]) {
    if (typeof collectors[key] !== 'function') {
      throw new WindowsAuthorizationEvidenceRefreshError('invalid_collectors');
    }
  }
}

function assertSnapshotShape(snapshot) {
  const keys = Reflect.ownKeys(snapshot);
  if (keys.length !== SNAPSHOT_FIELDS.length ||
      SNAPSHOT_FIELDS.some((field) => !keys.includes(field))) {
    throw new WindowsAuthorizationEvidenceRefreshError('invalid_snapshot');
  }
}
