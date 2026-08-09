import process from 'node:process';
import { types as utilTypes } from 'node:util';
import {
  runWindowsAuthorizationReadyBootstrap,
  WindowsAuthorizationReadyBootstrapError,
} from './windows-authorization-ready-bootstrap.mjs';
import {
  startWindowsAuthorizationEvidenceRefresh,
  clampAuthorizationRefreshIntervalMs,
  WindowsAuthorizationEvidenceRefreshError,
} from './windows-authorization-evidence-refresh.mjs';
import { createLiveWindowsAuthorizationEvidenceCollectors } from './windows-authorization-evidence-live-collectors.mjs';
import {
  loadOperationalBindingsFile,
  startOperationalBridge,
} from './operational-bridge.mjs';

/**
 * Phase 10c: Windows Day-2 operator session.
 *
 * Bootstraps to branded authorization_ready, starts the operational bridge,
 * then keeps Phase 10a evidence refresh running. Drift to not-ready fails
 * closed (bridge replaced with incomplete evidence; never invents true).
 * Uninstall remains explicit and optional.
 */

export class WindowsDay2OperatorSessionError extends Error {
  constructor(code = 'invalid_day2_operator_session') {
    super(`Windows Day-2 operator session rejected: ${code}`);
    this.name = 'WindowsDay2OperatorSessionError';
    this.code = code;
  }
}

/**
 * @param {{
 *   platform?: string,
 *   repoRoot: string,
 *   collectors?: object,
 *   bootstrap?: typeof runWindowsAuthorizationReadyBootstrap,
 *   startRefresh?: typeof startWindowsAuthorizationEvidenceRefresh,
 *   startBridge?: typeof startOperationalBridge,
 *   loadBindings?: typeof loadOperationalBindingsFile,
 *   bindingsPath?: string,
 *   skipApply?: boolean,
 *   intervalMs?: number,
 *   onEvent?: (event: object) => void | Promise<void>,
 *   setIntervalFn?: typeof setInterval,
 *   clearIntervalFn?: typeof clearInterval,
 * }} options
 */
export async function startWindowsDay2OperatorSession(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) ||
      utilTypes.isProxy(options)) {
    throw new WindowsDay2OperatorSessionError('invalid_options');
  }

  const platform = options.platform ?? process.platform;
  if (platform !== 'win32') {
    throw new WindowsDay2OperatorSessionError('unsupported_platform');
  }

  const repoRoot = options.repoRoot;
  if (typeof repoRoot !== 'string' || repoRoot.length < 1) {
    throw new WindowsDay2OperatorSessionError('invalid_repo_root');
  }

  const onEvent = options.onEvent;
  if (onEvent !== undefined && typeof onEvent !== 'function') {
    throw new WindowsDay2OperatorSessionError('invalid_on_event');
  }

  const bootstrap = options.bootstrap ?? runWindowsAuthorizationReadyBootstrap;
  const startRefresh = options.startRefresh ?? startWindowsAuthorizationEvidenceRefresh;
  const startBridge = options.startBridge ?? startOperationalBridge;
  const loadBindings = options.loadBindings ?? loadOperationalBindingsFile;
  if (typeof bootstrap !== 'function' || typeof startRefresh !== 'function' ||
      typeof startBridge !== 'function' || typeof loadBindings !== 'function') {
    throw new WindowsDay2OperatorSessionError('invalid_dependencies');
  }

  let intervalMs;
  try {
    intervalMs = clampAuthorizationRefreshIntervalMs(options.intervalMs);
  } catch (error) {
    if (error instanceof WindowsAuthorizationEvidenceRefreshError) {
      throw new WindowsDay2OperatorSessionError(error.code);
    }
    throw error;
  }

  let collectors = options.collectors;
  let ownsCollectors = false;
  if (collectors === undefined) {
    collectors = createLiveWindowsAuthorizationEvidenceCollectors();
    ownsCollectors = true;
  }

  const emit = async (event) => {
    if (onEvent !== undefined) await onEvent(Object.freeze({ ...event }));
  };

  let bridge = null;
  let refresh = null;
  let stopped = false;
  let lastReady = false;

  const replaceBridge = async (evidence, authorizationReady) => {
    if (bridge !== null) {
      await bridge.close().catch(() => {});
      bridge = null;
    }
    const bindings = await loadBindings(repoRoot, options.bindingsPath ?? 'samples/operational/bindings.json');
    bridge = await startBridge({
      repoRoot,
      bindings,
      productionAuthorizationEvidence: evidence,
    });
    await emit({
      kind: 'operational_bridge',
      harness_ready: bridge.harness_ready === true,
      authorization_ready: bridge.authorization_ready === true,
      operational_authorization_wired: bridge.operational_authorization_wired === true,
      production_authorization_terminal_code: bridge.production_authorization_terminal_code,
      evidence_authorization_ready: authorizationReady === true,
    });
  };

  try {
    let bootstrapResult;
    try {
      bootstrapResult = await bootstrap({
        platform: 'win32',
        collectors,
        skipApply: options.skipApply === true,
      });
    } catch (error) {
      if (error instanceof WindowsAuthorizationReadyBootstrapError) {
        throw new WindowsDay2OperatorSessionError(error.code);
      }
      throw error;
    }

    await emit({
      kind: 'bootstrap',
      authorization_ready: bootstrapResult.authorization_ready === true,
      terminal_code: bootstrapResult.terminal_code,
      apply_attempted: bootstrapResult.apply_attempted === true,
      apply_succeeded: bootstrapResult.apply_succeeded === true,
      helper_vault_free: bootstrapResult.helper_vault_free === true,
      personal_vault_forbidden: true,
      company_vault_forbidden: true,
      mutation_authorized: false,
      collector_error: bootstrapResult.collector_error === true,
    });

    if (bootstrapResult.authorization_ready !== true) {
      throw new WindowsDay2OperatorSessionError('authorization_not_ready');
    }

    lastReady = true;
    await replaceBridge(bootstrapResult.evidence, true);

    refresh = startRefresh({
      collectors,
      intervalMs,
      setIntervalFn: options.setIntervalFn,
      clearIntervalFn: options.clearIntervalFn,
      async onSnapshot(snapshot, cycle) {
        if (stopped) return;
        const ready = snapshot.authorization_ready === true;
        await emit({ kind: 'refresh', ...snapshot });
        if (lastReady === true && ready !== true) {
          await emit({
            kind: 'authorization_drift',
            authorization_ready: false,
            terminal_code: snapshot.terminal_code,
            collector_error: snapshot.collector_error === true,
            mutation_authorized: false,
          });
        }
        lastReady = ready;
        // Always replace bridge from latest branded evidence — never invent true.
        await replaceBridge(cycle.evidence, ready);
      },
    });

    await emit({
      kind: 'day2_started',
      authorization_ready: true,
      interval_ms: intervalMs,
      mutation_authorized: false,
      note: 'Foreground Day-2 session; Ctrl+C stops bridge/refresh. Uninstall remains explicit.',
    });

    return Object.freeze({
      async stop() {
        if (stopped) return;
        stopped = true;
        if (refresh !== null) {
          await refresh.stop().catch(() => {});
          refresh = null;
        }
        if (bridge !== null) {
          await bridge.close().catch(() => {});
          bridge = null;
        }
        if (ownsCollectors && typeof collectors.dispose === 'function') {
          await collectors.dispose().catch(() => {});
        }
      },
      snapshot() {
        return refresh === null ? null : refresh.snapshot();
      },
      get authorization_ready() {
        const snap = refresh === null ? null : refresh.snapshot();
        return snap === null ? lastReady : snap.authorization_ready === true;
      },
    });
  } catch (error) {
    if (refresh !== null) await refresh.stop().catch(() => {});
    if (bridge !== null) await bridge.close().catch(() => {});
    if (ownsCollectors && typeof collectors.dispose === 'function') {
      await collectors.dispose().catch(() => {});
    }
    throw error;
  }
}
