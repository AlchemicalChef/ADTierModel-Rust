import { useState, useEffect } from "react";
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  Cog6ToothIcon,
  TrashIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";
import {
  getGpoStatus,
  configureTierGpo,
  configureAllGpos,
  deleteTierGpo,
  type TierGpoStatus,
  type GpoConfigResult,
} from "../../services/tauri";
import type { TierLevel } from "../../types/tier";

const tierColors: Record<string, { bg: string; text: string; border: string }> = {
  Tier0: {
    bg: "bg-red-50 dark:bg-red-900/20",
    text: "text-red-700 dark:text-red-300",
    border: "border-red-200 dark:border-red-800",
  },
  Tier1: {
    bg: "bg-amber-50 dark:bg-amber-900/20",
    text: "text-amber-700 dark:text-amber-300",
    border: "border-amber-200 dark:border-amber-800",
  },
  Tier2: {
    bg: "bg-blue-50 dark:bg-blue-900/20",
    text: "text-blue-700 dark:text-blue-300",
    border: "border-blue-200 dark:border-blue-800",
  },
};

interface GpoStatusCardProps {
  status: TierGpoStatus;
  onConfigure: (tier: string) => void;
  onDelete: (tier: string) => void;
  isConfiguring: boolean;
}

function GpoStatusCard({ status, onConfigure, onDelete, isConfiguring }: GpoStatusCardProps) {
  const colors = tierColors[status.tier] || tierColors.Tier2;
  const hasAnyGpo = status.basePolicy.exists || status.logonRestrictions.exists;
  const isFullyConfigured =
    status.basePolicy.exists &&
    status.basePolicy.linked &&
    status.logonRestrictions.exists &&
    status.logonRestrictions.linked &&
    status.restrictionsConfigured;

  return (
    <div className={`rounded-lg border ${colors.border} ${colors.bg} p-4`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          {isFullyConfigured ? (
            <ShieldCheckIcon className={`w-5 h-5 ${colors.text}`} />
          ) : (
            <ShieldExclamationIcon className="w-5 h-5 text-amber-500" />
          )}
          <h3 className={`font-semibold ${colors.text}`}>{status.tier}</h3>
        </div>
        <div className="flex items-center gap-2">
          {hasAnyGpo && (
            <button
              onClick={() => onDelete(status.tier)}
              disabled={isConfiguring}
              className="p-1.5 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/30 rounded transition-colors disabled:opacity-50"
              title="Delete GPOs"
            >
              <TrashIcon className="w-4 h-4" />
            </button>
          )}
          <button
            onClick={() => onConfigure(status.tier)}
            disabled={isConfiguring}
            className="px-3 py-1.5 text-sm font-medium bg-white dark:bg-surface-800 border border-gray-200 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-surface-700 transition-colors disabled:opacity-50 flex items-center gap-1"
          >
            {isConfiguring ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <Cog6ToothIcon className="w-4 h-4" />
            )}
            {isFullyConfigured ? "Reconfigure" : "Configure"}
          </button>
        </div>
      </div>

      {/* GPO Status */}
      <div className="space-y-3">
        {/* Base Policy */}
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">Base Policy</span>
          <div className="flex items-center gap-2">
            {status.basePolicy.exists ? (
              <>
                <CheckCircleIcon className="w-4 h-4 text-green-500" />
                <span className="text-green-600 dark:text-green-400">Created</span>
                {status.basePolicy.linked && (
                  <span className="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded">
                    Linked
                  </span>
                )}
              </>
            ) : (
              <>
                <XCircleIcon className="w-4 h-4 text-gray-400" />
                <span className="text-gray-500">Not created</span>
              </>
            )}
          </div>
        </div>

        {/* Logon Restrictions Policy */}
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">Logon Restrictions</span>
          <div className="flex items-center gap-2">
            {status.logonRestrictions.exists ? (
              <>
                <CheckCircleIcon className="w-4 h-4 text-green-500" />
                <span className="text-green-600 dark:text-green-400">Created</span>
                {status.logonRestrictions.linked && (
                  <span className="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded">
                    Linked
                  </span>
                )}
              </>
            ) : (
              <>
                <XCircleIcon className="w-4 h-4 text-gray-400" />
                <span className="text-gray-500">Not created</span>
              </>
            )}
          </div>
        </div>

        {/* Restrictions Configured */}
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">User Rights Configured</span>
          {status.restrictionsConfigured ? (
            <CheckCircleIcon className="w-4 h-4 text-green-500" />
          ) : (
            <XCircleIcon className="w-4 h-4 text-gray-400" />
          )}
        </div>
      </div>

      {/* Deny Logon Groups */}
      {status.restrictionsConfigured && (
        <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
          <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
            Denied Logon Rights
          </p>
          <div className="space-y-1.5">
            {status.denyLocalLogon.length > 0 && (
              <div className="text-xs">
                <span className="text-gray-500 dark:text-gray-400">Local Logon: </span>
                <span className="text-gray-700 dark:text-gray-300">
                  {status.denyLocalLogon.join(", ")}
                </span>
              </div>
            )}
            {status.denyRdpLogon.length > 0 && (
              <div className="text-xs">
                <span className="text-gray-500 dark:text-gray-400">RDP Logon: </span>
                <span className="text-gray-700 dark:text-gray-300">
                  {status.denyRdpLogon.join(", ")}
                </span>
              </div>
            )}
            {status.denyNetworkLogon.length > 0 && (
              <div className="text-xs">
                <span className="text-gray-500 dark:text-gray-400">Network Logon: </span>
                <span className="text-gray-700 dark:text-gray-300">
                  {status.denyNetworkLogon.join(", ")}
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function GpoManagementPanel() {
  const [gpoStatuses, setGpoStatuses] = useState<TierGpoStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [configuring, setConfiguring] = useState<string | null>(null);
  const [result, setResult] = useState<GpoConfigResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const statuses = await getGpoStatus();
      setGpoStatuses(statuses);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleConfigureTier = async (tier: string) => {
    setConfiguring(tier);
    setResult(null);
    setError(null);
    try {
      const res = await configureTierGpo(tier as TierLevel);
      setResult(res);
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfiguring(null);
    }
  };

  const handleConfigureAll = async () => {
    setConfiguring("all");
    setResult(null);
    setError(null);
    try {
      const res = await configureAllGpos();
      setResult(res);
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfiguring(null);
    }
  };

  const handleDeleteTier = async (tier: string) => {
    if (!confirm(`Are you sure you want to delete the GPOs for ${tier}? This cannot be undone.`)) {
      return;
    }
    setConfiguring(tier);
    setError(null);
    try {
      await deleteTierGpo(tier as TierLevel);
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfiguring(null);
    }
  };

  const allConfigured = gpoStatuses.every(
    (s) =>
      s.basePolicy.exists &&
      s.basePolicy.linked &&
      s.logonRestrictions.exists &&
      s.logonRestrictions.linked &&
      s.restrictionsConfigured
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <ShieldCheckIcon className="w-5 h-5" />
            GPO Management
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Configure Group Policy Objects for tier isolation
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchStatus}
            disabled={loading || configuring !== null}
            className="p-2 text-gray-500 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors disabled:opacity-50"
            title="Refresh status"
          >
            <ArrowPathIcon className={`w-5 h-5 ${loading ? "animate-spin" : ""}`} />
          </button>
          <button
            onClick={handleConfigureAll}
            disabled={configuring !== null}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {configuring === "all" ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <Cog6ToothIcon className="w-4 h-4" />
            )}
            Configure All Tiers
          </button>
        </div>
      </div>

      {/* Overall Status */}
      <div
        className={`rounded-lg p-4 ${
          allConfigured
            ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
            : "bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800"
        }`}
      >
        <div className="flex items-center gap-2">
          {allConfigured ? (
            <>
              <CheckCircleIcon className="w-5 h-5 text-green-600 dark:text-green-400" />
              <span className="font-medium text-green-700 dark:text-green-300">
                All tier GPOs are configured
              </span>
            </>
          ) : (
            <>
              <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 dark:text-amber-400" />
              <span className="font-medium text-amber-700 dark:text-amber-300">
                Some tier GPOs require configuration
              </span>
            </>
          )}
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400 mt-1 ml-7">
          {allConfigured
            ? "User rights assignments are properly configured to enforce tier isolation."
            : "Configure GPOs to enforce tier isolation through user rights assignments."}
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <div className="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4">
          <div className="flex items-center gap-2">
            <XCircleIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
            <span className="font-medium text-red-700 dark:text-red-300">Error</span>
          </div>
          <p className="text-sm text-red-600 dark:text-red-400 mt-1 ml-7">{error}</p>
        </div>
      )}

      {/* Result Message */}
      {result && !error && (
        <div
          className={`rounded-lg p-4 ${
            result.success
              ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
              : "bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800"
          }`}
        >
          <div className="flex items-center gap-2">
            {result.success ? (
              <CheckCircleIcon className="w-5 h-5 text-green-600 dark:text-green-400" />
            ) : (
              <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 dark:text-amber-400" />
            )}
            <span
              className={`font-medium ${
                result.success
                  ? "text-green-700 dark:text-green-300"
                  : "text-amber-700 dark:text-amber-300"
              }`}
            >
              {result.success ? "Configuration Complete" : "Configuration Partially Complete"}
            </span>
          </div>
          <div className="text-sm mt-2 ml-7 space-y-1">
            {result.gposCreated.length > 0 && (
              <p className="text-gray-600 dark:text-gray-400">
                Created: {result.gposCreated.join(", ")}
              </p>
            )}
            {result.gposLinked.length > 0 && (
              <p className="text-gray-600 dark:text-gray-400">
                Linked: {result.gposLinked.join(", ")}
              </p>
            )}
            {result.gposConfigured.length > 0 && (
              <p className="text-green-600 dark:text-green-400">
                Configured: {result.gposConfigured.join(", ")}
              </p>
            )}
            {result.errors.length > 0 && (
              <div className="text-red-600 dark:text-red-400">
                <p>Errors:</p>
                <ul className="list-disc list-inside">
                  {result.errors.map((err, i) => (
                    <li key={i}>{err}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tier GPO Cards */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <ArrowPathIcon className="w-8 h-8 text-gray-400 animate-spin" />
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          {gpoStatuses.map((status) => (
            <GpoStatusCard
              key={status.tier}
              status={status}
              onConfigure={handleConfigureTier}
              onDelete={handleDeleteTier}
              isConfiguring={configuring === status.tier}
            />
          ))}
        </div>
      )}

      {/* Info Section */}
      <div className="bg-gray-50 dark:bg-surface-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          About Tier Isolation GPOs
        </h3>
        <div className="text-sm text-gray-600 dark:text-gray-400 space-y-2">
          <p>
            GPOs enforce tier isolation by restricting logon rights. Each tier has policies that
            deny logon from accounts in other tiers:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>
              <strong>Tier 0:</strong> Denies Tier 1 and Tier 2 accounts from logging in
            </li>
            <li>
              <strong>Tier 1:</strong> Denies Tier 0 and Tier 2 accounts from logging in
            </li>
            <li>
              <strong>Tier 2:</strong> Denies Tier 0 and Tier 1 accounts from logging in
            </li>
          </ul>
          <p className="mt-2">
            This prevents credential theft attacks where compromised lower-tier credentials could be
            used to access higher-tier systems.
          </p>
        </div>
      </div>
    </div>
  );
}
