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
  DocumentTextIcon,
  ServerStackIcon,
  BugAntIcon,
} from "@heroicons/react/24/outline";
import {
  getEndpointProtectionStatus,
  configureEndpointGpo,
  configureAllEndpointGpos,
  deleteEndpointGpo,
  type EndpointGpoStatus,
  type EndpointGpoConfigResult,
} from "../../services/tauri";
import { ENDPOINT_GPO_CONFIGS, type EndpointGpoConfig } from "../../types/endpointProtection";
import type { TierLevel } from "../../types/tier";

// Category colors
const categoryColors = {
  audit: {
    bg: "bg-blue-50 dark:bg-blue-900/20",
    text: "text-blue-700 dark:text-blue-300",
    border: "border-blue-200 dark:border-blue-800",
    icon: DocumentTextIcon,
  },
  "dc-audit": {
    bg: "bg-purple-50 dark:bg-purple-900/20",
    text: "text-purple-700 dark:text-purple-300",
    border: "border-purple-200 dark:border-purple-800",
    icon: ServerStackIcon,
  },
  defender: {
    bg: "bg-green-50 dark:bg-green-900/20",
    text: "text-green-700 dark:text-green-300",
    border: "border-green-200 dark:border-green-800",
    icon: BugAntIcon,
  },
};

interface GpoCardProps {
  config: EndpointGpoConfig;
  status: EndpointGpoStatus | undefined;
  onConfigure: (gpoType: string, tier?: TierLevel) => void;
  onDelete: (gpoType: string, tier?: TierLevel) => void;
  isConfiguring: boolean;
}

function GpoCard({ config, status, onConfigure, onDelete, isConfiguring }: GpoCardProps) {
  const colors = categoryColors[config.category];
  const IconComponent = colors.icon;
  const isConfigured = status?.exists && status?.linked;

  // For per-tier GPOs
  if (config.linkScope === "per-tier") {
    const tiers: TierLevel[] = ["Tier0", "Tier1", "Tier2"];
    const allTiersConfigured = status?.tierStatus?.every((t) => t.linked) ?? false;

    return (
      <div className={`rounded-lg border ${colors.border} ${colors.bg} p-4`}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <IconComponent className={`w-5 h-5 ${colors.text}`} />
            <h3 className={`font-semibold ${colors.text}`}>{config.name}</h3>
          </div>
          {allTiersConfigured ? (
            <ShieldCheckIcon className="w-5 h-5 text-green-500" />
          ) : (
            <ShieldExclamationIcon className="w-5 h-5 text-amber-500" />
          )}
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{config.description}</p>

        {/* Tier status */}
        <div className="space-y-2 mb-4">
          {tiers.map((tier) => {
            const tierStatus = status?.tierStatus?.find((t) => t.tier === tier);
            const tierLinked = tierStatus?.linked ?? false;

            return (
              <div key={tier} className="flex items-center justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-400">{tier}</span>
                <div className="flex items-center gap-2">
                  {tierLinked ? (
                    <>
                      <CheckCircleIcon className="w-4 h-4 text-green-500" />
                      <span className="text-green-600 dark:text-green-400">Linked</span>
                    </>
                  ) : (
                    <>
                      <XCircleIcon className="w-4 h-4 text-gray-400" />
                      <span className="text-gray-500">Not set</span>
                    </>
                  )}
                  <button
                    onClick={() => onConfigure(config.type, tier)}
                    disabled={isConfiguring}
                    className="px-2 py-1 text-xs font-medium bg-white dark:bg-surface-800 border border-gray-200 dark:border-gray-600 rounded hover:bg-gray-50 dark:hover:bg-surface-700 transition-colors disabled:opacity-50"
                  >
                    {tierLinked ? "Reconfigure" : "Configure"}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Configure All button */}
        <button
          onClick={() => {
            tiers.forEach((tier) => onConfigure(config.type, tier));
          }}
          disabled={isConfiguring}
          className="w-full px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {isConfiguring ? (
            <ArrowPathIcon className="w-4 h-4 animate-spin" />
          ) : (
            <Cog6ToothIcon className="w-4 h-4" />
          )}
          Configure All Tiers
        </button>

        {/* Features list */}
        <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
          <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Features</p>
          <ul className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
            {config.features.slice(0, 4).map((feature, i) => (
              <li key={i} className="flex items-start gap-1">
                <span className="text-gray-400">-</span>
                <span>{feature}</span>
              </li>
            ))}
            {config.features.length > 4 && (
              <li className="text-gray-400 italic">+{config.features.length - 4} more</li>
            )}
          </ul>
        </div>
      </div>
    );
  }

  // For DC-only or domain-wide GPOs
  return (
    <div className={`rounded-lg border ${colors.border} ${colors.bg} p-4`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <IconComponent className={`w-5 h-5 ${colors.text}`} />
          <h3 className={`font-semibold ${colors.text}`}>{config.name}</h3>
        </div>
        <div className="flex items-center gap-2">
          {status?.exists && (
            <button
              onClick={() => onDelete(config.type)}
              disabled={isConfiguring}
              className="p-1.5 text-red-500 hover:bg-red-100 dark:hover:bg-red-900/30 rounded transition-colors disabled:opacity-50"
              title="Delete GPO"
            >
              <TrashIcon className="w-4 h-4" />
            </button>
          )}
          {isConfigured ? (
            <ShieldCheckIcon className="w-5 h-5 text-green-500" />
          ) : (
            <ShieldExclamationIcon className="w-5 h-5 text-amber-500" />
          )}
        </div>
      </div>

      <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{config.description}</p>

      {/* Status */}
      <div className="space-y-2 mb-4">
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">Status</span>
          <div className="flex items-center gap-2">
            {status?.exists ? (
              <>
                <CheckCircleIcon className="w-4 h-4 text-green-500" />
                <span className="text-green-600 dark:text-green-400">Created</span>
                {status?.linked && (
                  <span className="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded">
                    Linked
                  </span>
                )}
              </>
            ) : (
              <>
                <XCircleIcon className="w-4 h-4 text-gray-400" />
                <span className="text-gray-500">Not configured</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-gray-600 dark:text-gray-400">Target</span>
          <span className="text-gray-700 dark:text-gray-300 text-xs">
            {config.linkScope === "dc-only" ? "Domain Controllers OU" : "Domain Root"}
          </span>
        </div>
      </div>

      {/* Configure button */}
      <button
        onClick={() => onConfigure(config.type)}
        disabled={isConfiguring}
        className="w-full px-3 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
      >
        {isConfiguring ? (
          <ArrowPathIcon className="w-4 h-4 animate-spin" />
        ) : (
          <Cog6ToothIcon className="w-4 h-4" />
        )}
        {isConfigured ? "Reconfigure" : "Configure"}
      </button>

      {/* Features list */}
      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700">
        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Features</p>
        <ul className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
          {config.features.slice(0, 4).map((feature, i) => (
            <li key={i} className="flex items-start gap-1">
              <span className="text-gray-400">-</span>
              <span>{feature}</span>
            </li>
          ))}
          {config.features.length > 4 && (
            <li className="text-gray-400 italic">+{config.features.length - 4} more</li>
          )}
        </ul>
      </div>
    </div>
  );
}

export function EndpointProtectionPanel() {
  const [statuses, setStatuses] = useState<EndpointGpoStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [configuring, setConfiguring] = useState<string | null>(null);
  const [results, setResults] = useState<EndpointGpoConfigResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const data = await getEndpointProtectionStatus();
      setStatuses(data);
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

  const handleConfigure = async (gpoType: string, tier?: TierLevel) => {
    setConfiguring(gpoType);
    setResults([]);
    setError(null);
    try {
      const result = await configureEndpointGpo(gpoType, tier);
      setResults([result]);
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfiguring(null);
    }
  };

  const handleConfigureAll = async () => {
    setConfiguring("all");
    setResults([]);
    setError(null);
    try {
      const allResults = await configureAllEndpointGpos();
      setResults(allResults);
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfiguring(null);
    }
  };

  const handleDelete = async (gpoType: string, tier?: TierLevel) => {
    const gpoName = tier ? `${gpoType} for ${tier}` : gpoType;
    if (!confirm(`Are you sure you want to delete ${gpoName}? This cannot be undone.`)) {
      return;
    }
    setConfiguring(gpoType);
    setError(null);
    try {
      await deleteEndpointGpo(gpoType, tier);
      await fetchStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setConfiguring(null);
    }
  };

  const getStatusForConfig = (config: EndpointGpoConfig): EndpointGpoStatus | undefined => {
    return statuses.find((s) => s.gpoType === config.type);
  };

  const auditConfigs = ENDPOINT_GPO_CONFIGS.filter((c) => c.category === "audit");
  const dcAuditConfigs = ENDPOINT_GPO_CONFIGS.filter((c) => c.category === "dc-audit");
  const defenderConfigs = ENDPOINT_GPO_CONFIGS.filter((c) => c.category === "defender");

  const successCount = results.filter((r) => r.success).length;
  const errorCount = results.filter((r) => !r.success).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <ShieldCheckIcon className="w-5 h-5" />
            Endpoint Protection GPOs
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Configure audit policies and Defender settings via Group Policy
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
            Configure All GPOs
          </button>
        </div>
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

      {/* Results Message */}
      {results.length > 0 && !error && (
        <div
          className={`rounded-lg p-4 ${
            errorCount === 0
              ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
              : "bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800"
          }`}
        >
          <div className="flex items-center gap-2">
            {errorCount === 0 ? (
              <CheckCircleIcon className="w-5 h-5 text-green-600 dark:text-green-400" />
            ) : (
              <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 dark:text-amber-400" />
            )}
            <span
              className={`font-medium ${
                errorCount === 0
                  ? "text-green-700 dark:text-green-300"
                  : "text-amber-700 dark:text-amber-300"
              }`}
            >
              {errorCount === 0
                ? `${successCount} GPO(s) configured successfully`
                : `${successCount} succeeded, ${errorCount} failed`}
            </span>
          </div>
          {results.some((r) => r.errors.length > 0) && (
            <div className="text-sm mt-2 ml-7 space-y-1">
              {results
                .filter((r) => r.errors.length > 0)
                .map((r, i) => (
                  <div key={i} className="text-red-600 dark:text-red-400">
                    <span className="font-medium">{r.gpoName}:</span>{" "}
                    {r.errors.join(", ")}
                  </div>
                ))}
            </div>
          )}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <ArrowPathIcon className="w-8 h-8 text-gray-400 animate-spin" />
        </div>
      ) : (
        <>
          {/* Windows Audit Policies Section */}
          <div>
            <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-3 flex items-center gap-2">
              <DocumentTextIcon className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              Windows Audit Policies (Per-Tier)
            </h3>
            <div className="grid gap-4 md:grid-cols-2">
              {auditConfigs.map((config) => (
                <GpoCard
                  key={config.type}
                  config={config}
                  status={getStatusForConfig(config)}
                  onConfigure={handleConfigure}
                  onDelete={handleDelete}
                  isConfiguring={configuring === config.type}
                />
              ))}
            </div>
          </div>

          {/* Domain Controller Audit Policies Section */}
          <div>
            <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-3 flex items-center gap-2">
              <ServerStackIcon className="w-5 h-5 text-purple-600 dark:text-purple-400" />
              Domain Controller Audit Policies
            </h3>
            <div className="grid gap-4 md:grid-cols-2">
              {dcAuditConfigs.map((config) => (
                <GpoCard
                  key={config.type}
                  config={config}
                  status={getStatusForConfig(config)}
                  onConfigure={handleConfigure}
                  onDelete={handleDelete}
                  isConfiguring={configuring === config.type}
                />
              ))}
            </div>
          </div>

          {/* Defender Antivirus Section */}
          <div>
            <h3 className="text-md font-semibold text-gray-800 dark:text-gray-200 mb-3 flex items-center gap-2">
              <BugAntIcon className="w-5 h-5 text-green-600 dark:text-green-400" />
              Defender Antivirus (Domain-Wide)
            </h3>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-1 max-w-xl">
              {defenderConfigs.map((config) => (
                <GpoCard
                  key={config.type}
                  config={config}
                  status={getStatusForConfig(config)}
                  onConfigure={handleConfigure}
                  onDelete={handleDelete}
                  isConfiguring={configuring === config.type}
                />
              ))}
            </div>
          </div>
        </>
      )}

      {/* Info Section */}
      <div className="bg-gray-50 dark:bg-surface-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          About Endpoint Protection GPOs
        </h3>
        <div className="text-sm text-gray-600 dark:text-gray-400 space-y-2">
          <p>
            These GPOs configure security audit policies and Defender settings across your
            environment:
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li>
              <strong>Audit Baseline:</strong> Microsoft-recommended audit policies for general security monitoring
            </li>
            <li>
              <strong>Audit Enhanced:</strong> ACSC/NSA hardened policies including PowerShell logging and command line auditing
            </li>
            <li>
              <strong>DC Audit Essential:</strong> Critical security events for Domain Controllers
            </li>
            <li>
              <strong>DC Audit Comprehensive:</strong> Full forensic logging including Kerberos and LDAP events
            </li>
            <li>
              <strong>Defender Protection:</strong> Balanced antivirus settings with cloud protection and PUA blocking
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
