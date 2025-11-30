import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ServerIcon,
  ShieldCheckIcon,
  ClockIcon,
  SignalIcon,
  CpuChipIcon,
} from "@heroicons/react/24/outline";
import {
  getDomainInfo,
  getTierCounts,
  getComplianceStatus,
  getGpoStatus,
  checkTierInitialization,
} from "../../services/tauri";
import { useSettingsStore } from "../../store/settingsStore";
import { notify } from "../../store/notificationStore";

type HealthStatus = "healthy" | "warning" | "error" | "unknown";

interface HealthCheck {
  name: string;
  status: HealthStatus;
  message: string;
  lastChecked: Date | null;
  icon: React.ElementType;
}

function getStatusColor(status: HealthStatus) {
  switch (status) {
    case "healthy":
      return {
        bg: "bg-green-100 dark:bg-green-900/30",
        text: "text-green-700 dark:text-green-300",
        border: "border-green-200 dark:border-green-800",
        icon: "text-green-500",
      };
    case "warning":
      return {
        bg: "bg-amber-100 dark:bg-amber-900/30",
        text: "text-amber-700 dark:text-amber-300",
        border: "border-amber-200 dark:border-amber-800",
        icon: "text-amber-500",
      };
    case "error":
      return {
        bg: "bg-red-100 dark:bg-red-900/30",
        text: "text-red-700 dark:text-red-300",
        border: "border-red-200 dark:border-red-800",
        icon: "text-red-500",
      };
    default:
      return {
        bg: "bg-gray-100 dark:bg-gray-800",
        text: "text-gray-600 dark:text-gray-400",
        border: "border-gray-200 dark:border-gray-700",
        icon: "text-gray-400",
      };
  }
}

function StatusIcon({ status }: { status: HealthStatus }) {
  switch (status) {
    case "healthy":
      return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
    case "warning":
      return <ExclamationTriangleIcon className="w-5 h-5 text-amber-500" />;
    case "error":
      return <XCircleIcon className="w-5 h-5 text-red-500" />;
    default:
      return <ClockIcon className="w-5 h-5 text-gray-400" />;
  }
}

function HealthCheckCard({ check }: { check: HealthCheck }) {
  const colors = getStatusColor(check.status);
  const Icon = check.icon;

  return (
    <div className={`rounded-lg border ${colors.border} ${colors.bg} p-4`}>
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg bg-white dark:bg-surface-800`}>
          <Icon className={`w-5 h-5 ${colors.icon}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between">
            <h4 className={`text-sm font-medium ${colors.text}`}>{check.name}</h4>
            <StatusIcon status={check.status} />
          </div>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {check.message}
          </p>
          {check.lastChecked && (
            <p className="text-xs text-gray-500 dark:text-gray-500 mt-2">
              Last checked: {check.lastChecked.toLocaleTimeString()}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export function HealthCheckPanel() {
  const queryClient = useQueryClient();
  const [isRefreshing, setIsRefreshing] = useState(false);
  const { autoRefreshInterval } = useSettingsStore();

  // Domain connection check
  const domainQuery = useQuery({
    queryKey: ["healthCheck", "domain"],
    queryFn: getDomainInfo,
    staleTime: 30_000,
    retry: 1,
  });

  // Tier initialization check
  const initQuery = useQuery({
    queryKey: ["healthCheck", "initialization"],
    queryFn: checkTierInitialization,
    staleTime: 60_000,
    retry: 1,
  });

  // Tier counts check
  const countsQuery = useQuery({
    queryKey: ["healthCheck", "tierCounts"],
    queryFn: getTierCounts,
    staleTime: 30_000,
    retry: 1,
  });

  // Compliance check
  const complianceQuery = useQuery({
    queryKey: ["healthCheck", "compliance"],
    queryFn: getComplianceStatus,
    staleTime: 60_000,
    retry: 1,
  });

  // GPO status check
  const gpoQuery = useQuery({
    queryKey: ["healthCheck", "gpo"],
    queryFn: getGpoStatus,
    staleTime: 60_000,
    retry: 1,
  });

  // Build health checks array
  const healthChecks: HealthCheck[] = [
    {
      name: "Domain Connection",
      icon: ServerIcon,
      status: domainQuery.isLoading
        ? "unknown"
        : domainQuery.isError
        ? "error"
        : domainQuery.data?.connected
        ? "healthy"
        : "warning",
      message: domainQuery.isLoading
        ? "Checking connection..."
        : domainQuery.isError
        ? "Failed to connect to domain"
        : domainQuery.data?.connected
        ? `Connected to ${domainQuery.data.dnsRoot}`
        : "Running in mock mode",
      lastChecked: domainQuery.dataUpdatedAt ? new Date(domainQuery.dataUpdatedAt) : null,
    },
    {
      name: "Tier Structure",
      icon: CpuChipIcon,
      status: initQuery.isLoading
        ? "unknown"
        : initQuery.isError
        ? "error"
        : initQuery.data?.isInitialized
        ? "healthy"
        : "warning",
      message: initQuery.isLoading
        ? "Checking initialization..."
        : initQuery.isError
        ? "Failed to check initialization"
        : initQuery.data?.isInitialized
        ? `All tier OUs and groups configured`
        : `Missing: ${initQuery.data?.missingComponents?.slice(0, 2).join(", ") || "components"}`,
      lastChecked: initQuery.dataUpdatedAt ? new Date(initQuery.dataUpdatedAt) : null,
    },
    {
      name: "Object Discovery",
      icon: SignalIcon,
      status: countsQuery.isLoading
        ? "unknown"
        : countsQuery.isError
        ? "error"
        : "healthy",
      message: countsQuery.isLoading
        ? "Discovering objects..."
        : countsQuery.isError
        ? "Failed to discover objects"
        : `Found ${
            (countsQuery.data?.Tier0 || 0) +
            (countsQuery.data?.Tier1 || 0) +
            (countsQuery.data?.Tier2 || 0) +
            (countsQuery.data?.Unassigned || 0)
          } total objects`,
      lastChecked: countsQuery.dataUpdatedAt ? new Date(countsQuery.dataUpdatedAt) : null,
    },
    {
      name: "Compliance Status",
      icon: ShieldCheckIcon,
      status: complianceQuery.isLoading
        ? "unknown"
        : complianceQuery.isError
        ? "error"
        : complianceQuery.data
        ? complianceQuery.data.score >= 90
          ? "healthy"
          : complianceQuery.data.score >= 70
          ? "warning"
          : "error"
        : "unknown",
      message: complianceQuery.isLoading
        ? "Running compliance checks..."
        : complianceQuery.isError
        ? "Failed to check compliance"
        : complianceQuery.data
        ? `Score: ${complianceQuery.data.score}% (${complianceQuery.data.totalViolations} violations)`
        : "No compliance data",
      lastChecked: complianceQuery.dataUpdatedAt ? new Date(complianceQuery.dataUpdatedAt) : null,
    },
    {
      name: "GPO Configuration",
      icon: ShieldCheckIcon,
      status: gpoQuery.isLoading
        ? "unknown"
        : gpoQuery.isError
        ? "error"
        : gpoQuery.data
        ? gpoQuery.data.every((g) => g.restrictionsConfigured)
          ? "healthy"
          : gpoQuery.data.some((g) => g.restrictionsConfigured)
          ? "warning"
          : "error"
        : "unknown",
      message: gpoQuery.isLoading
        ? "Checking GPO status..."
        : gpoQuery.isError
        ? "Failed to check GPO status"
        : gpoQuery.data
        ? `${gpoQuery.data.filter((g) => g.restrictionsConfigured).length}/${gpoQuery.data.length} tiers configured`
        : "No GPO data",
      lastChecked: gpoQuery.dataUpdatedAt ? new Date(gpoQuery.dataUpdatedAt) : null,
    },
  ];

  // Calculate overall health
  const overallHealth: HealthStatus =
    healthChecks.every((c) => c.status === "healthy")
      ? "healthy"
      : healthChecks.some((c) => c.status === "error")
      ? "error"
      : healthChecks.some((c) => c.status === "warning")
      ? "warning"
      : "unknown";

  const handleRefreshAll = async () => {
    setIsRefreshing(true);
    try {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["healthCheck"] }),
        queryClient.invalidateQueries({ queryKey: ["tierCounts"] }),
        queryClient.invalidateQueries({ queryKey: ["complianceStatus"] }),
        queryClient.invalidateQueries({ queryKey: ["domainInfo"] }),
      ]);
      notify.success("Health Check Complete", "All systems checked successfully");
    } catch {
      notify.error("Health Check Failed", "Some checks could not be completed");
    } finally {
      setIsRefreshing(false);
    }
  };

  const overallColors = getStatusColor(overallHealth);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <SignalIcon className="w-5 h-5" />
            System Health
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Monitor AD connection and tier model status
          </p>
        </div>
        <button
          onClick={handleRefreshAll}
          disabled={isRefreshing}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
        >
          <ArrowPathIcon className={`w-4 h-4 ${isRefreshing ? "animate-spin" : ""}`} />
          Refresh All
        </button>
      </div>

      {/* Overall Status */}
      <div className={`rounded-xl border ${overallColors.border} ${overallColors.bg} p-6`}>
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-full bg-white dark:bg-surface-800`}>
            <StatusIcon status={overallHealth} />
          </div>
          <div>
            <h3 className={`text-xl font-semibold ${overallColors.text}`}>
              {overallHealth === "healthy"
                ? "All Systems Operational"
                : overallHealth === "warning"
                ? "Some Systems Need Attention"
                : overallHealth === "error"
                ? "System Issues Detected"
                : "Checking Systems..."}
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
              {healthChecks.filter((c) => c.status === "healthy").length} of{" "}
              {healthChecks.length} checks passing
            </p>
          </div>
        </div>

        {autoRefreshInterval !== "off" && (
          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
            <p className="text-sm text-gray-500 dark:text-gray-400 flex items-center gap-2">
              <ArrowPathIcon className="w-4 h-4" />
              Auto-refresh enabled: every{" "}
              {autoRefreshInterval === "1min"
                ? "minute"
                : autoRefreshInterval === "5min"
                ? "5 minutes"
                : "15 minutes"}
            </p>
          </div>
        )}
      </div>

      {/* Health Checks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {healthChecks.map((check) => (
          <HealthCheckCard key={check.name} check={check} />
        ))}
      </div>

      {/* Quick Stats */}
      {countsQuery.data && complianceQuery.data && (
        <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-4">
            Quick Statistics
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {countsQuery.data.Tier0 || 0}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Tier 0 Objects</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {countsQuery.data.Tier1 || 0}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Tier 1 Objects</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">
                {countsQuery.data.Tier2 || 0}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Tier 2 Objects</p>
            </div>
            <div>
              <p className="text-2xl font-bold text-amber-600 dark:text-amber-400">
                {countsQuery.data.Unassigned || 0}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">Unassigned</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
