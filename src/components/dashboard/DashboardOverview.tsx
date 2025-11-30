import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldCheckIcon,
  ServerIcon,
  ComputerDesktopIcon,
  QuestionMarkCircleIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
  ArrowPathIcon,
  ChartBarIcon,
  CheckCircleIcon,
  XCircleIcon,
  UserPlusIcon,
  DocumentArrowUpIcon,
} from "@heroicons/react/24/outline";
import { useTierStore } from "../../store/tierStore";
import { getComplianceStatus, type ComplianceStatus } from "../../services/tauri";
import { tierConfig } from "../../types/tier";
import type { TierLevel } from "../../types/tier";
import { CreateAdminWizard } from "../admin";
import { CsvBulkImport } from "../import";

interface StatCardProps {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  bgColor: string;
  borderColor: string;
  onClick?: () => void;
}

function StatCard({ label, value, icon: Icon, color, bgColor, borderColor, onClick }: StatCardProps) {
  return (
    <div
      onClick={onClick}
      className={`bg-white dark:bg-surface-850 rounded-xl border ${borderColor} p-6 transition-all ${
        onClick ? "cursor-pointer hover:shadow-md hover:scale-[1.02]" : ""
      }`}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{label}</p>
          <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
        </div>
        <div className={`w-14 h-14 rounded-xl ${bgColor} flex items-center justify-center`}>
          <Icon className={`w-7 h-7 ${color}`} />
        </div>
      </div>
    </div>
  );
}

function TierDistributionBar({ tierCounts }: { tierCounts: { Tier0: number; Tier1: number; Tier2: number; Unassigned: number } }) {
  const total = Object.values(tierCounts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const tiers: Array<{ key: TierLevel | "Unassigned"; config: typeof tierConfig[TierLevel] }> = [
    { key: "Tier0", config: tierConfig.Tier0 },
    { key: "Tier1", config: tierConfig.Tier1 },
    { key: "Tier2", config: tierConfig.Tier2 },
    { key: "Unassigned", config: tierConfig.Unassigned },
  ];

  return (
    <div className="bg-white dark:bg-surface-850 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center gap-2">
        <ChartBarIcon className="w-4 h-4" />
        Tier Distribution
      </h3>

      {/* Distribution bar */}
      <div className="h-8 rounded-lg overflow-hidden flex">
        {tiers.map(({ key, config }) => {
          const count = tierCounts[key] || 0;
          const percentage = (count / total) * 100;
          if (percentage === 0) return null;

          return (
            <div
              key={key}
              className={`${config.barColor} transition-all relative group`}
              style={{ width: `${percentage}%` }}
            >
              <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                <span className="text-xs font-semibold text-white drop-shadow-md">
                  {count}
                </span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="mt-4 flex flex-wrap gap-4">
        {tiers.map(({ key, config }) => {
          const count = tierCounts[key] || 0;
          const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : "0";

          return (
            <div key={key} className="flex items-center gap-2">
              <div className={`w-3 h-3 rounded ${config.barColor}`} />
              <span className="text-sm text-gray-600 dark:text-gray-400">
                {config.shortLabel}: {count} ({percentage}%)
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ComplianceScoreRing({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 36;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getScoreColor = (s: number) => {
    if (s >= 90) return { stroke: "stroke-green-500", text: "text-green-600 dark:text-green-400" };
    if (s >= 70) return { stroke: "stroke-amber-500", text: "text-amber-600 dark:text-amber-400" };
    if (s >= 50) return { stroke: "stroke-orange-500", text: "text-orange-600 dark:text-orange-400" };
    return { stroke: "stroke-red-500", text: "text-red-600 dark:text-red-400" };
  };

  const colors = getScoreColor(score);

  return (
    <div className="relative w-20 h-20">
      <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
        <circle
          cx="40"
          cy="40"
          r="36"
          fill="none"
          stroke="currentColor"
          className="text-gray-200 dark:text-gray-700"
          strokeWidth="6"
        />
        <circle
          cx="40"
          cy="40"
          r="36"
          fill="none"
          className={colors.stroke}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: "stroke-dashoffset 0.5s ease-in-out" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className={`text-lg font-bold ${colors.text}`}>{score}</span>
      </div>
    </div>
  );
}

function ComplianceSummaryCard({ compliance }: { compliance: ComplianceStatus | undefined; isLoading: boolean }) {
  if (!compliance) {
    return (
      <div className="bg-white dark:bg-surface-850 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-center h-32">
          <ArrowPathIcon className="w-6 h-6 animate-spin text-blue-500" />
        </div>
      </div>
    );
  }

  const hasIssues = compliance.totalViolations > 0;

  return (
    <div className={`bg-white dark:bg-surface-850 rounded-xl border ${
      hasIssues ? "border-amber-200 dark:border-amber-800" : "border-green-200 dark:border-green-800"
    } p-6`}>
      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4 flex items-center gap-2">
        <ShieldExclamationIcon className="w-4 h-4" />
        Compliance Status
      </h3>

      <div className="flex items-center gap-6">
        <ComplianceScoreRing score={compliance.score} />

        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            {hasIssues ? (
              <>
                <ExclamationTriangleIcon className="w-5 h-5 text-amber-500" />
                <span className="text-sm font-medium text-amber-700 dark:text-amber-300">
                  {compliance.totalViolations} violation{compliance.totalViolations !== 1 ? "s" : ""} found
                </span>
              </>
            ) : (
              <>
                <CheckCircleIcon className="w-5 h-5 text-green-500" />
                <span className="text-sm font-medium text-green-700 dark:text-green-300">
                  Fully compliant
                </span>
              </>
            )}
          </div>

          {hasIssues && (
            <div className="flex gap-3 text-xs">
              {compliance.criticalCount > 0 && (
                <span className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded">
                  {compliance.criticalCount} Critical
                </span>
              )}
              {compliance.highCount > 0 && (
                <span className="px-2 py-1 bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300 rounded">
                  {compliance.highCount} High
                </span>
              )}
              {compliance.mediumCount > 0 && (
                <span className="px-2 py-1 bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 rounded">
                  {compliance.mediumCount} Medium
                </span>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ConnectionStatusCard() {
  const { domainInfo, isConnected } = useTierStore();

  return (
    <div className={`bg-white dark:bg-surface-850 rounded-xl border ${
      isConnected ? "border-green-200 dark:border-green-800" : "border-amber-200 dark:border-amber-800"
    } p-6`}>
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 flex items-center gap-2">
            {isConnected ? (
              <CheckCircleIcon className="w-4 h-4 text-green-500" />
            ) : (
              <XCircleIcon className="w-4 h-4 text-amber-500" />
            )}
            Domain Connection
          </h3>
          <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">
            {domainInfo?.dnsRoot || "Not connected"}
          </p>
          {domainInfo?.netbiosName && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              {domainInfo.netbiosName}
            </p>
          )}
        </div>
        <div className={`px-3 py-1 rounded-full text-xs font-medium ${
          isConnected
            ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
            : "bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
        }`}>
          {isConnected ? "Connected" : "Mock Mode"}
        </div>
      </div>
    </div>
  );
}

interface DashboardOverviewProps {
  onNavigateToTier?: (tier: TierLevel | "Unassigned") => void;
  onNavigateToCompliance?: () => void;
}

export function DashboardOverview({ onNavigateToTier, onNavigateToCompliance }: DashboardOverviewProps) {
  const { tierCounts } = useTierStore();
  const [showCreateAdminWizard, setShowCreateAdminWizard] = useState(false);
  const [showCsvImport, setShowCsvImport] = useState(false);

  const { data: compliance, isLoading: complianceLoading } = useQuery({
    queryKey: ["complianceStatus"],
    queryFn: getComplianceStatus,
    staleTime: 60_000,
  });

  const totalObjects = Object.values(tierCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
          <ChartBarIcon className="w-5 h-5" />
          Dashboard Overview
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Quick summary of your AD Tier Model status
        </p>
      </div>

      {/* Connection Status */}
      <ConnectionStatusCard />

      {/* Tier Counts Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Tier 0"
          value={tierCounts.Tier0}
          icon={ShieldCheckIcon}
          color="text-red-600 dark:text-red-400"
          bgColor="bg-red-100 dark:bg-red-900/30"
          borderColor="border-red-200 dark:border-red-800"
          onClick={() => onNavigateToTier?.("Tier0")}
        />
        <StatCard
          label="Tier 1"
          value={tierCounts.Tier1}
          icon={ServerIcon}
          color="text-amber-600 dark:text-amber-400"
          bgColor="bg-amber-100 dark:bg-amber-900/30"
          borderColor="border-amber-200 dark:border-amber-800"
          onClick={() => onNavigateToTier?.("Tier1")}
        />
        <StatCard
          label="Tier 2"
          value={tierCounts.Tier2}
          icon={ComputerDesktopIcon}
          color="text-green-600 dark:text-green-400"
          bgColor="bg-green-100 dark:bg-green-900/30"
          borderColor="border-green-200 dark:border-green-800"
          onClick={() => onNavigateToTier?.("Tier2")}
        />
        <StatCard
          label="Unassigned"
          value={tierCounts.Unassigned}
          icon={QuestionMarkCircleIcon}
          color="text-gray-600 dark:text-gray-400"
          bgColor="bg-gray-100 dark:bg-gray-700"
          borderColor="border-gray-200 dark:border-gray-700"
          onClick={() => onNavigateToTier?.("Unassigned")}
        />
      </div>

      {/* Distribution and Compliance Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TierDistributionBar tierCounts={tierCounts} />
        <div onClick={onNavigateToCompliance} className={onNavigateToCompliance ? "cursor-pointer" : ""}>
          <ComplianceSummaryCard compliance={compliance} isLoading={complianceLoading} />
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white dark:bg-surface-850 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">
          Quick Actions
        </h3>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => setShowCreateAdminWizard(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
          >
            <UserPlusIcon className="w-4 h-4" />
            Create Admin Account
          </button>
          <button
            onClick={() => setShowCsvImport(true)}
            className="flex items-center gap-2 px-4 py-2 bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded-lg hover:bg-green-100 dark:hover:bg-green-900/50 transition-colors"
          >
            <DocumentArrowUpIcon className="w-4 h-4" />
            CSV Bulk Import
          </button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="bg-white dark:bg-surface-850 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-4">
          Quick Stats
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
            <p className="text-2xl font-bold text-gray-900 dark:text-white">{totalObjects}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Total Objects</p>
          </div>
          <div className="text-center p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
            <p className="text-2xl font-bold text-red-600 dark:text-red-400">
              {tierCounts.Tier0}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Critical Assets</p>
          </div>
          <div className="text-center p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
            <p className="text-2xl font-bold text-amber-600 dark:text-amber-400">
              {tierCounts.Unassigned}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Need Assignment</p>
          </div>
          <div className="text-center p-4 bg-gray-50 dark:bg-surface-900 rounded-lg">
            <p className="text-2xl font-bold text-purple-600 dark:text-purple-400">
              {compliance?.totalViolations || 0}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">Violations</p>
          </div>
        </div>
      </div>

      {/* Create Admin Wizard */}
      <CreateAdminWizard
        isOpen={showCreateAdminWizard}
        onClose={() => setShowCreateAdminWizard(false)}
      />

      {/* CSV Bulk Import */}
      <CsvBulkImport
        isOpen={showCsvImport}
        onClose={() => setShowCsvImport(false)}
      />
    </div>
  );
}
