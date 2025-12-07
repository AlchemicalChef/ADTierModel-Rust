import { useState, useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ShieldExclamationIcon,
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  ExclamationCircleIcon,
  InformationCircleIcon,
  ArrowPathIcon,
  UserGroupIcon,
  ChevronRightIcon,
  DocumentArrowDownIcon,
  WrenchScrewdriverIcon,
  CheckCircleIcon,
  NoSymbolIcon,
  ClockIcon,
  LockClosedIcon,
  KeyIcon,
} from "@heroicons/react/24/outline";
import { Menu, Dialog } from "@headlessui/react";
import {
  moveObjectToTier,
  bulkDisableStaleAccounts,
  hardenServiceAccounts,
  type ComplianceViolation,
  type CrossTierAccess,
  type ViolationSeverity,
  type ViolationType,
} from "../../services/tauri";
import { useComplianceStatus } from "../../hooks/useTierData";
import { notify } from "../../store/notificationStore";
import { tierConfig } from "../../types/tier";
import type { TierLevel } from "../../types/tier";
import { exportComplianceReportToCSV, exportComplianceViolationsToCSV } from "../../services/export";
import { exportHtmlReport, type ReportData } from "../../services/exportService";
import { logAudit } from "../../store/auditStore";
import { useTierStore } from "../../store/tierStore";
import { useComplianceHistoryStore } from "../../store/complianceHistoryStore";
import { ComplianceTrendChart } from "./ComplianceTrendChart";

function getSeverityConfig(severity: ViolationSeverity) {
  switch (severity) {
    case "critical":
      return {
        icon: ShieldExclamationIcon,
        bgColor: "bg-red-100 dark:bg-red-900/30",
        textColor: "text-red-700 dark:text-red-300",
        borderColor: "border-red-200 dark:border-red-800",
        label: "Critical",
      };
    case "high":
      return {
        icon: ExclamationCircleIcon,
        bgColor: "bg-orange-100 dark:bg-orange-900/30",
        textColor: "text-orange-700 dark:text-orange-300",
        borderColor: "border-orange-200 dark:border-orange-800",
        label: "High",
      };
    case "medium":
      return {
        icon: ExclamationTriangleIcon,
        bgColor: "bg-amber-100 dark:bg-amber-900/30",
        textColor: "text-amber-700 dark:text-amber-300",
        borderColor: "border-amber-200 dark:border-amber-800",
        label: "Medium",
      };
    case "low":
      return {
        icon: InformationCircleIcon,
        bgColor: "bg-blue-100 dark:bg-blue-900/30",
        textColor: "text-blue-700 dark:text-blue-300",
        borderColor: "border-blue-200 dark:border-blue-800",
        label: "Low",
      };
  }
}

function getScoreColor(score: number): string {
  if (score >= 90) return "text-green-600 dark:text-green-400";
  if (score >= 70) return "text-amber-600 dark:text-amber-400";
  if (score >= 50) return "text-orange-600 dark:text-orange-400";
  return "text-red-600 dark:text-red-400";
}

function getScoreRingColor(score: number): string {
  if (score >= 90) return "stroke-green-500";
  if (score >= 70) return "stroke-amber-500";
  if (score >= 50) return "stroke-orange-500";
  return "stroke-red-500";
}

// Check if a violation can be auto-remediated
function canAutoRemediate(violationType: ViolationType): boolean {
  return [
    "misplacedTier0Infrastructure",
    "wrongTierPlacement",
  ].includes(violationType);
}

// Get the suggested remediation action
function getRemediationAction(violation: ComplianceViolation): { action: string; targetTier?: TierLevel } | null {
  switch (violation.violationType) {
    case "misplacedTier0Infrastructure":
      return { action: "move", targetTier: "Tier0" };
    case "wrongTierPlacement":
      // The first tier mentioned is usually the correct one
      if (violation.tiersInvolved.length > 0) {
        return { action: "move", targetTier: violation.tiersInvolved[0] };
      }
      return null;
    default:
      return null;
  }
}

interface ViolationCardProps {
  violation: ComplianceViolation;
  onRemediate?: (violation: ComplianceViolation) => void;
}

function ViolationCard({ violation, onRemediate }: ViolationCardProps) {
  const config = getSeverityConfig(violation.severity);
  const Icon = config.icon;
  const canFix = canAutoRemediate(violation.violationType);

  return (
    <div
      className={`bg-white dark:bg-surface-850 rounded-lg border ${config.borderColor} p-4`}
    >
      <div className="flex items-start gap-3">
        <div
          className={`flex-shrink-0 w-10 h-10 rounded-lg ${config.bgColor} flex items-center justify-center`}
        >
          <Icon className={`w-5 h-5 ${config.textColor}`} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">
                {violation.objectName}
              </h4>
              <span
                className={`px-2 py-0.5 text-xs font-medium rounded ${config.bgColor} ${config.textColor}`}
              >
                {config.label}
              </span>
            </div>

            {canFix && onRemediate && (
              <button
                onClick={() => onRemediate(violation)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
              >
                <WrenchScrewdriverIcon className="w-3.5 h-3.5" />
                Fix
              </button>
            )}
          </div>

          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {violation.description}
          </p>

          {violation.tiersInvolved.length > 0 && (
            <div className="flex items-center gap-1 mt-2">
              {violation.tiersInvolved.map((tier, idx) => {
                const tierCfg = tierConfig[tier as TierLevel];
                return (
                  <span key={tier} className="flex items-center gap-1">
                    {idx > 0 && (
                      <ChevronRightIcon className="w-3 h-3 text-gray-400" />
                    )}
                    <span
                      className={`px-1.5 py-0.5 text-xs font-medium rounded ${tierCfg?.bgColor || "bg-gray-100"} ${tierCfg?.textColor || "text-gray-600"}`}
                    >
                      {tier}
                    </span>
                  </span>
                );
              })}
            </div>
          )}

          <p className="text-xs text-gray-500 dark:text-gray-500 mt-2 font-mono truncate">
            {violation.objectDn}
          </p>

          <div className="mt-3 p-2 bg-gray-50 dark:bg-surface-900 rounded">
            <p className="text-xs text-gray-600 dark:text-gray-400">
              <span className="font-medium">Remediation:</span>{" "}
              {violation.remediation}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

// Remediation confirmation modal
interface RemediationModalProps {
  violation: ComplianceViolation | null;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

function RemediationModal({ violation, isOpen, onClose, onSuccess }: RemediationModalProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  if (!violation) return null;

  const remediationAction = getRemediationAction(violation);

  const handleRemediate = async () => {
    if (!remediationAction) return;

    setIsLoading(true);
    setError(null);

    try {
      if (remediationAction.action === "move" && remediationAction.targetTier) {
        await moveObjectToTier(violation.objectDn, remediationAction.targetTier);

        logAudit(
          "remediate_violation",
          `Moved ${violation.objectName} to ${remediationAction.targetTier} to fix ${violation.violationType}`,
          [violation.samAccountName],
          true,
          { targetTier: remediationAction.targetTier, details: { violationType: violation.violationType } }
        );

        setSuccess(true);
        setTimeout(() => {
          onSuccess();
          onClose();
          setSuccess(false);
        }, 1500);
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Remediation failed";

      logAudit(
        "remediate_violation",
        `Failed to remediate ${violation.objectName}: ${errorMsg}`,
        [violation.samAccountName],
        false,
        { error: errorMsg, details: { violationType: violation.violationType } }
      );

      setError(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setError(null);
    setSuccess(false);
    onClose();
  };

  return (
    <Dialog open={isOpen} onClose={handleClose} className="relative z-50">
      <div className="fixed inset-0 bg-black/50" aria-hidden="true" />

      <div className="fixed inset-0 flex items-center justify-center p-4">
        <Dialog.Panel className="mx-auto max-w-md w-full bg-white dark:bg-surface-800 rounded-xl shadow-2xl">
          <div className="p-6">
            {success ? (
              <div className="text-center py-8">
                <CheckCircleIcon className="w-16 h-16 text-green-500 mx-auto mb-4" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Remediation Complete
                </h3>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
                  The violation has been fixed successfully.
                </p>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
                    <WrenchScrewdriverIcon className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                  </div>
                  <div>
                    <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                      Confirm Remediation
                    </Dialog.Title>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      This action will fix the compliance violation
                    </p>
                  </div>
                </div>

                <div className="bg-gray-50 dark:bg-surface-700 rounded-lg p-4 mb-4">
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    <span className="font-medium">Object:</span> {violation.objectName}
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    <span className="font-medium">Issue:</span> {violation.description}
                  </p>
                  {remediationAction?.targetTier && (
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      <span className="font-medium">Action:</span> Move to {remediationAction.targetTier}
                    </p>
                  )}
                </div>

                <div className="bg-amber-50 dark:bg-amber-900/20 rounded-lg p-3 mb-4">
                  <p className="text-xs text-amber-700 dark:text-amber-300">
                    <ExclamationTriangleIcon className="w-4 h-4 inline mr-1" />
                    This action will modify Active Directory. Make sure you have the necessary permissions.
                  </p>
                </div>

                {error && (
                  <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3 mb-4 text-sm text-red-700 dark:text-red-300">
                    {error}
                  </div>
                )}

                <div className="flex justify-end gap-3">
                  <button
                    onClick={handleClose}
                    disabled={isLoading}
                    className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleRemediate}
                    disabled={isLoading || !remediationAction}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                  >
                    {isLoading ? (
                      <>
                        <ArrowPathIcon className="w-4 h-4 animate-spin" />
                        Applying...
                      </>
                    ) : (
                      <>
                        <WrenchScrewdriverIcon className="w-4 h-4" />
                        Apply Fix
                      </>
                    )}
                  </button>
                </div>
              </>
            )}
          </div>
        </Dialog.Panel>
      </div>
    </Dialog>
  );
}

interface CrossTierCardProps {
  access: CrossTierAccess;
}

function CrossTierCard({ access }: CrossTierCardProps) {
  return (
    <div className="bg-white dark:bg-surface-850 rounded-lg border border-red-200 dark:border-red-800 p-4">
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
          <UserGroupIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
        </div>

        <div className="flex-1 min-w-0">
          <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">
            {access.accountName}
          </h4>

          <div className="flex items-center gap-1 mt-2">
            <span className="text-xs text-gray-500">Access to:</span>
            {access.tiers.map((tier, idx) => {
              const tierCfg = tierConfig[tier as TierLevel];
              return (
                <span key={tier} className="flex items-center gap-1">
                  {idx > 0 && <span className="text-gray-400">+</span>}
                  <span
                    className={`px-1.5 py-0.5 text-xs font-medium rounded ${tierCfg?.bgColor || "bg-gray-100"} ${tierCfg?.textColor || "text-gray-600"}`}
                  >
                    {tier}
                  </span>
                </span>
              );
            })}
          </div>

          <div className="mt-2">
            <p className="text-xs text-gray-500">Via groups:</p>
            <div className="flex flex-wrap gap-1 mt-1">
              {access.groups.map((group) => (
                <span
                  key={group}
                  className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 rounded"
                >
                  {group}
                </span>
              ))}
            </div>
          </div>

          <p className="text-xs text-gray-500 dark:text-gray-500 mt-2 font-mono truncate">
            {access.accountDn}
          </p>
        </div>
      </div>
    </div>
  );
}

function ScoreRing({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="relative w-32 h-32">
      <svg className="w-32 h-32 -rotate-90" viewBox="0 0 100 100">
        {/* Background ring */}
        <circle
          cx="50"
          cy="50"
          r="45"
          fill="none"
          stroke="currentColor"
          className="text-gray-200 dark:text-gray-700"
          strokeWidth="8"
        />
        {/* Score ring */}
        <circle
          cx="50"
          cy="50"
          r="45"
          fill="none"
          className={getScoreRingColor(score)}
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{ transition: "stroke-dashoffset 0.5s ease-in-out" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className={`text-3xl font-bold ${getScoreColor(score)}`}>
          {score}
        </span>
      </div>
    </div>
  );
}

export function ComplianceDashboard() {
  const queryClient = useQueryClient();
  const [selectedViolation, setSelectedViolation] = useState<ComplianceViolation | null>(null);
  const [showRemediationModal, setShowRemediationModal] = useState(false);
  const [showBulkDisableModal, setShowBulkDisableModal] = useState(false);
  const [bulkDisableLoading, setBulkDisableLoading] = useState(false);
  const [showHardenModal, setShowHardenModal] = useState(false);
  const [hardenLoading, setHardenLoading] = useState(false);
  const [exportingHtml, setExportingHtml] = useState(false);
  const { addSnapshot } = useComplianceHistoryStore();
  const { domainInfo, tierCounts } = useTierStore();

  const {
    data: compliance,
    isLoading,
    refetch,
    isFetching,
  } = useComplianceStatus();

  // Record compliance snapshot when data is fetched
  useEffect(() => {
    if (compliance) {
      addSnapshot({
        score: compliance.score,
        totalViolations: compliance.totalViolations,
        criticalCount: compliance.criticalCount,
        highCount: compliance.highCount,
        mediumCount: compliance.mediumCount,
        lowCount: compliance.lowCount,
      });
    }
  }, [compliance, addSnapshot]);

  const handleRemediate = (violation: ComplianceViolation) => {
    setSelectedViolation(violation);
    setShowRemediationModal(true);
  };

  const handleRemediationSuccess = () => {
    // Refetch compliance data and tier data
    refetch();
    queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
    queryClient.invalidateQueries({ queryKey: ["tierCounts"] });
  };

  // Get stale account violations
  const staleAccountViolations = compliance?.violations.filter(
    (v) => v.violationType === "staleAccount"
  ) || [];

  // Get service account violations (not marked as sensitive)
  const serviceAccountViolations = compliance?.violations.filter(
    (v) => v.violationType === "serviceAccountInteractiveLogon"
  ) || [];

  // Handle bulk disable of stale accounts
  const handleBulkDisable = async () => {
    if (staleAccountViolations.length === 0) return;

    setBulkDisableLoading(true);
    try {
      const objectDns = staleAccountViolations.map((v) => v.objectDn);
      const result = await bulkDisableStaleAccounts(objectDns);

      if (result.successCount > 0) {
        logAudit(
          "bulk_disable",
          `Disabled ${result.successCount} stale accounts`,
          result.disabledAccounts.map((dn) => dn.split(",")[0]?.replace("CN=", "") || dn),
          true,
          { details: { count: result.successCount } }
        );

        notify.success(
          "Accounts Disabled",
          `Successfully disabled ${result.successCount} stale account${result.successCount > 1 ? "s" : ""}`
        );
      }

      if (result.failureCount > 0) {
        notify.warning(
          "Some Disables Failed",
          `${result.failureCount} account${result.failureCount > 1 ? "s" : ""} could not be disabled`
        );
      }

      // Refresh data
      refetch();
      queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
      queryClient.invalidateQueries({ queryKey: ["tierCounts"] });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Bulk disable failed";
      notify.error("Bulk Disable Failed", errorMsg);

      logAudit(
        "bulk_disable",
        `Failed to bulk disable stale accounts: ${errorMsg}`,
        staleAccountViolations.map((v) => v.samAccountName),
        false,
        { error: errorMsg }
      );
    } finally {
      setBulkDisableLoading(false);
      setShowBulkDisableModal(false);
    }
  };

  // Handle hardening service accounts
  const handleHardenServiceAccounts = async () => {
    if (serviceAccountViolations.length === 0) return;

    setHardenLoading(true);
    try {
      const objectDns = serviceAccountViolations.map((v) => v.objectDn);
      const result = await hardenServiceAccounts(objectDns);

      if (result.successCount > 0) {
        logAudit(
          "remediate_violation",
          `Hardened ${result.successCount} service accounts (marked as sensitive)`,
          result.hardenedAccounts.map((dn) => dn.split(",")[0]?.replace("CN=", "") || dn),
          true,
          { details: { action: "harden_service_accounts", count: result.successCount } }
        );

        notify.success(
          "Accounts Hardened",
          `Successfully hardened ${result.successCount} service account${result.successCount > 1 ? "s" : ""}`
        );
      }

      if (result.failureCount > 0) {
        notify.warning(
          "Some Hardening Failed",
          `${result.failureCount} account${result.failureCount > 1 ? "s" : ""} could not be hardened`
        );
      }

      // Refresh data
      refetch();
      queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Hardening failed";
      notify.error("Hardening Failed", errorMsg);

      logAudit(
        "remediate_violation",
        `Failed to harden service accounts: ${errorMsg}`,
        serviceAccountViolations.map((v) => v.samAccountName),
        false,
        { error: errorMsg }
      );
    } finally {
      setHardenLoading(false);
      setShowHardenModal(false);
    }
  };

  // Handle HTML report export
  const handleExportHtmlReport = async () => {
    if (!compliance) return;

    setExportingHtml(true);
    try {
      const reportData: ReportData = {
        domainInfo: domainInfo || null,
        tierCounts: tierCounts || null,
        complianceStatus: compliance,
        gpoStatus: null, // Could fetch this if needed
        generatedAt: new Date(),
      };

      const result = await exportHtmlReport(reportData);

      if (result.success && result.filePath) {
        notify.success("Report Exported", `Report saved to ${result.filePath}`);
        logAudit(
          "export",
          "Exported HTML compliance report",
          [],
          true,
          { details: { filePath: result.filePath } }
        );
      } else if (result.error && result.error !== "Export cancelled") {
        notify.error("Export Failed", result.error);
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Export failed";
      notify.error("Export Failed", errorMsg);
    } finally {
      setExportingHtml(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <ArrowPathIcon className="w-8 h-8 animate-spin text-blue-500 mx-auto mb-4" />
          <p className="text-gray-500 dark:text-gray-400">
            Running compliance checks...
          </p>
        </div>
      </div>
    );
  }

  if (!compliance) {
    return (
      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
        Unable to load compliance data.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Score and Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Compliance Score */}
        <div className="bg-white dark:bg-surface-850 rounded-xl border border-gray-200 dark:border-gray-700 p-6 flex flex-col items-center">
          <h3 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-4">
            Compliance Score
          </h3>
          <ScoreRing score={compliance.score} />
          <p className="text-xs text-gray-500 mt-4">
            Last checked:{" "}
            {new Date(compliance.lastChecked).toLocaleString()}
          </p>
          <div className="mt-4 flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {isFetching ? (
                <>
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  Checking...
                </>
              ) : (
                <>
                  <ArrowPathIcon className="w-4 h-4" />
                  Recheck
                </>
              )}
            </button>

            {/* Export Menu */}
            <Menu as="div" className="relative">
              <Menu.Button
                disabled={isFetching || exportingHtml}
                className="flex items-center gap-2 px-3 py-2 text-sm bg-white dark:bg-surface-800 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-surface-700 disabled:opacity-50 transition-colors"
              >
                {exportingHtml ? (
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                ) : (
                  <DocumentArrowDownIcon className="w-4 h-4" />
                )}
                Export
              </Menu.Button>
              <Menu.Items className="absolute left-0 mt-1 w-56 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20">
                <div className="px-3 py-2 border-b border-gray-100 dark:border-gray-700">
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    HTML Report
                  </p>
                </div>
                <Menu.Item>
                  {({ active }) => (
                    <button
                      onClick={handleExportHtmlReport}
                      className={`flex items-center gap-2 w-full px-3 py-2 text-sm text-left ${
                        active ? "bg-gray-100 dark:bg-surface-700" : ""
                      } text-gray-700 dark:text-gray-300`}
                    >
                      <DocumentArrowDownIcon className="w-4 h-4" />
                      Full HTML Report
                    </button>
                  )}
                </Menu.Item>
                <div className="px-3 py-2 border-b border-t border-gray-100 dark:border-gray-700 mt-1">
                  <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                    CSV Export
                  </p>
                </div>
                <Menu.Item>
                  {({ active }) => (
                    <button
                      onClick={() => exportComplianceReportToCSV(compliance)}
                      className={`flex items-center gap-2 w-full px-3 py-2 text-sm text-left ${
                        active ? "bg-gray-100 dark:bg-surface-700" : ""
                      } text-gray-700 dark:text-gray-300`}
                    >
                      Full Report (CSV)
                    </button>
                  )}
                </Menu.Item>
                <Menu.Item>
                  {({ active }) => (
                    <button
                      onClick={() =>
                        exportComplianceViolationsToCSV(compliance.violations)
                      }
                      disabled={compliance.violations.length === 0}
                      className={`flex items-center gap-2 w-full px-3 py-2 text-sm text-left ${
                        active ? "bg-gray-100 dark:bg-surface-700" : ""
                      } ${
                        compliance.violations.length === 0
                          ? "text-gray-400 cursor-not-allowed"
                          : "text-gray-700 dark:text-gray-300"
                      }`}
                    >
                      Violations Only (CSV)
                    </button>
                  )}
                </Menu.Item>
              </Menu.Items>
            </Menu>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="lg:col-span-3 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-surface-850 rounded-lg border border-red-200 dark:border-red-800 p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-red-100 dark:bg-red-900/30 flex items-center justify-center">
                <ShieldExclamationIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {compliance.criticalCount}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Critical
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-surface-850 rounded-lg border border-orange-200 dark:border-orange-800 p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center">
                <ExclamationCircleIcon className="w-5 h-5 text-orange-600 dark:text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {compliance.highCount}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">High</p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-surface-850 rounded-lg border border-amber-200 dark:border-amber-800 p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
                <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {compliance.mediumCount}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Medium
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-surface-850 rounded-lg border border-blue-200 dark:border-blue-800 p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
                <InformationCircleIcon className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                  {compliance.lowCount}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">Low</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Trend Chart */}
      <ComplianceTrendChart days={30} />

      {/* No violations message */}
      {compliance.totalViolations === 0 && (
        <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-xl p-8 text-center">
          <ShieldCheckIcon className="w-16 h-16 text-green-500 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-green-800 dark:text-green-200">
            No Compliance Violations
          </h3>
          <p className="text-sm text-green-600 dark:text-green-400 mt-2">
            Your AD Tier Model is fully compliant. Keep up the good work!
          </p>
        </div>
      )}

      {/* Cross-Tier Access Section */}
      {compliance.crossTierAccess.length > 0 && (
        <section>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-red-700 dark:text-red-300 mb-3">
            <ShieldExclamationIcon className="w-4 h-4" />
            Cross-Tier Access Violations ({compliance.crossTierAccess.length})
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            These accounts have membership in groups across multiple tiers,
            violating tier separation. This is a critical security risk.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {compliance.crossTierAccess.map((access) => (
              <CrossTierCard key={access.accountDn} access={access} />
            ))}
          </div>
        </section>
      )}

      {/* Stale Accounts Section */}
      {staleAccountViolations.length > 0 && (
        <section className="bg-amber-50 dark:bg-amber-900/10 rounded-xl border border-amber-200 dark:border-amber-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-amber-700 dark:text-amber-300">
                <ClockIcon className="w-4 h-4" />
                Stale Accounts ({staleAccountViolations.length})
              </h3>
              <p className="text-sm text-amber-600 dark:text-amber-400 mt-1">
                These accounts have not logged in for an extended period and may pose a security risk.
              </p>
            </div>
            <button
              onClick={() => setShowBulkDisableModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-amber-600 text-white text-sm font-medium rounded-lg hover:bg-amber-700 transition-colors"
            >
              <NoSymbolIcon className="w-4 h-4" />
              Disable All ({staleAccountViolations.length})
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {staleAccountViolations.slice(0, 6).map((violation) => (
              <div
                key={violation.objectDn}
                className="bg-white dark:bg-surface-850 rounded-lg border border-amber-200 dark:border-amber-700 p-3"
              >
                <div className="flex items-center gap-2">
                  <ClockIcon className="w-4 h-4 text-amber-500 flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                      {violation.objectName}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      {violation.description}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {staleAccountViolations.length > 6 && (
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-3 text-center">
              And {staleAccountViolations.length - 6} more stale accounts...
            </p>
          )}
        </section>
      )}

      {/* Service Account Security Section */}
      {serviceAccountViolations.length > 0 && (
        <section className="bg-purple-50 dark:bg-purple-900/10 rounded-xl border border-purple-200 dark:border-purple-800 p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="flex items-center gap-2 text-sm font-semibold text-purple-700 dark:text-purple-300">
                <KeyIcon className="w-4 h-4" />
                Unsecured Service Accounts ({serviceAccountViolations.length})
              </h3>
              <p className="text-sm text-purple-600 dark:text-purple-400 mt-1">
                These service accounts are not marked as sensitive and may be vulnerable to credential theft attacks.
              </p>
            </div>
            <button
              onClick={() => setShowHardenModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white text-sm font-medium rounded-lg hover:bg-purple-700 transition-colors"
            >
              <LockClosedIcon className="w-4 h-4" />
              Harden All ({serviceAccountViolations.length})
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {serviceAccountViolations.slice(0, 6).map((violation) => (
              <div
                key={violation.objectDn}
                className="bg-white dark:bg-surface-850 rounded-lg border border-purple-200 dark:border-purple-700 p-3"
              >
                <div className="flex items-center gap-2">
                  <KeyIcon className="w-4 h-4 text-purple-500 flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                      {violation.objectName}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                      {violation.samAccountName}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {serviceAccountViolations.length > 6 && (
            <p className="text-xs text-purple-600 dark:text-purple-400 mt-3 text-center">
              And {serviceAccountViolations.length - 6} more service accounts...
            </p>
          )}
        </section>
      )}

      {/* All Violations Section */}
      {compliance.violations.length > 0 && (
        <section>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
            <ExclamationTriangleIcon className="w-4 h-4" />
            All Violations ({compliance.violations.length})
          </h3>
          <div className="grid grid-cols-1 gap-4">
            {compliance.violations.map((violation, idx) => (
              <ViolationCard
                key={`${violation.objectDn}-${idx}`}
                violation={violation}
                onRemediate={handleRemediate}
              />
            ))}
          </div>
        </section>
      )}

      {/* Remediation Modal */}
      <RemediationModal
        violation={selectedViolation}
        isOpen={showRemediationModal}
        onClose={() => {
          setShowRemediationModal(false);
          setSelectedViolation(null);
        }}
        onSuccess={handleRemediationSuccess}
      />

      {/* Bulk Disable Confirmation Modal */}
      <Dialog
        open={showBulkDisableModal}
        onClose={() => !bulkDisableLoading && setShowBulkDisableModal(false)}
        className="relative z-50"
      >
        <div className="fixed inset-0 bg-black/50" aria-hidden="true" />
        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Dialog.Panel className="mx-auto max-w-md w-full bg-white dark:bg-surface-800 rounded-xl shadow-2xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-full bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
                <NoSymbolIcon className="w-6 h-6 text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                  Disable Stale Accounts
                </Dialog.Title>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  This action cannot be easily undone
                </p>
              </div>
            </div>

            <div className="bg-amber-50 dark:bg-amber-900/20 rounded-lg p-4 mb-4">
              <p className="text-sm text-amber-800 dark:text-amber-200">
                You are about to disable <strong>{staleAccountViolations.length}</strong> stale account{staleAccountViolations.length > 1 ? "s" : ""}.
                These accounts will no longer be able to log in until re-enabled.
              </p>
            </div>

            <div className="max-h-40 overflow-y-auto mb-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              {staleAccountViolations.map((v) => (
                <div
                  key={v.objectDn}
                  className="px-3 py-2 text-sm border-b border-gray-100 dark:border-gray-700 last:border-0"
                >
                  <span className="font-medium text-gray-900 dark:text-gray-100">
                    {v.objectName}
                  </span>
                  <span className="text-gray-500 dark:text-gray-400 ml-2">
                    ({v.samAccountName})
                  </span>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowBulkDisableModal(false)}
                disabled={bulkDisableLoading}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkDisable}
                disabled={bulkDisableLoading}
                className="flex items-center gap-2 px-4 py-2 bg-amber-600 text-white rounded-lg hover:bg-amber-700 transition-colors disabled:opacity-50"
              >
                {bulkDisableLoading ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    Disabling...
                  </>
                ) : (
                  <>
                    <NoSymbolIcon className="w-4 h-4" />
                    Disable All
                  </>
                )}
              </button>
            </div>
          </Dialog.Panel>
        </div>
      </Dialog>

      {/* Harden Service Accounts Confirmation Modal */}
      <Dialog
        open={showHardenModal}
        onClose={() => !hardenLoading && setShowHardenModal(false)}
        className="relative z-50"
      >
        <div className="fixed inset-0 bg-black/50" aria-hidden="true" />
        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Dialog.Panel className="mx-auto max-w-md w-full bg-white dark:bg-surface-800 rounded-xl shadow-2xl p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-full bg-purple-100 dark:bg-purple-900/30 flex items-center justify-center">
                <LockClosedIcon className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              </div>
              <div>
                <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                  Harden Service Accounts
                </Dialog.Title>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Mark as sensitive to prevent credential theft
                </p>
              </div>
            </div>

            <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4 mb-4">
              <p className="text-sm text-purple-800 dark:text-purple-200">
                You are about to harden <strong>{serviceAccountViolations.length}</strong> service account{serviceAccountViolations.length > 1 ? "s" : ""}.
                This will mark them as "sensitive and cannot be delegated", preventing credential theft attacks like Kerberos delegation abuse.
              </p>
            </div>

            <div className="max-h-40 overflow-y-auto mb-4 border border-gray-200 dark:border-gray-700 rounded-lg">
              {serviceAccountViolations.map((v) => (
                <div
                  key={v.objectDn}
                  className="px-3 py-2 text-sm border-b border-gray-100 dark:border-gray-700 last:border-0"
                >
                  <span className="font-medium text-gray-900 dark:text-gray-100">
                    {v.objectName}
                  </span>
                  <span className="text-gray-500 dark:text-gray-400 ml-2">
                    ({v.samAccountName})
                  </span>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowHardenModal(false)}
                disabled={hardenLoading}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleHardenServiceAccounts}
                disabled={hardenLoading}
                className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors disabled:opacity-50"
              >
                {hardenLoading ? (
                  <>
                    <ArrowPathIcon className="w-4 h-4 animate-spin" />
                    Hardening...
                  </>
                ) : (
                  <>
                    <LockClosedIcon className="w-4 h-4" />
                    Harden All
                  </>
                )}
              </button>
            </div>
          </Dialog.Panel>
        </div>
      </Dialog>
    </div>
  );
}
