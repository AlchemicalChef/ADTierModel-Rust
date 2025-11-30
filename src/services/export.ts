/**
 * Export service for generating CSV reports
 */

import type { TierMember, TierLevel } from "../types/tier";
import type { ComplianceStatus, ComplianceViolation, CrossTierAccess } from "./tauri";

/**
 * Convert data to CSV format
 */
function toCSV(headers: string[], rows: string[][]): string {
  const escapeCell = (cell: string): string => {
    if (cell.includes(",") || cell.includes('"') || cell.includes("\n")) {
      return `"${cell.replace(/"/g, '""')}"`;
    }
    return cell;
  };

  const headerLine = headers.map(escapeCell).join(",");
  const dataLines = rows.map((row) => row.map(escapeCell).join(","));

  return [headerLine, ...dataLines].join("\n");
}

/**
 * Trigger a file download in the browser
 */
function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Export tier members to CSV
 */
export function exportTierMembersToCSV(
  members: TierMember[],
  tier: TierLevel | "Unassigned"
): void {
  const headers = [
    "Name",
    "SAM Account Name",
    "Object Type",
    "Tier",
    "Enabled",
    "Last Logon",
    "Operating System",
    "Role Type",
    "Distinguished Name",
    "Description",
  ];

  const rows = members.map((m) => [
    m.name,
    m.samAccountName,
    m.objectType,
    m.tier || "Unassigned",
    m.enabled ? "Yes" : "No",
    m.lastLogon || "Never",
    m.operatingSystem || "",
    m.roleType || "",
    m.distinguishedName,
    m.description || "",
  ]);

  const csv = toCSV(headers, rows);
  const timestamp = new Date().toISOString().split("T")[0];
  downloadFile(csv, `${tier}-members-${timestamp}.csv`, "text/csv;charset=utf-8;");
}

/**
 * Export all tiers to CSV
 */
export function exportAllTiersToCSV(
  tier0: TierMember[],
  tier1: TierMember[],
  tier2: TierMember[],
  unassigned: TierMember[]
): void {
  const allMembers = [
    ...tier0.map((m) => ({ ...m, tier: "Tier0" as TierLevel })),
    ...tier1.map((m) => ({ ...m, tier: "Tier1" as TierLevel })),
    ...tier2.map((m) => ({ ...m, tier: "Tier2" as TierLevel })),
    ...unassigned.map((m) => ({ ...m, tier: undefined })),
  ];

  const headers = [
    "Name",
    "SAM Account Name",
    "Object Type",
    "Tier",
    "Enabled",
    "Last Logon",
    "Operating System",
    "Role Type",
    "Distinguished Name",
    "Description",
  ];

  const rows = allMembers.map((m) => [
    m.name,
    m.samAccountName,
    m.objectType,
    m.tier || "Unassigned",
    m.enabled ? "Yes" : "No",
    m.lastLogon || "Never",
    m.operatingSystem || "",
    m.roleType || "",
    m.distinguishedName,
    m.description || "",
  ]);

  const csv = toCSV(headers, rows);
  const timestamp = new Date().toISOString().split("T")[0];
  downloadFile(csv, `all-tiers-${timestamp}.csv`, "text/csv;charset=utf-8;");
}

/**
 * Export compliance violations to CSV
 */
export function exportComplianceViolationsToCSV(
  violations: ComplianceViolation[]
): void {
  const headers = [
    "Object Name",
    "SAM Account Name",
    "Violation Type",
    "Severity",
    "Description",
    "Tiers Involved",
    "Remediation",
    "Distinguished Name",
  ];

  const rows = violations.map((v) => [
    v.objectName,
    v.samAccountName,
    v.violationType,
    v.severity,
    v.description,
    v.tiersInvolved.join(", "),
    v.remediation,
    v.objectDn,
  ]);

  const csv = toCSV(headers, rows);
  const timestamp = new Date().toISOString().split("T")[0];
  downloadFile(csv, `compliance-violations-${timestamp}.csv`, "text/csv;charset=utf-8;");
}

/**
 * Export cross-tier access to CSV
 */
export function exportCrossTierAccessToCSV(
  crossTierAccess: CrossTierAccess[]
): void {
  const headers = [
    "Account Name",
    "Tiers",
    "Groups",
    "Distinguished Name",
  ];

  const rows = crossTierAccess.map((c) => [
    c.accountName,
    c.tiers.join(", "),
    c.groups.join("; "),
    c.accountDn,
  ]);

  const csv = toCSV(headers, rows);
  const timestamp = new Date().toISOString().split("T")[0];
  downloadFile(csv, `cross-tier-access-${timestamp}.csv`, "text/csv;charset=utf-8;");
}

/**
 * Export full compliance report to CSV
 */
export function exportComplianceReportToCSV(status: ComplianceStatus): void {
  // Summary section
  const summaryHeaders = ["Metric", "Value"];
  const summaryRows = [
    ["Compliance Score", status.score.toString()],
    ["Total Violations", status.totalViolations.toString()],
    ["Critical", status.criticalCount.toString()],
    ["High", status.highCount.toString()],
    ["Medium", status.mediumCount.toString()],
    ["Low", status.lowCount.toString()],
    ["Cross-Tier Access Violations", status.crossTierAccess.length.toString()],
    ["Last Checked", status.lastChecked],
  ];

  const summaryCsv = toCSV(summaryHeaders, summaryRows);

  // Violations section
  const violationHeaders = [
    "Object Name",
    "SAM Account Name",
    "Violation Type",
    "Severity",
    "Description",
    "Tiers Involved",
    "Remediation",
    "Distinguished Name",
  ];

  const violationRows = status.violations.map((v) => [
    v.objectName,
    v.samAccountName,
    v.violationType,
    v.severity,
    v.description,
    v.tiersInvolved.join(", "),
    v.remediation,
    v.objectDn,
  ]);

  const violationsCsv = toCSV(violationHeaders, violationRows);

  // Combine into full report
  const fullReport = [
    "=== COMPLIANCE SUMMARY ===",
    "",
    summaryCsv,
    "",
    "",
    "=== VIOLATIONS ===",
    "",
    violationsCsv,
  ].join("\n");

  const timestamp = new Date().toISOString().split("T")[0];
  downloadFile(fullReport, `compliance-report-${timestamp}.csv`, "text/csv;charset=utf-8;");
}
