/**
 * HTML Report Generator for AD Tier Model
 * Generates comprehensive compliance and tier model reports
 */

import type { ComplianceStatus, TierGpoStatus } from "./tauri";
import type { TierCounts, DomainInfo, TierMember } from "../types/tier";

export interface ReportData {
  domainInfo: DomainInfo | null;
  tierCounts: TierCounts | null;
  complianceStatus: ComplianceStatus | null;
  gpoStatus: TierGpoStatus[] | null;
  tierMembers?: {
    tier0: TierMember[];
    tier1: TierMember[];
    tier2: TierMember[];
    unassigned: TierMember[];
  };
  generatedAt: Date;
}

function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function formatDate(date: Date): string {
  return date.toLocaleString("en-US", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getScoreColor(score: number): string {
  if (score >= 90) return "#16a34a";
  if (score >= 70) return "#ca8a04";
  return "#dc2626";
}

function getTierColor(tier: string): string {
  switch (tier) {
    case "Tier0":
      return "#dc2626";
    case "Tier1":
      return "#f59e0b";
    case "Tier2":
      return "#22c55e";
    default:
      return "#6b7280";
  }
}

export function generateHtmlReport(data: ReportData): string {
  const {
    domainInfo,
    tierCounts,
    complianceStatus,
    gpoStatus,
    tierMembers,
    generatedAt,
  } = data;

  const scoreColor = complianceStatus
    ? getScoreColor(complianceStatus.score)
    : "#6b7280";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AD Tier Model Compliance Report - ${escapeHtml(domainInfo?.dnsRoot || "Unknown Domain")}</title>
  <style>
    :root {
      --tier0-color: #dc2626;
      --tier1-color: #f59e0b;
      --tier2-color: #22c55e;
      --critical-color: #dc2626;
      --high-color: #ea580c;
      --medium-color: #ca8a04;
      --low-color: #16a34a;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      line-height: 1.6;
      color: #1f2937;
      background: #f9fafb;
      padding: 40px;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: white;
      border-radius: 12px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
      overflow: hidden;
    }

    .header {
      background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
      color: white;
      padding: 40px;
    }

    .header h1 {
      font-size: 28px;
      margin-bottom: 8px;
    }

    .header .subtitle {
      font-size: 16px;
      opacity: 0.9;
    }

    .header .meta {
      margin-top: 20px;
      display: flex;
      gap: 30px;
      font-size: 14px;
    }

    .header .meta-item {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .content {
      padding: 40px;
    }

    .section {
      margin-bottom: 40px;
    }

    .section-title {
      font-size: 20px;
      color: #1e3a8a;
      border-bottom: 2px solid #e5e7eb;
      padding-bottom: 12px;
      margin-bottom: 24px;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }

    .summary-card {
      background: #f9fafb;
      border-radius: 8px;
      padding: 20px;
      text-align: center;
    }

    .summary-card .value {
      font-size: 36px;
      font-weight: bold;
      margin-bottom: 4px;
    }

    .summary-card .label {
      font-size: 14px;
      color: #6b7280;
    }

    .score-card {
      background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
      border: 2px solid ${scoreColor};
    }

    .score-card .value {
      color: ${scoreColor};
    }

    .tier-distribution {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
    }

    .tier-card {
      border-radius: 8px;
      padding: 20px;
      text-align: center;
      color: white;
    }

    .tier-card.tier0 { background: linear-gradient(135deg, #dc2626 0%, #ef4444 100%); }
    .tier-card.tier1 { background: linear-gradient(135deg, #d97706 0%, #f59e0b 100%); }
    .tier-card.tier2 { background: linear-gradient(135deg, #16a34a 0%, #22c55e 100%); }
    .tier-card.unassigned { background: linear-gradient(135deg, #4b5563 0%, #6b7280 100%); }

    .tier-card .count {
      font-size: 32px;
      font-weight: bold;
    }

    .tier-card .name {
      font-size: 14px;
      opacity: 0.9;
    }

    .violations-summary {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }

    .violation-badge {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 500;
    }

    .violation-badge.critical {
      background: #fef2f2;
      color: #dc2626;
      border: 1px solid #fecaca;
    }

    .violation-badge.high {
      background: #fff7ed;
      color: #ea580c;
      border: 1px solid #fed7aa;
    }

    .violation-badge.medium {
      background: #fefce8;
      color: #ca8a04;
      border: 1px solid #fef08a;
    }

    .violation-badge.low {
      background: #f0fdf4;
      color: #16a34a;
      border: 1px solid #bbf7d0;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 16px;
    }

    th, td {
      text-align: left;
      padding: 12px 16px;
      border-bottom: 1px solid #e5e7eb;
    }

    th {
      background: #f9fafb;
      font-weight: 600;
      color: #374151;
      font-size: 14px;
    }

    tr:hover {
      background: #f9fafb;
    }

    .severity-pill {
      display: inline-block;
      padding: 4px 12px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
      text-transform: uppercase;
    }

    .severity-pill.critical { background: #fef2f2; color: #dc2626; }
    .severity-pill.high { background: #fff7ed; color: #ea580c; }
    .severity-pill.medium { background: #fefce8; color: #ca8a04; }
    .severity-pill.low { background: #f0fdf4; color: #16a34a; }

    .gpo-status {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 16px;
    }

    .gpo-card {
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 20px;
    }

    .gpo-card .tier-name {
      font-weight: 600;
      margin-bottom: 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid #e5e7eb;
    }

    .gpo-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 8px 0;
      font-size: 14px;
    }

    .status-indicator {
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
    }

    .status-dot.green { background: #22c55e; }
    .status-dot.red { background: #ef4444; }
    .status-dot.yellow { background: #f59e0b; }

    .footer {
      background: #f9fafb;
      padding: 24px 40px;
      border-top: 1px solid #e5e7eb;
      text-align: center;
      font-size: 14px;
      color: #6b7280;
    }

    .no-data {
      text-align: center;
      padding: 40px;
      color: #6b7280;
      font-style: italic;
    }

    @media print {
      body {
        background: white;
        padding: 0;
      }

      .container {
        box-shadow: none;
      }

      .header {
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>AD Tier Model Compliance Report</h1>
      <p class="subtitle">Enterprise Security Administrative Environment (ESAE) Assessment</p>
      <div class="meta">
        <div class="meta-item">
          <span>Domain:</span>
          <strong>${escapeHtml(domainInfo?.dnsRoot || "Not Connected")}</strong>
        </div>
        <div class="meta-item">
          <span>NetBIOS:</span>
          <strong>${escapeHtml(domainInfo?.netbiosName || "N/A")}</strong>
        </div>
        <div class="meta-item">
          <span>Generated:</span>
          <strong>${formatDate(generatedAt)}</strong>
        </div>
      </div>
    </div>

    <div class="content">
      <!-- Executive Summary -->
      <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="summary-grid">
          <div class="summary-card score-card">
            <div class="value">${complianceStatus?.score ?? "N/A"}${complianceStatus ? "%" : ""}</div>
            <div class="label">Compliance Score</div>
          </div>
          <div class="summary-card">
            <div class="value">${complianceStatus?.totalViolations ?? 0}</div>
            <div class="label">Total Violations</div>
          </div>
          <div class="summary-card">
            <div class="value">${tierCounts ? (tierCounts.Tier0 + tierCounts.Tier1 + tierCounts.Tier2 + tierCounts.Unassigned) : 0}</div>
            <div class="label">Total Objects</div>
          </div>
          <div class="summary-card">
            <div class="value">${gpoStatus?.filter(g => g.restrictionsConfigured).length ?? 0}/${gpoStatus?.length ?? 0}</div>
            <div class="label">GPOs Configured</div>
          </div>
        </div>

        ${complianceStatus && complianceStatus.totalViolations > 0 ? `
        <div class="violations-summary">
          ${complianceStatus.criticalCount > 0 ? `<div class="violation-badge critical">${complianceStatus.criticalCount} Critical</div>` : ""}
          ${complianceStatus.highCount > 0 ? `<div class="violation-badge high">${complianceStatus.highCount} High</div>` : ""}
          ${complianceStatus.mediumCount > 0 ? `<div class="violation-badge medium">${complianceStatus.mediumCount} Medium</div>` : ""}
          ${complianceStatus.lowCount > 0 ? `<div class="violation-badge low">${complianceStatus.lowCount} Low</div>` : ""}
        </div>
        ` : ""}
      </div>

      <!-- Tier Distribution -->
      <div class="section">
        <h2 class="section-title">Tier Distribution</h2>
        ${tierCounts ? `
        <div class="tier-distribution">
          <div class="tier-card tier0">
            <div class="count">${tierCounts.Tier0}</div>
            <div class="name">Tier 0 - Infrastructure</div>
          </div>
          <div class="tier-card tier1">
            <div class="count">${tierCounts.Tier1}</div>
            <div class="name">Tier 1 - Servers</div>
          </div>
          <div class="tier-card tier2">
            <div class="count">${tierCounts.Tier2}</div>
            <div class="name">Tier 2 - Workstations</div>
          </div>
          <div class="tier-card unassigned">
            <div class="count">${tierCounts.Unassigned}</div>
            <div class="name">Unassigned</div>
          </div>
        </div>
        ` : '<p class="no-data">No tier count data available</p>'}
      </div>

      <!-- Compliance Violations -->
      <div class="section">
        <h2 class="section-title">Compliance Violations</h2>
        ${complianceStatus && complianceStatus.violations.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Object</th>
              <th>Type</th>
              <th>Description</th>
              <th>Remediation</th>
            </tr>
          </thead>
          <tbody>
            ${complianceStatus.violations.map(v => `
            <tr>
              <td><span class="severity-pill ${v.severity}">${escapeHtml(v.severity)}</span></td>
              <td><strong>${escapeHtml(v.objectName)}</strong><br><small style="color: #6b7280">${escapeHtml(v.samAccountName)}</small></td>
              <td>${escapeHtml(v.violationType.replace(/([A-Z])/g, ' $1').trim())}</td>
              <td>${escapeHtml(v.description)}</td>
              <td>${escapeHtml(v.remediation)}</td>
            </tr>
            `).join("")}
          </tbody>
        </table>
        ` : '<p class="no-data">No compliance violations detected</p>'}
      </div>

      <!-- Cross-Tier Access -->
      ${complianceStatus && complianceStatus.crossTierAccess.length > 0 ? `
      <div class="section">
        <h2 class="section-title">Cross-Tier Access Violations</h2>
        <table>
          <thead>
            <tr>
              <th>Account</th>
              <th>Tiers Accessed</th>
              <th>Groups</th>
            </tr>
          </thead>
          <tbody>
            ${complianceStatus.crossTierAccess.map(a => `
            <tr>
              <td><strong>${escapeHtml(a.accountName)}</strong></td>
              <td>${a.tiers.map(t => `<span style="display: inline-block; padding: 2px 8px; border-radius: 4px; background: ${getTierColor(t)}20; color: ${getTierColor(t)}; margin-right: 4px; font-size: 12px;">${escapeHtml(t)}</span>`).join("")}</td>
              <td><small>${a.groups.map(g => escapeHtml(g)).join(", ")}</small></td>
            </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
      ` : ""}

      <!-- GPO Status -->
      <div class="section">
        <h2 class="section-title">Group Policy Configuration</h2>
        ${gpoStatus && gpoStatus.length > 0 ? `
        <div class="gpo-status">
          ${gpoStatus.map(g => `
          <div class="gpo-card">
            <div class="tier-name" style="color: ${getTierColor(g.tier)}">${escapeHtml(g.tier)}</div>
            <div class="gpo-item">
              <span>Base Policy</span>
              <span class="status-indicator">
                <span class="status-dot ${g.basePolicy.exists ? "green" : "red"}"></span>
                ${g.basePolicy.exists ? "Exists" : "Missing"}
              </span>
            </div>
            <div class="gpo-item">
              <span>Logon Restrictions</span>
              <span class="status-indicator">
                <span class="status-dot ${g.logonRestrictions.exists ? "green" : "red"}"></span>
                ${g.logonRestrictions.exists ? "Exists" : "Missing"}
              </span>
            </div>
            <div class="gpo-item">
              <span>Restrictions Applied</span>
              <span class="status-indicator">
                <span class="status-dot ${g.restrictionsConfigured ? "green" : "yellow"}"></span>
                ${g.restrictionsConfigured ? "Configured" : "Not Configured"}
              </span>
            </div>
          </div>
          `).join("")}
        </div>
        ` : '<p class="no-data">No GPO status data available</p>'}
      </div>

      ${tierMembers ? `
      <!-- Tier 0 Members -->
      <div class="section">
        <h2 class="section-title">Tier 0 Members (${tierMembers.tier0.length})</h2>
        ${tierMembers.tier0.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>SAM Account Name</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${tierMembers.tier0.slice(0, 50).map(m => `
            <tr>
              <td><strong>${escapeHtml(m.name)}</strong></td>
              <td>${escapeHtml(m.objectType)}</td>
              <td><code>${escapeHtml(m.samAccountName)}</code></td>
              <td><span class="status-indicator"><span class="status-dot ${m.enabled ? "green" : "red"}"></span>${m.enabled ? "Enabled" : "Disabled"}</span></td>
            </tr>
            `).join("")}
          </tbody>
        </table>
        ${tierMembers.tier0.length > 50 ? `<p style="margin-top: 16px; color: #6b7280; font-size: 14px;">Showing first 50 of ${tierMembers.tier0.length} members</p>` : ""}
        ` : '<p class="no-data">No Tier 0 members found</p>'}
      </div>
      ` : ""}
    </div>

    <div class="footer">
      <p>Generated by AD Tier Model Manager | ${formatDate(generatedAt)}</p>
      <p style="margin-top: 8px; font-size: 12px;">This report provides a snapshot of the Active Directory tier model compliance status. For real-time monitoring, use the AD Tier Model application.</p>
    </div>
  </div>
</body>
</html>`;
}
