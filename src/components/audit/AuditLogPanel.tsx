import { useState } from "react";
import {
  ClockIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowRightIcon,
  UserGroupIcon,
  TrashIcon,
  ArrowPathIcon,
  DocumentArrowDownIcon,
} from "@heroicons/react/24/outline";
import {
  useAuditStore,
  actionLabels,
  type AuditLogEntry,
  type AuditAction,
} from "../../store/auditStore";

function getActionIcon(action: AuditAction) {
  switch (action) {
    case "move_object":
    case "bulk_move":
    case "move_tier0_component":
      return ArrowRightIcon;
    case "add_to_group":
    case "bulk_add_to_group":
      return UserGroupIcon;
    case "remove_from_group":
    case "bulk_remove_from_group":
      return TrashIcon;
    case "initialize_tier_model":
      return ArrowPathIcon;
    default:
      return ClockIcon;
  }
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}

function formatFullTimestamp(timestamp: string): string {
  return new Date(timestamp).toLocaleString();
}

interface AuditEntryCardProps {
  entry: AuditLogEntry;
}

function AuditEntryCard({ entry }: AuditEntryCardProps) {
  const [expanded, setExpanded] = useState(false);
  const Icon = getActionIcon(entry.action);

  return (
    <div
      className={`bg-white dark:bg-surface-850 rounded-lg border p-4 ${
        entry.success
          ? "border-gray-200 dark:border-gray-700"
          : "border-red-200 dark:border-red-800"
      }`}
    >
      <div className="flex items-start gap-3">
        {/* Status Icon */}
        <div
          className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
            entry.success
              ? "bg-green-100 dark:bg-green-900/30"
              : "bg-red-100 dark:bg-red-900/30"
          }`}
        >
          {entry.success ? (
            <CheckCircleIcon className="w-4 h-4 text-green-600 dark:text-green-400" />
          ) : (
            <XCircleIcon className="w-4 h-4 text-red-600 dark:text-red-400" />
          )}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <Icon className="w-4 h-4 text-gray-500 dark:text-gray-400" />
            <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {actionLabels[entry.action]}
            </span>
            {entry.targetTier && (
              <span className="px-2 py-0.5 text-xs font-medium bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded">
                {entry.targetTier}
              </span>
            )}
            {entry.targetGroup && (
              <span className="px-2 py-0.5 text-xs font-medium bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded">
                {entry.targetGroup}
              </span>
            )}
          </div>

          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {entry.description}
          </p>

          {entry.error && (
            <p className="text-sm text-red-600 dark:text-red-400 mt-1">
              Error: {entry.error}
            </p>
          )}

          <div className="flex items-center gap-4 mt-2">
            <span
              className="text-xs text-gray-500 dark:text-gray-500"
              title={formatFullTimestamp(entry.timestamp)}
            >
              {formatTimestamp(entry.timestamp)}
            </span>

            {entry.targetObjects.length > 0 && (
              <button
                onClick={() => setExpanded(!expanded)}
                className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
              >
                {expanded ? "Hide" : "Show"} {entry.targetObjects.length} object
                {entry.targetObjects.length !== 1 ? "s" : ""}
              </button>
            )}
          </div>

          {/* Expanded details */}
          {expanded && entry.targetObjects.length > 0 && (
            <div className="mt-3 p-2 bg-gray-50 dark:bg-surface-900 rounded text-xs font-mono">
              {entry.targetObjects.map((obj, idx) => (
                <div
                  key={idx}
                  className="text-gray-600 dark:text-gray-400 truncate py-0.5"
                >
                  {obj}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

type FilterOption = "all" | "success" | "failed";

export function AuditLogPanel() {
  const { entries, clearEntries } = useAuditStore();
  const [filter, setFilter] = useState<FilterOption>("all");
  const [actionFilter, setActionFilter] = useState<AuditAction | "all">("all");

  const filteredEntries = entries.filter((entry) => {
    if (filter === "success" && !entry.success) return false;
    if (filter === "failed" && entry.success) return false;
    if (actionFilter !== "all" && entry.action !== actionFilter) return false;
    return true;
  });

  const exportAuditLog = () => {
    const headers = [
      "Timestamp",
      "Action",
      "Description",
      "Success",
      "Target Tier",
      "Target Group",
      "Objects",
      "Error",
    ];

    const rows = entries.map((e) => [
      e.timestamp,
      actionLabels[e.action],
      e.description,
      e.success ? "Yes" : "No",
      e.targetTier || "",
      e.targetGroup || "",
      e.targetObjects.join("; "),
      e.error || "",
    ]);

    const escapeCell = (cell: string): string => {
      if (cell.includes(",") || cell.includes('"') || cell.includes("\n")) {
        return `"${cell.replace(/"/g, '""')}"`;
      }
      return cell;
    };

    const csv = [
      headers.map(escapeCell).join(","),
      ...rows.map((row) => row.map(escapeCell).join(",")),
    ].join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `audit-log-${new Date().toISOString().split("T")[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Audit Log
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Track changes made through the application
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Status Filter */}
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value as FilterOption)}
            className="px-3 py-2 text-sm bg-white dark:bg-surface-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300"
          >
            <option value="all">All Status</option>
            <option value="success">Successful</option>
            <option value="failed">Failed</option>
          </select>

          {/* Action Filter */}
          <select
            value={actionFilter}
            onChange={(e) =>
              setActionFilter(e.target.value as AuditAction | "all")
            }
            className="px-3 py-2 text-sm bg-white dark:bg-surface-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300"
          >
            <option value="all">All Actions</option>
            {Object.entries(actionLabels).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>

          {/* Export Button */}
          <button
            onClick={exportAuditLog}
            disabled={entries.length === 0}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-white dark:bg-surface-800 border border-gray-200 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-surface-700 disabled:opacity-50 transition-colors"
          >
            <DocumentArrowDownIcon className="w-4 h-4" />
            Export
          </button>

          {/* Clear Button */}
          <button
            onClick={() => {
              if (confirm("Are you sure you want to clear the audit log?")) {
                clearEntries();
              }
            }}
            disabled={entries.length === 0}
            className="flex items-center gap-2 px-3 py-2 text-sm bg-white dark:bg-surface-800 border border-red-200 dark:border-red-800 rounded-lg text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 transition-colors"
          >
            <TrashIcon className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <p className="text-2xl font-semibold text-gray-900 dark:text-white">
            {entries.length}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Total Entries
          </p>
        </div>
        <div className="bg-white dark:bg-surface-850 rounded-lg border border-green-200 dark:border-green-800 p-4">
          <p className="text-2xl font-semibold text-green-600 dark:text-green-400">
            {entries.filter((e) => e.success).length}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Successful</p>
        </div>
        <div className="bg-white dark:bg-surface-850 rounded-lg border border-red-200 dark:border-red-800 p-4">
          <p className="text-2xl font-semibold text-red-600 dark:text-red-400">
            {entries.filter((e) => !e.success).length}
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">Failed</p>
        </div>
      </div>

      {/* Entries List */}
      {filteredEntries.length === 0 ? (
        <div className="text-center py-12 text-gray-500 dark:text-gray-400">
          <ClockIcon className="w-12 h-12 mx-auto mb-4 opacity-50" />
          <p>
            {entries.length === 0
              ? "No audit entries yet"
              : "No entries match your filters"}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredEntries.map((entry) => (
            <AuditEntryCard key={entry.id} entry={entry} />
          ))}
        </div>
      )}
    </div>
  );
}
