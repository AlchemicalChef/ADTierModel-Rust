import { useState, useCallback, useRef } from "react";
import { Dialog } from "@headlessui/react";
import {
  XMarkIcon,
  DocumentArrowUpIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  TrashIcon,
  PlayIcon,
} from "@heroicons/react/24/outline";
import { useQueryClient } from "@tanstack/react-query";
import { moveObjectToTier, addToTierGroup, type GroupSuffix } from "../../services/tauri";
import { tierConfig, type TierLevel } from "../../types/tier";
import { logAudit } from "../../store/auditStore";

interface CsvBulkImportProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ImportRow {
  id: string;
  distinguishedName: string;
  samAccountName: string;
  objectName: string;
  targetTier: TierLevel | "";
  targetGroups: GroupSuffix[];
  status: "pending" | "processing" | "success" | "error";
  error?: string;
}

function parseCsv(text: string): ImportRow[] {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];

  const headerLine = lines[0].toLowerCase();
  const headers = headerLine.split(",").map((h) => h.trim());

  // Find column indices
  const dnIndex = headers.findIndex((h) => h === "distinguishedname" || h === "dn");
  const samIndex = headers.findIndex((h) => h === "samaccountname" || h === "sam");
  const nameIndex = headers.findIndex((h) => h === "name" || h === "cn");
  const tierIndex = headers.findIndex((h) => h === "tier" || h === "targettier");
  const groupsIndex = headers.findIndex((h) => h === "groups" || h === "targetgroups");

  if (dnIndex === -1 && samIndex === -1) {
    return [];
  }

  const rows: ImportRow[] = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Handle quoted values
    const values: string[] = [];
    let current = "";
    let inQuotes = false;

    for (const char of line) {
      if (char === '"') {
        inQuotes = !inQuotes;
      } else if (char === "," && !inQuotes) {
        values.push(current.trim());
        current = "";
      } else {
        current += char;
      }
    }
    values.push(current.trim());

    const dn = dnIndex >= 0 ? values[dnIndex] || "" : "";
    const sam = samIndex >= 0 ? values[samIndex] || "" : "";
    const name = nameIndex >= 0 ? values[nameIndex] || "" : sam || dn.split(",")[0]?.replace("CN=", "") || "";

    const tierValue = tierIndex >= 0 ? values[tierIndex]?.trim() : "";
    let targetTier: TierLevel | "" = "";
    if (tierValue) {
      const normalized = tierValue.toLowerCase();
      if (normalized === "tier0" || normalized === "0" || normalized === "t0") targetTier = "Tier0";
      else if (normalized === "tier1" || normalized === "1" || normalized === "t1") targetTier = "Tier1";
      else if (normalized === "tier2" || normalized === "2" || normalized === "t2") targetTier = "Tier2";
    }

    const groupsValue = groupsIndex >= 0 ? values[groupsIndex]?.trim() : "";
    const targetGroups: GroupSuffix[] = [];
    if (groupsValue) {
      const groupNames = groupsValue.split(";").map((g) => g.trim());
      for (const g of groupNames) {
        const normalized = g.toLowerCase();
        if (normalized === "admins") targetGroups.push("Admins");
        else if (normalized === "operators") targetGroups.push("Operators");
        else if (normalized === "readers") targetGroups.push("Readers");
        else if (normalized === "serviceaccounts") targetGroups.push("ServiceAccounts");
        else if (normalized === "jumpservers") targetGroups.push("JumpServers");
      }
    }

    if (dn || sam) {
      rows.push({
        id: `row-${i}`,
        distinguishedName: dn,
        samAccountName: sam,
        objectName: name,
        targetTier,
        targetGroups,
        status: "pending",
      });
    }
  }

  return rows;
}

export function CsvBulkImport({ isOpen, onClose }: CsvBulkImportProps) {
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [rows, setRows] = useState<ImportRow[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [processedCount, setProcessedCount] = useState(0);
  const [fileName, setFileName] = useState<string>("");
  const [defaultTier, setDefaultTier] = useState<TierLevel | "">("Tier1");

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setFileName(file.name);

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const parsed = parseCsv(text);
      setRows(parsed);
      setProcessedCount(0);
    };
    reader.readAsText(file);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (!file || !file.name.endsWith(".csv")) return;

    setFileName(file.name);

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      const parsed = parseCsv(text);
      setRows(parsed);
      setProcessedCount(0);
    };
    reader.readAsText(file);
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
  }, []);

  const updateRowTier = (id: string, tier: TierLevel | "") => {
    setRows((prev) =>
      prev.map((r) => (r.id === id ? { ...r, targetTier: tier } : r))
    );
  };

  const updateRowGroups = (id: string, groups: GroupSuffix[]) => {
    setRows((prev) =>
      prev.map((r) => (r.id === id ? { ...r, targetGroups: groups } : r))
    );
  };

  const removeRow = (id: string) => {
    setRows((prev) => prev.filter((r) => r.id !== id));
  };

  const applyDefaultTier = () => {
    if (!defaultTier) return;
    setRows((prev) =>
      prev.map((r) => (r.targetTier === "" ? { ...r, targetTier: defaultTier } : r))
    );
  };

  const handleProcess = async () => {
    const pendingRows = rows.filter((r) => r.status === "pending" && r.targetTier);
    if (pendingRows.length === 0) return;

    setIsProcessing(true);
    setProcessedCount(0);

    for (const row of pendingRows) {
      // Update status to processing
      setRows((prev) =>
        prev.map((r) => (r.id === row.id ? { ...r, status: "processing" } : r))
      );

      try {
        // Move to tier
        if (row.targetTier && row.distinguishedName) {
          await moveObjectToTier(row.distinguishedName, row.targetTier);

          // Add to groups
          for (const group of row.targetGroups) {
            await addToTierGroup(row.distinguishedName, row.targetTier, group);
          }

          logAudit(
            "bulk_move",
            `Bulk imported ${row.objectName} to ${row.targetTier}`,
            [row.distinguishedName],
            true,
            {
              targetTier: row.targetTier,
              details: { groups: row.targetGroups },
            }
          );
        }

        setRows((prev) =>
          prev.map((r) => (r.id === row.id ? { ...r, status: "success" } : r))
        );
      } catch (error) {
        setRows((prev) =>
          prev.map((r) =>
            r.id === row.id
              ? { ...r, status: "error", error: String(error) }
              : r
          )
        );
      }

      setProcessedCount((prev) => prev + 1);
    }

    setIsProcessing(false);

    // Refresh data
    queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
    queryClient.invalidateQueries({ queryKey: ["tierCounts"] });
  };

  const handleClose = () => {
    if (isProcessing) return;
    setRows([]);
    setFileName("");
    setProcessedCount(0);
    onClose();
  };

  const pendingCount = rows.filter((r) => r.status === "pending" && r.targetTier).length;
  const successCount = rows.filter((r) => r.status === "success").length;
  const errorCount = rows.filter((r) => r.status === "error").length;

  return (
    <Dialog open={isOpen} onClose={handleClose} className="relative z-50">
      <div className="fixed inset-0 bg-black/50" aria-hidden="true" />

      <div className="fixed inset-0 flex items-center justify-center p-4">
        <Dialog.Panel className="w-full max-w-4xl bg-white dark:bg-surface-850 rounded-xl shadow-2xl max-h-[80vh] flex flex-col">
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-100 dark:bg-blue-900/30">
                <DocumentArrowUpIcon className="w-5 h-5 text-blue-600 dark:text-blue-400" />
              </div>
              <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
                CSV Bulk Import
              </Dialog.Title>
            </div>
            <button
              onClick={handleClose}
              disabled={isProcessing}
              className="p-2 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg disabled:opacity-50"
            >
              <XMarkIcon className="w-5 h-5 text-gray-500" />
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-auto p-6">
            {rows.length === 0 ? (
              /* File Upload Area */
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-xl p-12 text-center hover:border-blue-400 dark:hover:border-blue-500 transition-colors"
              >
                <DocumentArrowUpIcon className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600 dark:text-gray-400 mb-2">
                  Drag and drop a CSV file here, or
                </p>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv"
                  onChange={handleFileChange}
                  className="hidden"
                />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  Browse Files
                </button>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-4">
                  CSV should include columns: DistinguishedName or SAMAccountName, Name, Tier, Groups (optional)
                </p>
              </div>
            ) : (
              /* Data Preview */
              <div className="space-y-4">
                {/* Stats Bar */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      File: <span className="font-medium">{fileName}</span>
                    </span>
                    <span className="text-sm text-gray-600 dark:text-gray-400">
                      {rows.length} rows
                    </span>
                    {successCount > 0 && (
                      <span className="text-sm text-green-600 dark:text-green-400">
                        {successCount} imported
                      </span>
                    )}
                    {errorCount > 0 && (
                      <span className="text-sm text-red-600 dark:text-red-400">
                        {errorCount} failed
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <select
                      value={defaultTier}
                      onChange={(e) => setDefaultTier(e.target.value as TierLevel | "")}
                      className="text-sm px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-surface-900 text-gray-900 dark:text-white"
                    >
                      <option value="">Select default tier</option>
                      <option value="Tier0">Tier 0</option>
                      <option value="Tier1">Tier 1</option>
                      <option value="Tier2">Tier 2</option>
                    </select>
                    <button
                      onClick={applyDefaultTier}
                      disabled={!defaultTier}
                      className="text-sm px-3 py-1.5 bg-gray-100 dark:bg-surface-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-surface-600 disabled:opacity-50"
                    >
                      Apply to empty
                    </button>
                  </div>
                </div>

                {/* Table */}
                <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 dark:bg-surface-900">
                      <tr>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                          Object
                        </th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                          Target Tier
                        </th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                          Groups
                        </th>
                        <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                          Status
                        </th>
                        <th className="px-3 py-2 w-10"></th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                      {rows.map((row) => (
                        <tr
                          key={row.id}
                          className={`${
                            row.status === "success"
                              ? "bg-green-50 dark:bg-green-900/10"
                              : row.status === "error"
                              ? "bg-red-50 dark:bg-red-900/10"
                              : ""
                          }`}
                        >
                          <td className="px-3 py-2">
                            <div className="font-medium text-gray-900 dark:text-white">
                              {row.objectName}
                            </div>
                            <div className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">
                              {row.samAccountName || row.distinguishedName}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            <select
                              value={row.targetTier}
                              onChange={(e) => updateRowTier(row.id, e.target.value as TierLevel | "")}
                              disabled={row.status !== "pending"}
                              className={`text-sm px-2 py-1 rounded border ${
                                row.targetTier
                                  ? `${tierConfig[row.targetTier].bgColor} ${tierConfig[row.targetTier].textColor} ${tierConfig[row.targetTier].borderColor}`
                                  : "border-gray-300 dark:border-gray-600 bg-white dark:bg-surface-900"
                              } disabled:opacity-50`}
                            >
                              <option value="">Select tier</option>
                              <option value="Tier0">Tier 0</option>
                              <option value="Tier1">Tier 1</option>
                              <option value="Tier2">Tier 2</option>
                            </select>
                          </td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              {(["Admins", "Operators", "Readers"] as GroupSuffix[]).map((group) => (
                                <button
                                  key={group}
                                  onClick={() => {
                                    const newGroups = row.targetGroups.includes(group)
                                      ? row.targetGroups.filter((g) => g !== group)
                                      : [...row.targetGroups, group];
                                    updateRowGroups(row.id, newGroups);
                                  }}
                                  disabled={row.status !== "pending"}
                                  className={`px-2 py-0.5 text-xs rounded transition-colors ${
                                    row.targetGroups.includes(group)
                                      ? "bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300"
                                      : "bg-gray-100 dark:bg-surface-700 text-gray-500 dark:text-gray-400"
                                  } disabled:opacity-50`}
                                >
                                  {group}
                                </button>
                              ))}
                            </div>
                          </td>
                          <td className="px-3 py-2">
                            {row.status === "pending" && (
                              <span className="text-gray-500 dark:text-gray-400 text-xs">Pending</span>
                            )}
                            {row.status === "processing" && (
                              <ArrowPathIcon className="w-4 h-4 animate-spin text-blue-500" />
                            )}
                            {row.status === "success" && (
                              <CheckCircleIcon className="w-5 h-5 text-green-500" />
                            )}
                            {row.status === "error" && (
                              <div className="flex items-center gap-1">
                                <ExclamationTriangleIcon className="w-5 h-5 text-red-500" />
                                <span className="text-xs text-red-500 truncate max-w-[100px]" title={row.error}>
                                  {row.error}
                                </span>
                              </div>
                            )}
                          </td>
                          <td className="px-3 py-2">
                            {row.status === "pending" && (
                              <button
                                onClick={() => removeRow(row.id)}
                                className="p-1 hover:bg-gray-100 dark:hover:bg-surface-700 rounded"
                              >
                                <TrashIcon className="w-4 h-4 text-gray-400 hover:text-red-500" />
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Footer */}
          {rows.length > 0 && (
            <div className="flex items-center justify-between px-6 py-4 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={() => {
                  setRows([]);
                  setFileName("");
                  setProcessedCount(0);
                }}
                disabled={isProcessing}
                className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg disabled:opacity-50"
              >
                Clear All
              </button>

              <div className="flex items-center gap-4">
                {isProcessing && (
                  <span className="text-sm text-gray-500">
                    Processing {processedCount} / {pendingCount}...
                  </span>
                )}
                <button
                  onClick={handleProcess}
                  disabled={isProcessing || pendingCount === 0}
                  className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {isProcessing ? (
                    <>
                      <ArrowPathIcon className="w-4 h-4 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    <>
                      <PlayIcon className="w-4 h-4" />
                      Import {pendingCount} Objects
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </Dialog.Panel>
      </div>
    </Dialog>
  );
}
