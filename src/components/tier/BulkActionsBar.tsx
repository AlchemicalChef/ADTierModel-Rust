import { useState } from "react";
import {
  CheckIcon,
  XMarkIcon,
  ArrowRightIcon,
  UserGroupIcon,
  TrashIcon,
} from "@heroicons/react/24/outline";
import { Menu } from "@headlessui/react";
import { useTierStore } from "../../store/tierStore";
import type { TierLevel, TierMember } from "../../types/tier";
import { moveObjectToTier, addToTierGroup, removeFromTierGroup, type GroupSuffix } from "../../services/tauri";
import { logAudit } from "../../store/auditStore";

interface BulkActionsBarProps {
  members: TierMember[];
  currentTier: TierLevel | "Unassigned";
  onRefresh: () => void;
}

const tierOptions: TierLevel[] = ["Tier0", "Tier1", "Tier2"];
const groupSuffixes: { value: GroupSuffix; label: string }[] = [
  { value: "Admins", label: "Admins" },
  { value: "Operators", label: "Operators" },
  { value: "Readers", label: "Readers" },
  { value: "ServiceAccounts", label: "Service Accounts" },
  { value: "JumpServers", label: "Jump Servers" },
];

export function BulkActionsBar({ members, currentTier, onRefresh }: BulkActionsBarProps) {
  const { selectedMembers, clearSelection, selectAllMembers } = useTierStore();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedCount = selectedMembers.size;
  const allSelected = selectedCount === members.length && members.length > 0;
  const someSelected = selectedCount > 0 && selectedCount < members.length;

  const selectedMembersList = members.filter((m) =>
    selectedMembers.has(m.distinguishedName)
  );

  const handleSelectAll = () => {
    if (allSelected) {
      clearSelection();
    } else {
      selectAllMembers(members.map((m) => m.distinguishedName));
    }
  };

  const handleBulkMove = async (targetTier: TierLevel) => {
    if (selectedCount === 0) return;

    setIsProcessing(true);
    setError(null);

    let successCount = 0;
    let failCount = 0;
    const targetObjects = selectedMembersList.map((m) => m.samAccountName);

    for (const member of selectedMembersList) {
      try {
        await moveObjectToTier(member.distinguishedName, targetTier);
        successCount++;
      } catch {
        failCount++;
      }
    }

    setIsProcessing(false);

    // Log audit entry
    logAudit(
      "bulk_move",
      `Moved ${successCount} object(s) to ${targetTier}${failCount > 0 ? ` (${failCount} failed)` : ""}`,
      targetObjects,
      failCount === 0,
      {
        targetTier,
        error: failCount > 0 ? `${failCount} operations failed` : undefined,
      }
    );

    if (failCount > 0) {
      setError(`Moved ${successCount}, failed ${failCount}`);
    }

    clearSelection();
    onRefresh();
  };

  const handleBulkAddToGroup = async (tier: TierLevel, groupSuffix: GroupSuffix) => {
    if (selectedCount === 0) return;

    setIsProcessing(true);
    setError(null);

    let successCount = 0;
    let failCount = 0;
    const targetObjects = selectedMembersList.map((m) => m.samAccountName);
    const groupName = `${tier}-${groupSuffix}`;

    for (const member of selectedMembersList) {
      try {
        await addToTierGroup(member.distinguishedName, tier, groupSuffix);
        successCount++;
      } catch {
        failCount++;
      }
    }

    setIsProcessing(false);

    // Log audit entry
    logAudit(
      "bulk_add_to_group",
      `Added ${successCount} object(s) to ${groupName}${failCount > 0 ? ` (${failCount} failed)` : ""}`,
      targetObjects,
      failCount === 0,
      {
        targetTier: tier,
        targetGroup: groupName,
        error: failCount > 0 ? `${failCount} operations failed` : undefined,
      }
    );

    if (failCount > 0) {
      setError(`Added ${successCount}, failed ${failCount}`);
    }

    clearSelection();
    onRefresh();
  };

  const handleBulkRemoveFromGroup = async (tier: TierLevel, groupSuffix: GroupSuffix) => {
    if (selectedCount === 0) return;

    setIsProcessing(true);
    setError(null);

    let successCount = 0;
    let failCount = 0;
    const targetObjects = selectedMembersList.map((m) => m.samAccountName);
    const groupName = `${tier}-${groupSuffix}`;

    for (const member of selectedMembersList) {
      try {
        await removeFromTierGroup(member.distinguishedName, tier, groupSuffix);
        successCount++;
      } catch {
        failCount++;
      }
    }

    setIsProcessing(false);

    // Log audit entry
    logAudit(
      "bulk_remove_from_group",
      `Removed ${successCount} object(s) from ${groupName}${failCount > 0 ? ` (${failCount} failed)` : ""}`,
      targetObjects,
      failCount === 0,
      {
        targetTier: tier,
        targetGroup: groupName,
        error: failCount > 0 ? `${failCount} operations failed` : undefined,
      }
    );

    if (failCount > 0) {
      setError(`Removed ${successCount}, failed ${failCount}`);
    }

    clearSelection();
    onRefresh();
  };

  if (selectedCount === 0 && !someSelected && !allSelected) {
    return (
      <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-3 mb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={handleSelectAll}
            className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors"
          >
            <div className="w-4 h-4 border-2 border-gray-300 dark:border-gray-600 rounded" />
            Select All
          </button>
          <span className="text-sm text-gray-500 dark:text-gray-400">
            Select items to perform bulk actions
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800 p-3 mb-4">
      <div className="flex flex-wrap items-center gap-3">
        {/* Select All Checkbox */}
        <button
          onClick={handleSelectAll}
          className="flex items-center gap-2 px-3 py-1.5 text-sm text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg transition-colors"
        >
          <div
            className={`w-4 h-4 border-2 rounded flex items-center justify-center ${
              allSelected
                ? "bg-blue-600 border-blue-600"
                : someSelected
                ? "bg-blue-600 border-blue-600"
                : "border-blue-400"
            }`}
          >
            {allSelected && <CheckIcon className="w-3 h-3 text-white" />}
            {someSelected && !allSelected && (
              <div className="w-2 h-0.5 bg-white" />
            )}
          </div>
          {allSelected ? "Deselect All" : "Select All"}
        </button>

        <div className="h-6 w-px bg-blue-200 dark:bg-blue-700" />

        {/* Selected Count */}
        <span className="text-sm font-medium text-blue-700 dark:text-blue-300">
          {selectedCount} selected
        </span>

        <div className="h-6 w-px bg-blue-200 dark:bg-blue-700" />

        {/* Bulk Move */}
        <Menu as="div" className="relative">
          <Menu.Button
            disabled={isProcessing}
            className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white dark:bg-surface-800 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-surface-700 disabled:opacity-50 transition-colors"
          >
            <ArrowRightIcon className="w-4 h-4" />
            Move to Tier
          </Menu.Button>
          <Menu.Items className="absolute left-0 mt-1 w-40 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20">
            {tierOptions.map((tier) => (
              <Menu.Item key={tier}>
                {({ active }) => (
                  <button
                    onClick={() => handleBulkMove(tier)}
                    disabled={tier === currentTier}
                    className={`w-full px-3 py-2 text-sm text-left ${
                      active ? "bg-gray-100 dark:bg-surface-700" : ""
                    } ${
                      tier === currentTier
                        ? "text-gray-400 cursor-not-allowed"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    {tier}
                  </button>
                )}
              </Menu.Item>
            ))}
          </Menu.Items>
        </Menu>

        {/* Bulk Add to Group */}
        <Menu as="div" className="relative">
          <Menu.Button
            disabled={isProcessing}
            className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white dark:bg-surface-800 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-surface-700 disabled:opacity-50 transition-colors"
          >
            <UserGroupIcon className="w-4 h-4" />
            Add to Group
          </Menu.Button>
          <Menu.Items className="absolute left-0 mt-1 w-56 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20 max-h-64 overflow-auto">
            {tierOptions.map((tier) => (
              <div key={tier}>
                <div className="px-3 py-1.5 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">
                  {tier}
                </div>
                {groupSuffixes.map((group) => (
                  <Menu.Item key={`${tier}-${group.value}`}>
                    {({ active }) => (
                      <button
                        onClick={() => handleBulkAddToGroup(tier, group.value)}
                        className={`w-full px-3 py-2 text-sm text-left ${
                          active
                            ? "bg-gray-100 dark:bg-surface-700"
                            : ""
                        } text-gray-700 dark:text-gray-300`}
                      >
                        {tier}-{group.label}
                      </button>
                    )}
                  </Menu.Item>
                ))}
              </div>
            ))}
          </Menu.Items>
        </Menu>

        {/* Bulk Remove from Group */}
        <Menu as="div" className="relative">
          <Menu.Button
            disabled={isProcessing}
            className="flex items-center gap-2 px-3 py-1.5 text-sm bg-white dark:bg-surface-800 text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-surface-700 disabled:opacity-50 transition-colors"
          >
            <TrashIcon className="w-4 h-4" />
            Remove from Group
          </Menu.Button>
          <Menu.Items className="absolute left-0 mt-1 w-56 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20 max-h-64 overflow-auto">
            {tierOptions.map((tier) => (
              <div key={tier}>
                <div className="px-3 py-1.5 text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase">
                  {tier}
                </div>
                {groupSuffixes.map((group) => (
                  <Menu.Item key={`${tier}-${group.value}`}>
                    {({ active }) => (
                      <button
                        onClick={() => handleBulkRemoveFromGroup(tier, group.value)}
                        className={`w-full px-3 py-2 text-sm text-left ${
                          active
                            ? "bg-gray-100 dark:bg-surface-700"
                            : ""
                        } text-gray-700 dark:text-gray-300`}
                      >
                        {tier}-{group.label}
                      </button>
                    )}
                  </Menu.Item>
                ))}
              </div>
            ))}
          </Menu.Items>
        </Menu>

        {/* Clear Selection */}
        <button
          onClick={clearSelection}
          className="ml-auto flex items-center gap-1 px-3 py-1.5 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:bg-blue-100 dark:hover:bg-blue-900/30 rounded-lg transition-colors"
        >
          <XMarkIcon className="w-4 h-4" />
          Cancel
        </button>

        {/* Error Message */}
        {error && (
          <span className="text-sm text-red-600 dark:text-red-400">{error}</span>
        )}

        {/* Processing Indicator */}
        {isProcessing && (
          <span className="text-sm text-blue-600 dark:text-blue-400">
            Processing...
          </span>
        )}
      </div>
    </div>
  );
}
