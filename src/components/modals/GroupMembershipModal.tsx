import { useState } from "react";
import { Dialog } from "@headlessui/react";
import {
  UserGroupIcon,
  XMarkIcon,
  PlusIcon,
  MinusIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";
import type { TierMember, TierLevel } from "../../types/tier";
import { addToTierGroup, removeFromTierGroup, type GroupSuffix } from "../../services/tauri";
import { logAudit } from "../../store/auditStore";

interface GroupMembershipModalProps {
  member: TierMember;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

type ActionType = "add" | "remove";

const tiers: TierLevel[] = ["Tier0", "Tier1", "Tier2"];
const groupSuffixes: { value: GroupSuffix; label: string; description: string }[] = [
  { value: "Admins", label: "Admins", description: "Full administrative access" },
  { value: "Operators", label: "Operators", description: "Operational access" },
  { value: "Readers", label: "Readers", description: "Read-only access" },
  { value: "ServiceAccounts", label: "Service Accounts", description: "Service account access" },
  { value: "JumpServers", label: "Jump Servers", description: "Jump server access" },
];

export function GroupMembershipModal({
  member,
  isOpen,
  onClose,
  onSuccess,
}: GroupMembershipModalProps) {
  const [action, setAction] = useState<ActionType>("add");
  const [targetTier, setTargetTier] = useState<TierLevel>("Tier1");
  const [targetGroup, setTargetGroup] = useState<GroupSuffix>("Operators");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    setIsLoading(true);
    setError(null);

    const groupName = `${targetTier}-${targetGroup}`;

    try {
      if (action === "add") {
        await addToTierGroup(member.distinguishedName, targetTier, targetGroup);
      } else {
        await removeFromTierGroup(member.distinguishedName, targetTier, targetGroup);
      }

      // Log successful audit entry
      logAudit(
        action === "add" ? "add_to_group" : "remove_from_group",
        `${action === "add" ? "Added" : "Removed"} ${member.name} ${action === "add" ? "to" : "from"} ${groupName}`,
        [member.samAccountName],
        true,
        { targetTier, targetGroup: groupName }
      );

      onSuccess();
      onClose();
    } catch (err) {
      const errorMsg = err instanceof Error
        ? err.message
        : `Failed to ${action === "add" ? "add to" : "remove from"} group`;

      // Log failed audit entry
      logAudit(
        action === "add" ? "add_to_group" : "remove_from_group",
        `Failed to ${action === "add" ? "add" : "remove"} ${member.name} ${action === "add" ? "to" : "from"} ${groupName}`,
        [member.samAccountName],
        false,
        { targetTier, targetGroup: groupName, error: errorMsg }
      );

      setError(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  const groupName = `${targetTier}-${targetGroup}`;

  return (
    <Dialog open={isOpen} onClose={onClose} className="relative z-50">
      <div className="fixed inset-0 bg-black/50" aria-hidden="true" />

      <div className="fixed inset-0 flex items-center justify-center p-4">
        <Dialog.Panel className="mx-auto max-w-md w-full bg-white dark:bg-surface-800 rounded-xl shadow-2xl">
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
            <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
              Manage Group Membership
            </Dialog.Title>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
            >
              <XMarkIcon className="w-5 h-5" />
            </button>
          </div>

          <div className="p-4 space-y-4">
            {/* Object Info */}
            <div className="bg-gray-50 dark:bg-surface-700 rounded-lg p-3">
              <p className="text-sm text-gray-500 dark:text-gray-400">Member:</p>
              <p className="font-medium text-gray-900 dark:text-white">
                {member.name}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                {member.objectType} • {member.samAccountName}
              </p>
            </div>

            {/* Action Type */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Action
              </label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => setAction("add")}
                  className={`flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    action === "add"
                      ? "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200"
                      : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                  }`}
                >
                  <PlusIcon className="w-4 h-4" />
                  Add to Group
                </button>
                <button
                  onClick={() => setAction("remove")}
                  className={`flex items-center justify-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    action === "remove"
                      ? "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200"
                      : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                  }`}
                >
                  <MinusIcon className="w-4 h-4" />
                  Remove from Group
                </button>
              </div>
            </div>

            {/* Tier Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Tier
              </label>
              <div className="grid grid-cols-3 gap-2">
                {tiers.map((tier) => (
                  <button
                    key={tier}
                    onClick={() => setTargetTier(tier)}
                    className={`px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                      targetTier === tier
                        ? tier === "Tier0"
                          ? "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200"
                          : tier === "Tier1"
                          ? "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200"
                          : "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200"
                        : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                    }`}
                  >
                    {tier}
                  </button>
                ))}
              </div>
            </div>

            {/* Group Selection */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Group
              </label>
              <div className="space-y-2">
                {groupSuffixes.map((group) => (
                  <button
                    key={group.value}
                    onClick={() => setTargetGroup(group.value)}
                    className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors text-left ${
                      targetGroup === group.value
                        ? "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200"
                        : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                    }`}
                  >
                    <UserGroupIcon className="w-4 h-4 flex-shrink-0" />
                    <div>
                      <span className="font-medium">{group.label}</span>
                      <span className="text-xs block opacity-75">
                        {group.description}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Preview */}
            <div
              className={`rounded-lg p-3 ${
                action === "add"
                  ? "bg-green-50 dark:bg-green-900/20"
                  : "bg-red-50 dark:bg-red-900/20"
              }`}
            >
              <p
                className={`text-sm ${
                  action === "add"
                    ? "text-green-800 dark:text-green-200"
                    : "text-red-800 dark:text-red-200"
                }`}
              >
                {action === "add" ? (
                  <>
                    <PlusIcon className="w-4 h-4 inline mr-1" />
                    Will add to group:{" "}
                  </>
                ) : (
                  <>
                    <MinusIcon className="w-4 h-4 inline mr-1" />
                    Will remove from group:{" "}
                  </>
                )}
                <span className="font-semibold">{groupName}</span>
              </p>
            </div>

            {/* Error */}
            {error && (
              <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3 text-sm text-red-700 dark:text-red-300">
                {error}
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-700">
            <button
              onClick={onClose}
              disabled={isLoading}
              className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={isLoading}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors disabled:opacity-50 ${
                action === "add"
                  ? "bg-green-600 text-white hover:bg-green-700"
                  : "bg-red-600 text-white hover:bg-red-700"
              }`}
            >
              {isLoading ? (
                <>
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  {action === "add" ? "Adding..." : "Removing..."}
                </>
              ) : (
                <>
                  {action === "add" ? (
                    <PlusIcon className="w-4 h-4" />
                  ) : (
                    <MinusIcon className="w-4 h-4" />
                  )}
                  {action === "add" ? "Add to Group" : "Remove from Group"}
                </>
              )}
            </button>
          </div>
        </Dialog.Panel>
      </div>
    </Dialog>
  );
}
