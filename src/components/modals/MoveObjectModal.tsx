import { useState } from "react";
import { Dialog } from "@headlessui/react";
import {
  ArrowRightIcon,
  XMarkIcon,
  FolderIcon,
  ArrowPathIcon,
} from "@heroicons/react/24/outline";
import type { TierMember, TierLevel } from "../../types/tier";
import { moveObjectToTier, type SubOUType } from "../../services/tauri";
import { logAudit } from "../../store/auditStore";

interface MoveObjectModalProps {
  member: TierMember;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const tiers: TierLevel[] = ["Tier0", "Tier1", "Tier2"];
const subOUs: { value: SubOUType; label: string; types: string[] }[] = [
  { value: "Users", label: "Users", types: ["User"] },
  { value: "Computers", label: "Computers", types: ["Computer"] },
  { value: "Groups", label: "Groups", types: ["Group"] },
  { value: "ServiceAccounts", label: "Service Accounts", types: ["ServiceAccount"] },
  { value: "AdminWorkstations", label: "Admin Workstations", types: ["AdminWorkstation"] },
];

export function MoveObjectModal({
  member,
  isOpen,
  onClose,
  onSuccess,
}: MoveObjectModalProps) {
  const [targetTier, setTargetTier] = useState<TierLevel>("Tier1");
  const [targetSubOU, setTargetSubOU] = useState<SubOUType | "">("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filter sub-OUs based on object type
  const availableSubOUs = subOUs.filter((ou) =>
    ou.types.includes(member.objectType)
  );

  // Auto-select appropriate sub-OU based on object type
  const getDefaultSubOU = (): SubOUType => {
    switch (member.objectType) {
      case "User":
        return "Users";
      case "Computer":
        return "Computers";
      case "Group":
        return "Groups";
      case "ServiceAccount":
        return "ServiceAccounts";
      case "AdminWorkstation":
        return "AdminWorkstations";
      default:
        return "Computers";
    }
  };

  const handleMove = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const subOU = targetSubOU || getDefaultSubOU();
      await moveObjectToTier(member.distinguishedName, targetTier, subOU);

      // Log audit entry
      logAudit(
        "move_object",
        `Moved ${member.name} to ${targetTier}/${subOU}`,
        [member.samAccountName],
        true,
        { targetTier }
      );

      onSuccess();
      onClose();
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : "Failed to move object";

      // Log failed audit entry
      logAudit(
        "move_object",
        `Failed to move ${member.name} to ${targetTier}`,
        [member.samAccountName],
        false,
        { targetTier, error: errorMsg }
      );

      setError(errorMsg);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={isOpen} onClose={onClose} className="relative z-50">
      <div className="fixed inset-0 bg-black/50" aria-hidden="true" />

      <div className="fixed inset-0 flex items-center justify-center p-4">
        <Dialog.Panel className="mx-auto max-w-md w-full bg-white dark:bg-surface-800 rounded-xl shadow-2xl">
          <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
            <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white">
              Move Object to Tier
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
              <p className="text-sm text-gray-500 dark:text-gray-400">Moving:</p>
              <p className="font-medium text-gray-900 dark:text-white">
                {member.name}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400 font-mono mt-1 truncate">
                {member.distinguishedName}
              </p>
            </div>

            {/* Target Tier */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Target Tier
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

            {/* Target Sub-OU */}
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Target OU
              </label>
              <div className="grid grid-cols-2 gap-2">
                {availableSubOUs.map((ou) => (
                  <button
                    key={ou.value}
                    onClick={() => setTargetSubOU(ou.value)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors ${
                      targetSubOU === ou.value
                        ? "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200"
                        : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                    }`}
                  >
                    <FolderIcon className="w-4 h-4" />
                    {ou.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Preview */}
            <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3">
              <p className="text-sm text-blue-800 dark:text-blue-200">
                <ArrowRightIcon className="w-4 h-4 inline mr-1" />
                Will move to:{" "}
                <span className="font-mono text-xs">
                  OU={targetSubOU || getDefaultSubOU()},OU={targetTier},...
                </span>
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
              onClick={handleMove}
              disabled={isLoading}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <ArrowPathIcon className="w-4 h-4 animate-spin" />
                  Moving...
                </>
              ) : (
                <>
                  <ArrowRightIcon className="w-4 h-4" />
                  Move Object
                </>
              )}
            </button>
          </div>
        </Dialog.Panel>
      </div>
    </Dialog>
  );
}
