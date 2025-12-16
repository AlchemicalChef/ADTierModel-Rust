import { useState, memo } from "react";
import {
  ComputerDesktopIcon,
  UserIcon,
  UserGroupIcon,
  ServerIcon,
  ShieldCheckIcon,
  KeyIcon,
  CloudIcon,
  CpuChipIcon,
  ArrowRightIcon,
  EllipsisVerticalIcon,
  CheckIcon,
  InformationCircleIcon,
} from "@heroicons/react/24/outline";
import { Menu } from "@headlessui/react";
import type { TierMember } from "../../types/tier";
import { getRoleLabel } from "../../types/tier";
import { MoveObjectModal } from "../modals/MoveObjectModal";
import { GroupMembershipModal } from "../modals/GroupMembershipModal";
import { ObjectDetailsModal } from "../modals/ObjectDetailsModal";
import { useTierStore } from "../../store/tierStore";

interface TierMemberCardProps {
  member: TierMember;
  onRefresh?: () => void;
  selectable?: boolean;
}

function getObjectIcon(member: TierMember) {
  // Special icons for Tier 0 roles
  if (member.roleType) {
    switch (member.roleType) {
      case "DomainController":
        return ServerIcon;
      case "ADFS":
        return KeyIcon;
      case "EntraConnect":
        return CloudIcon;
      case "CertificateAuthority":
        return ShieldCheckIcon;
      case "PAW":
        return CpuChipIcon;
    }
  }

  // Default icons by object type
  switch (member.objectType) {
    case "Computer":
    case "AdminWorkstation":
      return ComputerDesktopIcon;
    case "User":
    case "ServiceAccount":
      return UserIcon;
    case "Group":
      return UserGroupIcon;
    default:
      return ComputerDesktopIcon;
  }
}

function formatLastLogon(lastLogon: string | null): string {
  if (!lastLogon) return "Never";
  try {
    const date = new Date(lastLogon);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return "Today";
    if (diffDays === 1) return "Yesterday";
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    if (diffDays < 365) return `${Math.floor(diffDays / 30)} months ago`;
    return `${Math.floor(diffDays / 365)} years ago`;
  } catch {
    return "Unknown";
  }
}

export const TierMemberCard = memo(function TierMemberCard({ member, onRefresh, selectable = false }: TierMemberCardProps) {
  const Icon = getObjectIcon(member);
  const [showMoveModal, setShowMoveModal] = useState(false);
  const [showGroupModal, setShowGroupModal] = useState(false);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const { selectedMembers, toggleMemberSelection } = useTierStore();

  const isSelected = selectedMembers.has(member.distinguishedName);

  const handleActionSuccess = () => {
    onRefresh?.();
  };

  const handleCheckboxClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    toggleMemberSelection(member.distinguishedName);
  };

  return (
    <>
      <div
        className={`bg-white dark:bg-surface-850 rounded-lg border p-4 hover:shadow-md transition-shadow group ${
          isSelected
            ? "border-blue-400 dark:border-blue-600 ring-1 ring-blue-400 dark:ring-blue-600"
            : "border-gray-200 dark:border-gray-700"
        }`}
        onClick={selectable ? handleCheckboxClick : undefined}
        style={selectable ? { cursor: "pointer" } : undefined}
      >
        <div className="flex items-start gap-3">
          {/* Checkbox for selection */}
          {selectable && (
            <button
              onClick={handleCheckboxClick}
              className={`flex-shrink-0 w-5 h-5 rounded border-2 flex items-center justify-center transition-colors ${
                isSelected
                  ? "bg-blue-600 border-blue-600"
                  : "border-gray-300 dark:border-gray-600 hover:border-blue-400"
              }`}
            >
              {isSelected && <CheckIcon className="w-3 h-3 text-white" />}
            </button>
          )}

          {/* Icon */}
          <div
            className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
              member.enabled
                ? "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400"
                : "bg-gray-100 dark:bg-gray-800 text-gray-400"
            }`}
          >
            <Icon className="w-5 h-5" />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                {member.name}
              </h4>
              {!member.enabled && (
                <span className="flex-shrink-0 px-1.5 py-0.5 text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                  Disabled
                </span>
              )}
            </div>

            {/* Role badge for Tier 0 */}
            {member.roleType && (
              <span className="inline-block mt-1 px-2 py-0.5 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded">
                {getRoleLabel(member.roleType)}
              </span>
            )}

            {/* SAM Account Name */}
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 font-mono truncate">
              {member.samAccountName}
            </p>

            {/* Additional info */}
            <div className="flex items-center gap-3 mt-2 text-xs text-gray-500 dark:text-gray-400">
              {member.operatingSystem && (
                <span className="truncate">{member.operatingSystem}</span>
              )}
              {member.memberCount !== null && (
                <span>{member.memberCount} members</span>
              )}
              <span>Last logon: {formatLastLogon(member.lastLogon)}</span>
            </div>
          </div>

          {/* Action Menu */}
          <Menu as="div" className="relative">
            <Menu.Button className="p-1 rounded-lg text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-surface-700 opacity-0 group-hover:opacity-100 transition-opacity">
              <EllipsisVerticalIcon className="w-5 h-5" />
            </Menu.Button>
            <Menu.Items className="absolute right-0 mt-1 w-48 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-10">
              <Menu.Item>
                {({ active }) => (
                  <button
                    onClick={() => setShowDetailsModal(true)}
                    className={`flex items-center gap-2 w-full px-3 py-2 text-sm ${
                      active
                        ? "bg-gray-100 dark:bg-surface-700 text-gray-900 dark:text-white"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <InformationCircleIcon className="w-4 h-4" />
                    View Details
                  </button>
                )}
              </Menu.Item>
              <Menu.Item>
                {({ active }) => (
                  <button
                    onClick={() => setShowMoveModal(true)}
                    className={`flex items-center gap-2 w-full px-3 py-2 text-sm ${
                      active
                        ? "bg-gray-100 dark:bg-surface-700 text-gray-900 dark:text-white"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <ArrowRightIcon className="w-4 h-4" />
                    Move to Tier...
                  </button>
                )}
              </Menu.Item>
              <Menu.Item>
                {({ active }) => (
                  <button
                    onClick={() => setShowGroupModal(true)}
                    className={`flex items-center gap-2 w-full px-3 py-2 text-sm ${
                      active
                        ? "bg-gray-100 dark:bg-surface-700 text-gray-900 dark:text-white"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <UserGroupIcon className="w-4 h-4" />
                    Manage Groups...
                  </button>
                )}
              </Menu.Item>
            </Menu.Items>
          </Menu>
        </div>
      </div>

      {/* Modals */}
      <ObjectDetailsModal
        member={member}
        isOpen={showDetailsModal}
        onClose={() => setShowDetailsModal(false)}
        onRefresh={onRefresh}
      />
      <MoveObjectModal
        member={member}
        isOpen={showMoveModal}
        onClose={() => setShowMoveModal(false)}
        onSuccess={handleActionSuccess}
      />
      <GroupMembershipModal
        member={member}
        isOpen={showGroupModal}
        onClose={() => setShowGroupModal(false)}
        onSuccess={handleActionSuccess}
      />
    </>
  );
});
