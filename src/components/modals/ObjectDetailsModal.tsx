import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Dialog } from "@headlessui/react";
import {
  XMarkIcon,
  ComputerDesktopIcon,
  UserIcon,
  UserGroupIcon,
  ServerIcon,
  ShieldCheckIcon,
  KeyIcon,
  CloudIcon,
  CpuChipIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ArrowRightIcon,
  CalendarIcon,
  IdentificationIcon,
  FolderIcon,
  InformationCircleIcon,
  ArrowPathIcon,
  ChevronDownIcon,
  ChevronUpIcon,
} from "@heroicons/react/24/outline";
import type { TierMember, Tier0RoleType, TierLevel } from "../../types/tier";
import { tierConfig } from "../../types/tier";
import { MoveObjectModal } from "./MoveObjectModal";
import { GroupMembershipModal } from "./GroupMembershipModal";
import { getObjectGroups, getGroupMembers } from "../../services/tauri";

interface ObjectDetailsModalProps {
  member: TierMember | null;
  isOpen: boolean;
  onClose: () => void;
  onRefresh?: () => void;
}

function getObjectIcon(member: TierMember) {
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

function getRoleLabel(roleType: Tier0RoleType): string {
  switch (roleType) {
    case "DomainController":
      return "Domain Controller";
    case "ADFS":
      return "AD FS";
    case "EntraConnect":
      return "Entra Connect";
    case "CertificateAuthority":
      return "Certificate Authority";
    case "PAW":
      return "Privileged Access Workstation";
  }
}

function getObjectTypeLabel(objectType: string): string {
  switch (objectType) {
    case "User":
      return "User Account";
    case "Computer":
      return "Computer";
    case "AdminWorkstation":
      return "Admin Workstation";
    case "Group":
      return "Security Group";
    case "ServiceAccount":
      return "Service Account";
    default:
      return objectType;
  }
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return "Never";
  try {
    return new Date(dateStr).toLocaleString();
  } catch {
    return "Unknown";
  }
}

function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return "Never";
  try {
    const date = new Date(dateStr);
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

interface DetailRowProps {
  label: string;
  value: string | React.ReactNode;
  icon?: React.ElementType;
  copyable?: boolean;
  mono?: boolean;
}

function DetailRow({ label, value, icon: Icon, copyable, mono }: DetailRowProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (typeof value === "string") {
      navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="py-3 border-b border-gray-100 dark:border-gray-700 last:border-0">
      <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-1">
        {Icon && <Icon className="w-3.5 h-3.5" />}
        {label}
      </div>
      <div className="flex items-center gap-2">
        <span className={`text-sm text-gray-900 dark:text-gray-100 ${mono ? "font-mono" : ""} ${typeof value === "string" && value.length > 50 ? "break-all" : ""}`}>
          {value || "-"}
        </span>
        {copyable && typeof value === "string" && value && (
          <button
            onClick={handleCopy}
            className="flex-shrink-0 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded"
            title="Copy to clipboard"
          >
            {copied ? (
              <CheckIcon className="w-4 h-4 text-green-500" />
            ) : (
              <ClipboardDocumentIcon className="w-4 h-4" />
            )}
          </button>
        )}
      </div>
    </div>
  );
}

// Group members section - shows members of a group when expanded
function GroupMembersSection({ groupDn, memberCount }: { groupDn: string; memberCount: number }) {
  const [expanded, setExpanded] = useState(false);

  const { data: members, isLoading, error } = useQuery({
    queryKey: ["groupMembers", groupDn],
    queryFn: () => getGroupMembers(groupDn),
    enabled: expanded, // Only fetch when expanded
    staleTime: 30_000,
  });

  const getObjectIcon = (objectType: string) => {
    switch (objectType) {
      case "Computer":
        return ComputerDesktopIcon;
      case "Group":
        return UserGroupIcon;
      case "User":
      default:
        return UserIcon;
    }
  };

  return (
    <div className="py-3 border-b border-gray-100 dark:border-gray-700">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full text-left"
      >
        <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mb-1">
          <UserGroupIcon className="w-3.5 h-3.5" />
          Group Members
        </div>
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-900 dark:text-gray-100">
            {memberCount} member{memberCount !== 1 ? "s" : ""}
          </span>
          <div className="flex items-center gap-1 text-blue-600 dark:text-blue-400 text-xs">
            <span>{expanded ? "Hide" : "Show"}</span>
            {expanded ? (
              <ChevronUpIcon className="w-4 h-4" />
            ) : (
              <ChevronDownIcon className="w-4 h-4" />
            )}
          </div>
        </div>
      </button>

      {expanded && (
        <div className="mt-3 space-y-2">
          {isLoading && (
            <div className="flex items-center justify-center py-4">
              <ArrowPathIcon className="w-5 h-5 animate-spin text-gray-400" />
            </div>
          )}

          {error && (
            <div className="text-sm text-red-600 dark:text-red-400 py-2">
              Failed to load group members
            </div>
          )}

          {members && members.length === 0 && (
            <div className="text-sm text-gray-500 dark:text-gray-400 py-2">
              No members found
            </div>
          )}

          {members && members.length > 0 && (
            <div className="max-h-48 overflow-y-auto space-y-2">
              {members.map((m) => {
                const MemberIcon = getObjectIcon(m.objectType);
                return (
                  <div
                    key={m.distinguishedName}
                    className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-surface-900 rounded-lg"
                  >
                    <MemberIcon className={`w-4 h-4 flex-shrink-0 ${m.enabled ? "text-gray-400" : "text-gray-300"}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`text-sm font-medium truncate ${m.enabled ? "text-gray-900 dark:text-gray-100" : "text-gray-400 dark:text-gray-500"}`}>
                          {m.name}
                        </span>
                        {!m.enabled && (
                          <span className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 rounded">
                            Disabled
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate">
                        {m.samAccountName}
                      </p>
                    </div>
                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      {m.objectType}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Group membership list component
function GroupMembershipSection({ objectDn }: { objectDn: string }) {
  const [expanded, setExpanded] = useState(true);

  const { data: groups, isLoading, error } = useQuery({
    queryKey: ["objectGroups", objectDn],
    queryFn: () => getObjectGroups(objectDn),
    staleTime: 30_000,
  });

  const tierGroups = groups?.filter((g) => g.tier) || [];
  const otherGroups = groups?.filter((g) => !g.tier) || [];

  return (
    <div className="border-t border-gray-200 dark:border-gray-700 pt-4 mt-4">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center justify-between w-full text-left"
      >
        <div className="flex items-center gap-2">
          <UserGroupIcon className="w-4 h-4 text-gray-500 dark:text-gray-400" />
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
            Group Memberships
          </span>
          {groups && (
            <span className="px-1.5 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
              {groups.length}
            </span>
          )}
        </div>
        {expanded ? (
          <ChevronUpIcon className="w-4 h-4 text-gray-400" />
        ) : (
          <ChevronDownIcon className="w-4 h-4 text-gray-400" />
        )}
      </button>

      {expanded && (
        <div className="mt-3 space-y-3">
          {isLoading && (
            <div className="flex items-center justify-center py-4">
              <ArrowPathIcon className="w-5 h-5 animate-spin text-gray-400" />
            </div>
          )}

          {error && (
            <div className="text-sm text-red-600 dark:text-red-400 py-2">
              Failed to load group memberships
            </div>
          )}

          {groups && groups.length === 0 && (
            <div className="text-sm text-gray-500 dark:text-gray-400 py-2">
              No group memberships found
            </div>
          )}

          {/* Tier Groups */}
          {tierGroups.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
                Tier Groups
              </h4>
              <div className="space-y-2">
                {tierGroups.map((group) => {
                  const groupTierCfg = group.tier ? tierConfig[group.tier as TierLevel] : null;
                  return (
                    <div
                      key={group.groupDn}
                      className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-surface-900 rounded-lg"
                    >
                      <UserGroupIcon className="w-4 h-4 text-gray-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                            {group.groupName}
                          </span>
                          {groupTierCfg && (
                            <span className={`px-1.5 py-0.5 text-xs font-medium rounded ${groupTierCfg.badgeColor}`}>
                              {group.tier}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                          {group.groupType}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Other Groups */}
          {otherGroups.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
                Other Groups
              </h4>
              <div className="space-y-2">
                {otherGroups.map((group) => (
                  <div
                    key={group.groupDn}
                    className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-surface-900 rounded-lg"
                  >
                    <UserGroupIcon className="w-4 h-4 text-gray-400 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate block">
                        {group.groupName}
                      </span>
                      <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                        {group.groupType}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ObjectDetailsModal({
  member,
  isOpen,
  onClose,
  onRefresh,
}: ObjectDetailsModalProps) {
  const [showMoveModal, setShowMoveModal] = useState(false);
  const [showGroupModal, setShowGroupModal] = useState(false);

  if (!member) return null;

  const Icon = getObjectIcon(member);
  const tierCfg = member.tier ? tierConfig[member.tier as TierLevel] : null;

  const handleActionSuccess = () => {
    onRefresh?.();
  };

  return (
    <>
      <Dialog open={isOpen} onClose={onClose} className="relative z-50">
        <div className="fixed inset-0 bg-black/50" aria-hidden="true" />

        <div className="fixed inset-0 flex items-center justify-center p-4">
          <Dialog.Panel className="mx-auto max-w-lg w-full bg-white dark:bg-surface-800 rounded-xl shadow-2xl max-h-[90vh] flex flex-col">
            {/* Header */}
            <div className="flex items-start gap-4 p-6 border-b border-gray-200 dark:border-gray-700">
              <div
                className={`flex-shrink-0 w-14 h-14 rounded-xl flex items-center justify-center ${
                  member.enabled
                    ? "bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400"
                    : "bg-gray-100 dark:bg-gray-800 text-gray-400"
                }`}
              >
                <Icon className="w-7 h-7" />
              </div>

              <div className="flex-1 min-w-0">
                <Dialog.Title className="text-lg font-semibold text-gray-900 dark:text-white truncate">
                  {member.name}
                </Dialog.Title>
                <p className="text-sm text-gray-500 dark:text-gray-400 font-mono">
                  {member.samAccountName}
                </p>

                {/* Badges */}
                <div className="flex flex-wrap gap-2 mt-2">
                  <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                    member.enabled
                      ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                      : "bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400"
                  }`}>
                    {member.enabled ? "Enabled" : "Disabled"}
                  </span>

                  {tierCfg && (
                    <span className={`px-2 py-0.5 text-xs font-medium rounded ${tierCfg.badgeColor}`}>
                      {tierCfg.shortLabel}
                    </span>
                  )}

                  {!member.tier && (
                    <span className="px-2 py-0.5 text-xs font-medium rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300">
                      Unassigned
                    </span>
                  )}

                  {member.roleType && (
                    <span className="px-2 py-0.5 text-xs font-medium rounded bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                      {getRoleLabel(member.roleType)}
                    </span>
                  )}
                </div>
              </div>

              <button
                onClick={onClose}
                className="flex-shrink-0 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <XMarkIcon className="w-6 h-6" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              <div className="space-y-1">
                <DetailRow
                  label="Object Type"
                  value={getObjectTypeLabel(member.objectType)}
                  icon={IdentificationIcon}
                />

                <DetailRow
                  label="SAM Account Name"
                  value={member.samAccountName}
                  icon={UserIcon}
                  copyable
                  mono
                />

                <DetailRow
                  label="Distinguished Name"
                  value={member.distinguishedName}
                  icon={FolderIcon}
                  copyable
                  mono
                />

                {member.description && (
                  <DetailRow
                    label="Description"
                    value={member.description}
                    icon={InformationCircleIcon}
                  />
                )}

                <DetailRow
                  label="Last Logon"
                  value={
                    <span>
                      {formatRelativeTime(member.lastLogon)}
                      {member.lastLogon && (
                        <span className="text-gray-400 dark:text-gray-500 ml-2">
                          ({formatDate(member.lastLogon)})
                        </span>
                      )}
                    </span>
                  }
                  icon={CalendarIcon}
                />

                {member.operatingSystem && (
                  <DetailRow
                    label="Operating System"
                    value={member.operatingSystem}
                    icon={ComputerDesktopIcon}
                  />
                )}

                {member.memberCount !== null && member.objectType === "Group" && (
                  <GroupMembersSection
                    groupDn={member.distinguishedName}
                    memberCount={member.memberCount}
                  />
                )}

                <DetailRow
                  label="Tier Assignment"
                  value={
                    tierCfg ? (
                      <span className={tierCfg.textColor}>{tierCfg.label}</span>
                    ) : (
                      <span className="text-amber-600 dark:text-amber-400">Unassigned</span>
                    )
                  }
                  icon={ShieldCheckIcon}
                />
              </div>

              {/* Group Memberships Section */}
              <GroupMembershipSection objectDn={member.distinguishedName} />
            </div>

            {/* Actions */}
            <div className="flex justify-between gap-3 p-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-surface-850 rounded-b-xl">
              <button
                onClick={onClose}
                className="px-4 py-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors"
              >
                Close
              </button>

              <div className="flex gap-2">
                <button
                  onClick={() => setShowGroupModal(true)}
                  className="flex items-center gap-2 px-4 py-2 text-gray-700 dark:text-gray-300 bg-white dark:bg-surface-700 border border-gray-200 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-surface-600 transition-colors"
                >
                  <UserGroupIcon className="w-4 h-4" />
                  Groups
                </button>
                <button
                  onClick={() => setShowMoveModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <ArrowRightIcon className="w-4 h-4" />
                  Move
                </button>
              </div>
            </div>
          </Dialog.Panel>
        </div>
      </Dialog>

      {/* Sub-modals */}
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
}
