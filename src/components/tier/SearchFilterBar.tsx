import {
  MagnifyingGlassIcon,
  FunnelIcon,
  XMarkIcon,
  ComputerDesktopIcon,
  UserIcon,
  UserGroupIcon,
  CheckCircleIcon,
  XCircleIcon,
  DocumentArrowDownIcon,
  CalendarIcon,
  ClockIcon,
} from "@heroicons/react/24/outline";
import { Menu } from "@headlessui/react";
import { useTierStore, type ObjectTypeFilter, type StatusFilter, type LastLogonFilter } from "../../store/tierStore";
import { exportTierMembersToCSV } from "../../services/export";
import type { TierLevel, TierMember } from "../../types/tier";

const objectTypeOptions: { value: ObjectTypeFilter; label: string; icon: React.ElementType }[] = [
  { value: "all", label: "All Types", icon: FunnelIcon },
  { value: "Computer", label: "Computers", icon: ComputerDesktopIcon },
  { value: "User", label: "Users", icon: UserIcon },
  { value: "ServiceAccount", label: "Service Accounts", icon: UserIcon },
  { value: "Group", label: "Groups", icon: UserGroupIcon },
  { value: "AdminWorkstation", label: "Admin Workstations", icon: ComputerDesktopIcon },
];

const statusOptions: { value: StatusFilter; label: string; icon: React.ElementType }[] = [
  { value: "all", label: "All Status", icon: FunnelIcon },
  { value: "enabled", label: "Enabled", icon: CheckCircleIcon },
  { value: "disabled", label: "Disabled", icon: XCircleIcon },
];

const lastLogonOptions: { value: LastLogonFilter; label: string; icon: React.ElementType }[] = [
  { value: "all", label: "Any Time", icon: CalendarIcon },
  { value: "7days", label: "Last 7 days", icon: ClockIcon },
  { value: "30days", label: "Last 30 days", icon: ClockIcon },
  { value: "90days", label: "Last 90 days", icon: ClockIcon },
  { value: "stale", label: "Stale (90+ days)", icon: XCircleIcon },
  { value: "never", label: "Never logged in", icon: XCircleIcon },
];

interface SearchFilterBarProps {
  totalCount: number;
  filteredCount: number;
  tier: TierLevel | "Unassigned";
  members: TierMember[];
}

export function SearchFilterBar({ totalCount, filteredCount, tier, members }: SearchFilterBarProps) {
  const {
    filters,
    setSearchQuery,
    setObjectTypeFilter,
    setStatusFilter,
    setLastLogonFilter,
    clearFilters,
  } = useTierStore();

  const hasActiveFilters =
    filters.searchQuery !== "" ||
    filters.objectType !== "all" ||
    filters.status !== "all" ||
    filters.lastLogon !== "all";

  const currentTypeOption = objectTypeOptions.find((o) => o.value === filters.objectType);
  const currentStatusOption = statusOptions.find((o) => o.value === filters.status);
  const currentLastLogonOption = lastLogonOptions.find((o) => o.value === filters.lastLogon);

  return (
    <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-3 mb-4">
      <div className="flex flex-wrap items-center gap-3">
        {/* Search Input */}
        <div className="relative flex-1 min-w-[200px]">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={filters.searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by name or SAM account..."
            className="w-full pl-9 pr-3 py-2 text-sm bg-gray-50 dark:bg-surface-900 border border-gray-200 dark:border-gray-700 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none text-gray-900 dark:text-gray-100 placeholder-gray-400"
          />
          {filters.searchQuery && (
            <button
              onClick={() => setSearchQuery("")}
              className="absolute right-2 top-1/2 -translate-y-1/2 p-1 hover:bg-gray-200 dark:hover:bg-surface-700 rounded"
            >
              <XMarkIcon className="w-4 h-4 text-gray-400" />
            </button>
          )}
        </div>

        {/* Object Type Filter */}
        <Menu as="div" className="relative">
          <Menu.Button
            className={`flex items-center gap-2 px-3 py-2 text-sm border rounded-lg transition-colors ${
              filters.objectType !== "all"
                ? "bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300"
                : "bg-gray-50 dark:bg-surface-900 border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-surface-800"
            }`}
          >
            {currentTypeOption && <currentTypeOption.icon className="w-4 h-4" />}
            <span>{currentTypeOption?.label || "Type"}</span>
          </Menu.Button>
          <Menu.Items className="absolute right-0 mt-1 w-48 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20">
            {objectTypeOptions.map((option) => (
              <Menu.Item key={option.value}>
                {({ active }) => (
                  <button
                    onClick={() => setObjectTypeFilter(option.value)}
                    className={`flex items-center gap-2 w-full px-3 py-2 text-sm ${
                      active
                        ? "bg-gray-100 dark:bg-surface-700"
                        : ""
                    } ${
                      filters.objectType === option.value
                        ? "text-blue-600 dark:text-blue-400 font-medium"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <option.icon className="w-4 h-4" />
                    {option.label}
                  </button>
                )}
              </Menu.Item>
            ))}
          </Menu.Items>
        </Menu>

        {/* Status Filter */}
        <Menu as="div" className="relative">
          <Menu.Button
            className={`flex items-center gap-2 px-3 py-2 text-sm border rounded-lg transition-colors ${
              filters.status !== "all"
                ? "bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300"
                : "bg-gray-50 dark:bg-surface-900 border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-surface-800"
            }`}
          >
            {currentStatusOption && <currentStatusOption.icon className="w-4 h-4" />}
            <span>{currentStatusOption?.label || "Status"}</span>
          </Menu.Button>
          <Menu.Items className="absolute right-0 mt-1 w-40 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20">
            {statusOptions.map((option) => (
              <Menu.Item key={option.value}>
                {({ active }) => (
                  <button
                    onClick={() => setStatusFilter(option.value)}
                    className={`flex items-center gap-2 w-full px-3 py-2 text-sm ${
                      active
                        ? "bg-gray-100 dark:bg-surface-700"
                        : ""
                    } ${
                      filters.status === option.value
                        ? "text-blue-600 dark:text-blue-400 font-medium"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <option.icon className="w-4 h-4" />
                    {option.label}
                  </button>
                )}
              </Menu.Item>
            ))}
          </Menu.Items>
        </Menu>

        {/* Last Logon Filter */}
        <Menu as="div" className="relative">
          <Menu.Button
            className={`flex items-center gap-2 px-3 py-2 text-sm border rounded-lg transition-colors ${
              filters.lastLogon !== "all"
                ? "bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300"
                : "bg-gray-50 dark:bg-surface-900 border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-surface-800"
            }`}
          >
            {currentLastLogonOption && <currentLastLogonOption.icon className="w-4 h-4" />}
            <span>{currentLastLogonOption?.label || "Last Logon"}</span>
          </Menu.Button>
          <Menu.Items className="absolute right-0 mt-1 w-48 bg-white dark:bg-surface-800 rounded-lg shadow-lg border border-gray-200 dark:border-gray-700 py-1 z-20">
            {lastLogonOptions.map((option) => (
              <Menu.Item key={option.value}>
                {({ active }) => (
                  <button
                    onClick={() => setLastLogonFilter(option.value)}
                    className={`flex items-center gap-2 w-full px-3 py-2 text-sm ${
                      active
                        ? "bg-gray-100 dark:bg-surface-700"
                        : ""
                    } ${
                      filters.lastLogon === option.value
                        ? "text-blue-600 dark:text-blue-400 font-medium"
                        : "text-gray-700 dark:text-gray-300"
                    }`}
                  >
                    <option.icon className="w-4 h-4" />
                    {option.label}
                  </button>
                )}
              </Menu.Item>
            ))}
          </Menu.Items>
        </Menu>

        {/* Clear Filters */}
        {hasActiveFilters && (
          <button
            onClick={clearFilters}
            className="flex items-center gap-1 px-3 py-2 text-sm text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-surface-700 rounded-lg transition-colors"
          >
            <XMarkIcon className="w-4 h-4" />
            Clear
          </button>
        )}

        {/* Export Button */}
        <button
          onClick={() => exportTierMembersToCSV(members, tier)}
          disabled={members.length === 0}
          className="flex items-center gap-2 px-3 py-2 text-sm bg-gray-50 dark:bg-surface-900 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-surface-800 disabled:opacity-50 transition-colors"
        >
          <DocumentArrowDownIcon className="w-4 h-4" />
          Export
        </button>

        {/* Results Count */}
        <div className="ml-auto text-sm text-gray-500 dark:text-gray-400">
          {hasActiveFilters ? (
            <span>
              Showing <span className="font-medium text-gray-900 dark:text-white">{filteredCount}</span> of{" "}
              <span className="font-medium">{totalCount}</span>
            </span>
          ) : (
            <span>
              <span className="font-medium text-gray-900 dark:text-white">{totalCount}</span> objects
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
