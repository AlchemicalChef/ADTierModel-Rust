import { useState, useMemo } from "react";
import { useTierStore } from "../../store/tierStore";
import { tierConfig } from "../../types/tier";
import type { TierLevel, TierMember } from "../../types/tier";
import { TierSummaryCard } from "./TierSummaryCard";
import { Tier0InfrastructurePanel } from "./Tier0InfrastructurePanel";
import { SearchFilterBar } from "./SearchFilterBar";
import { BulkActionsBar } from "./BulkActionsBar";
import { VirtualizedMemberGrid } from "./VirtualizedMemberGrid";
import { useQueryClient } from "@tanstack/react-query";

interface TierTabPanelProps {
  tier: TierLevel | "Unassigned";
}

type ViewMode = "members" | "infrastructure";

export function TierTabPanel({ tier }: TierTabPanelProps) {
  const {
    tier0Members,
    tier1Members,
    tier2Members,
    unassignedMembers,
    isLoading,
    filters,
    clearSelection,
  } = useTierStore();
  const [viewMode, setViewMode] = useState<ViewMode>("members");
  const queryClient = useQueryClient();

  const config = tierConfig[tier];

  // Get members for this tier
  const allMembers: TierMember[] = useMemo(() => {
    switch (tier) {
      case "Tier0":
        return tier0Members;
      case "Tier1":
        return tier1Members;
      case "Tier2":
        return tier2Members;
      case "Unassigned":
        return unassignedMembers;
    }
  }, [tier, tier0Members, tier1Members, tier2Members, unassignedMembers]);

  // Apply filters
  const filteredMembers = useMemo(() => {
    let result = allMembers;

    // Search filter
    if (filters.searchQuery) {
      const query = filters.searchQuery.toLowerCase();
      result = result.filter(
        (m) =>
          m.name.toLowerCase().includes(query) ||
          m.samAccountName.toLowerCase().includes(query) ||
          m.distinguishedName.toLowerCase().includes(query)
      );
    }

    // Object type filter
    if (filters.objectType !== "all") {
      result = result.filter((m) => m.objectType === filters.objectType);
    }

    // Status filter
    if (filters.status !== "all") {
      const isEnabled = filters.status === "enabled";
      result = result.filter((m) => m.enabled === isEnabled);
    }

    // Last logon filter
    if (filters.lastLogon !== "all") {
      const now = new Date();
      result = result.filter((m) => {
        if (filters.lastLogon === "never") {
          return !m.lastLogon;
        }

        if (!m.lastLogon) {
          return filters.lastLogon === "stale"; // Never logged in counts as stale
        }

        const lastLogon = new Date(m.lastLogon);
        const diffDays = Math.floor((now.getTime() - lastLogon.getTime()) / (1000 * 60 * 60 * 24));

        switch (filters.lastLogon) {
          case "7days":
            return diffDays <= 7;
          case "30days":
            return diffDays <= 30;
          case "90days":
            return diffDays <= 90;
          case "stale":
            return diffDays > 90;
          default:
            return true;
        }
      });
    }

    return result;
  }, [allMembers, filters]);

  // Group filtered members by object type
  const computers = filteredMembers.filter((m) =>
    ["Computer", "AdminWorkstation"].includes(m.objectType)
  );
  const users = filteredMembers.filter((m) =>
    ["User", "ServiceAccount"].includes(m.objectType)
  );
  const groups = filteredMembers.filter((m) => m.objectType === "Group");

  const handleRefresh = () => {
    clearSelection();
    queryClient.invalidateQueries({ queryKey: ["tierMembers"] });
    queryClient.invalidateQueries({ queryKey: ["tierCounts"] });
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4" />
          <p className="text-gray-500 dark:text-gray-400">Loading {config.label}...</p>
        </div>
      </div>
    );
  }

  if (allMembers.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div
            className={`w-16 h-16 rounded-full ${config.bgColor} flex items-center justify-center mx-auto mb-4`}
          >
            <span className={`text-2xl font-bold ${config.textColor}`}>0</span>
          </div>
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100 mb-1">
            No objects in {config.label}
          </h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            {tier === "Unassigned"
              ? "All objects are assigned to tiers"
              : "No computers, users, or groups found in this tier"}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* View Toggle for Tier0 */}
      {tier === "Tier0" && (
        <div className="flex items-center gap-2 bg-white dark:bg-surface-800 rounded-lg p-1 w-fit">
          <button
            onClick={() => setViewMode("members")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              viewMode === "members"
                ? "bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-200"
                : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
            }`}
          >
            Members
          </button>
          <button
            onClick={() => setViewMode("infrastructure")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              viewMode === "infrastructure"
                ? "bg-red-100 dark:bg-red-900/50 text-red-800 dark:text-red-200"
                : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
            }`}
          >
            Infrastructure
          </button>
        </div>
      )}

      {/* Infrastructure Panel for Tier0 */}
      {tier === "Tier0" && viewMode === "infrastructure" && (
        <Tier0InfrastructurePanel />
      )}

      {/* Members View */}
      {(tier !== "Tier0" || viewMode === "members") && (
        <>
          {/* Search and Filter Bar */}
          <SearchFilterBar
            totalCount={allMembers.length}
            filteredCount={filteredMembers.length}
            tier={tier}
            members={filteredMembers}
          />

          {/* Bulk Actions Bar */}
          {tier !== "Unassigned" && (
            <BulkActionsBar
              members={filteredMembers}
              currentTier={tier}
              onRefresh={handleRefresh}
            />
          )}

          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <TierSummaryCard
              title="Computers"
              count={computers.length}
              tier={tier}
              icon="computer"
            />
            <TierSummaryCard
              title="Users"
              count={users.length}
              tier={tier}
              icon="user"
            />
            <TierSummaryCard
              title="Groups"
              count={groups.length}
              tier={tier}
              icon="group"
            />
          </div>

          {/* No results message */}
          {filteredMembers.length === 0 && allMembers.length > 0 && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              No objects match your search criteria
            </div>
          )}

          {/* Virtualized Members Grid */}
          {filteredMembers.length > 0 && (
            <VirtualizedMemberGrid
              members={{ computers, users, groups }}
              tier={tier}
              onRefresh={handleRefresh}
            />
          )}
        </>
      )}
    </div>
  );
}
