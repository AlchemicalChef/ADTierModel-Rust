import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { TierLevel, TierCounts, DomainInfo, TierMember, ObjectType } from "../types/tier";

// Filter options
export type ObjectTypeFilter = ObjectType | "all";
export type StatusFilter = "all" | "enabled" | "disabled";
export type LastLogonFilter = "all" | "7days" | "30days" | "90days" | "never" | "stale";

interface SearchFilters {
  searchQuery: string;
  objectType: ObjectTypeFilter;
  status: StatusFilter;
  lastLogon: LastLogonFilter;
}

interface TierState {
  // Current state
  selectedTier: TierLevel | "Unassigned";
  tierCounts: TierCounts;
  isConnected: boolean;
  domainInfo: DomainInfo | null;
  isLoading: boolean;
  error: string | null;

  // Search and filter
  filters: SearchFilters;
  selectedMembers: Set<string>; // Set of distinguished names

  // Tier data
  tier0Members: TierMember[];
  tier1Members: TierMember[];
  tier2Members: TierMember[];
  unassignedMembers: TierMember[];

  // Actions
  setSelectedTier: (tier: TierLevel | "Unassigned") => void;
  setTierCounts: (counts: TierCounts) => void;
  setConnected: (connected: boolean) => void;
  setDomainInfo: (info: DomainInfo | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setTierMembers: (tier: TierLevel | "Unassigned", members: TierMember[]) => void;
  clearAllData: () => void;

  // Search and filter actions
  setSearchQuery: (query: string) => void;
  setObjectTypeFilter: (type: ObjectTypeFilter) => void;
  setStatusFilter: (status: StatusFilter) => void;
  setLastLogonFilter: (lastLogon: LastLogonFilter) => void;
  clearFilters: () => void;

  // Bulk selection actions
  toggleMemberSelection: (dn: string) => void;
  selectAllMembers: (dns: string[]) => void;
  clearSelection: () => void;
  isSelected: (dn: string) => boolean;
}

export const useTierStore = create<TierState>()(
  persist(
    (set, get) => ({
      // Initial state
      selectedTier: "Tier0",
      tierCounts: { Tier0: 0, Tier1: 0, Tier2: 0, Unassigned: 0 },
      isConnected: false,
      domainInfo: null,
      isLoading: false,
      error: null,
      tier0Members: [],
      tier1Members: [],
      tier2Members: [],
      unassignedMembers: [],

      // Search and filter state
      filters: {
        searchQuery: "",
        objectType: "all",
        status: "all",
        lastLogon: "all",
      },
      selectedMembers: new Set<string>(),

      // Actions
      setSelectedTier: (tier) => set({ selectedTier: tier }),
      setTierCounts: (counts) => set({ tierCounts: counts }),
      setConnected: (connected) => set({ isConnected: connected }),
      setDomainInfo: (info) => set({ domainInfo: info }),
      setLoading: (loading) => set({ isLoading: loading }),
      setError: (error) => set({ error }),
      setTierMembers: (tier, members) => {
        switch (tier) {
          case "Tier0":
            set({ tier0Members: members });
            break;
          case "Tier1":
            set({ tier1Members: members });
            break;
          case "Tier2":
            set({ tier2Members: members });
            break;
          case "Unassigned":
            set({ unassignedMembers: members });
            break;
        }
      },
      clearAllData: () =>
        set({
          tier0Members: [],
          tier1Members: [],
          tier2Members: [],
          unassignedMembers: [],
          tierCounts: { Tier0: 0, Tier1: 0, Tier2: 0, Unassigned: 0 },
        }),

      // Search and filter actions
      setSearchQuery: (query) =>
        set((state) => ({
          filters: { ...state.filters, searchQuery: query },
        })),
      setObjectTypeFilter: (type) =>
        set((state) => ({
          filters: { ...state.filters, objectType: type },
        })),
      setStatusFilter: (status) =>
        set((state) => ({
          filters: { ...state.filters, status: status },
        })),
      setLastLogonFilter: (lastLogon) =>
        set((state) => ({
          filters: { ...state.filters, lastLogon: lastLogon },
        })),
      clearFilters: () =>
        set({
          filters: { searchQuery: "", objectType: "all", status: "all", lastLogon: "all" },
        }),

      // Bulk selection actions
      toggleMemberSelection: (dn) =>
        set((state) => {
          const newSelection = new Set(state.selectedMembers);
          if (newSelection.has(dn)) {
            newSelection.delete(dn);
          } else {
            newSelection.add(dn);
          }
          return { selectedMembers: newSelection };
        }),
      selectAllMembers: (dns) =>
        set({ selectedMembers: new Set(dns) }),
      clearSelection: () =>
        set({ selectedMembers: new Set() }),
      isSelected: (dn) => get().selectedMembers.has(dn),
    }),
    {
      name: "tier-storage",
      partialize: (state) => ({
        selectedTier: state.selectedTier,
      }),
    }
  )
);
