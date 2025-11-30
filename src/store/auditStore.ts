import { create } from "zustand";
import { persist } from "zustand/middleware";

export type AuditAction =
  | "move_object"
  | "add_to_group"
  | "remove_from_group"
  | "bulk_move"
  | "bulk_add_to_group"
  | "bulk_remove_from_group"
  | "bulk_disable"
  | "initialize_tier_model"
  | "move_tier0_component"
  | "remediate_violation"
  | "create_account"
  | "export";

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: AuditAction;
  description: string;
  targetObjects: string[];
  targetTier?: string;
  targetGroup?: string;
  success: boolean;
  error?: string;
  details?: Record<string, unknown>;
}

interface AuditState {
  entries: AuditLogEntry[];
  maxEntries: number;

  // Actions
  addEntry: (entry: Omit<AuditLogEntry, "id" | "timestamp">) => void;
  clearEntries: () => void;
  getRecentEntries: (count: number) => AuditLogEntry[];
}

function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export const useAuditStore = create<AuditState>()(
  persist(
    (set, get) => ({
      entries: [],
      maxEntries: 500, // Keep last 500 entries

      addEntry: (entry) =>
        set((state) => {
          const newEntry: AuditLogEntry = {
            ...entry,
            id: generateId(),
            timestamp: new Date().toISOString(),
          };

          const newEntries = [newEntry, ...state.entries].slice(0, state.maxEntries);
          return { entries: newEntries };
        }),

      clearEntries: () => set({ entries: [] }),

      getRecentEntries: (count) => get().entries.slice(0, count),
    }),
    {
      name: "audit-log-storage",
    }
  )
);

// Helper function to log an audit entry
export function logAudit(
  action: AuditAction,
  description: string,
  targetObjects: string[],
  success: boolean,
  options?: {
    targetTier?: string;
    targetGroup?: string;
    error?: string;
    details?: Record<string, unknown>;
  }
): void {
  useAuditStore.getState().addEntry({
    action,
    description,
    targetObjects,
    success,
    targetTier: options?.targetTier,
    targetGroup: options?.targetGroup,
    error: options?.error,
    details: options?.details,
  });
}

// Action display names
export const actionLabels: Record<AuditAction, string> = {
  move_object: "Move Object",
  add_to_group: "Add to Group",
  remove_from_group: "Remove from Group",
  bulk_move: "Bulk Move",
  bulk_add_to_group: "Bulk Add to Group",
  bulk_remove_from_group: "Bulk Remove from Group",
  bulk_disable: "Bulk Disable Accounts",
  initialize_tier_model: "Initialize Tier Model",
  move_tier0_component: "Move Tier 0 Component",
  remediate_violation: "Remediate Violation",
  create_account: "Create Account",
  export: "Export Report",
};
