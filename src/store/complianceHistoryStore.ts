import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface ComplianceSnapshot {
  timestamp: string;
  score: number;
  totalViolations: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

interface ComplianceHistoryState {
  snapshots: ComplianceSnapshot[];
  maxSnapshots: number;

  // Actions
  addSnapshot: (snapshot: Omit<ComplianceSnapshot, "timestamp">) => void;
  getRecentSnapshots: (count: number) => ComplianceSnapshot[];
  clearHistory: () => void;
}

export const useComplianceHistoryStore = create<ComplianceHistoryState>()(
  persist(
    (set, get) => ({
      snapshots: [],
      maxSnapshots: 90, // Keep 90 days of history

      addSnapshot: (snapshot) =>
        set((state) => {
          const now = new Date();
          const today = now.toISOString().split("T")[0];

          // Check if we already have a snapshot for today
          const existingTodayIndex = state.snapshots.findIndex(
            (s) => s.timestamp.startsWith(today)
          );

          const newSnapshot: ComplianceSnapshot = {
            ...snapshot,
            timestamp: now.toISOString(),
          };

          let newSnapshots: ComplianceSnapshot[];

          if (existingTodayIndex >= 0) {
            // Update today's snapshot
            newSnapshots = [...state.snapshots];
            newSnapshots[existingTodayIndex] = newSnapshot;
          } else {
            // Add new snapshot
            newSnapshots = [newSnapshot, ...state.snapshots].slice(
              0,
              state.maxSnapshots
            );
          }

          return { snapshots: newSnapshots };
        }),

      getRecentSnapshots: (count) => get().snapshots.slice(0, count),

      clearHistory: () => set({ snapshots: [] }),
    }),
    {
      name: "compliance-history-storage",
    }
  )
);

// Helper to get trend direction
export function getTrendDirection(
  snapshots: ComplianceSnapshot[]
): "up" | "down" | "stable" {
  if (snapshots.length < 2) return "stable";

  const recent = snapshots[0].score;
  const previous = snapshots[1].score;

  if (recent > previous) return "up";
  if (recent < previous) return "down";
  return "stable";
}

// Helper to calculate average score over period
export function getAverageScore(snapshots: ComplianceSnapshot[]): number {
  if (snapshots.length === 0) return 0;
  const sum = snapshots.reduce((acc, s) => acc + s.score, 0);
  return Math.round(sum / snapshots.length);
}

// Helper to get score change over period
export function getScoreChange(snapshots: ComplianceSnapshot[]): number {
  if (snapshots.length < 2) return 0;
  return snapshots[0].score - snapshots[snapshots.length - 1].score;
}
