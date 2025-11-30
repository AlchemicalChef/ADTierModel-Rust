import { create } from "zustand";
import { persist } from "zustand/middleware";

export type ThemeMode = "light" | "dark" | "system";
export type RefreshInterval = "off" | "1min" | "5min" | "15min";

interface SettingsState {
  // Appearance
  theme: ThemeMode;

  // Compliance Settings
  staleAccountThresholdDays: number;

  // Refresh Settings
  autoRefreshInterval: RefreshInterval;

  // Actions
  setTheme: (theme: ThemeMode) => void;
  setStaleAccountThreshold: (days: number) => void;
  setAutoRefreshInterval: (interval: RefreshInterval) => void;
  resetToDefaults: () => void;
}

const defaultSettings = {
  theme: "system" as ThemeMode,
  staleAccountThresholdDays: 90,
  autoRefreshInterval: "off" as RefreshInterval,
};

export const useSettingsStore = create<SettingsState>()(
  persist(
    (set) => ({
      ...defaultSettings,

      setTheme: (theme) => {
        set({ theme });
        applyTheme(theme);
      },

      setStaleAccountThreshold: (days) => {
        set({ staleAccountThresholdDays: days });
      },

      setAutoRefreshInterval: (interval) => {
        set({ autoRefreshInterval: interval });
      },

      resetToDefaults: () => {
        set(defaultSettings);
        applyTheme(defaultSettings.theme);
      },
    }),
    {
      name: "ad-tier-model-settings",
      onRehydrateStorage: () => (state) => {
        // Apply theme on rehydration
        if (state) {
          applyTheme(state.theme);
        }
      },
    }
  )
);

// Apply theme to document
function applyTheme(theme: ThemeMode) {
  const root = document.documentElement;

  if (theme === "system") {
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    root.classList.toggle("dark", prefersDark);
  } else {
    root.classList.toggle("dark", theme === "dark");
  }
}

// Convert refresh interval to milliseconds
export function getRefreshIntervalMs(interval: RefreshInterval): number | null {
  switch (interval) {
    case "1min":
      return 60 * 1000;
    case "5min":
      return 5 * 60 * 1000;
    case "15min":
      return 15 * 60 * 1000;
    default:
      return null;
  }
}
