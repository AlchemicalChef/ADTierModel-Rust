import { useState } from "react";
import {
  SunIcon,
  MoonIcon,
  ComputerDesktopIcon,
  ArrowPathIcon,
  ClockIcon,
  ShieldExclamationIcon,
  Cog6ToothIcon,
  ShieldCheckIcon,
  SignalIcon,
} from "@heroicons/react/24/outline";
import { useSettingsStore, type ThemeMode, type RefreshInterval } from "../../store/settingsStore";
import { useTierStore } from "../../store/tierStore";
import { GpoManagementPanel } from "../gpo";
import { HealthCheckPanel } from "../health";

const themeOptions: { value: ThemeMode; label: string; icon: React.ElementType }[] = [
  { value: "light", label: "Light", icon: SunIcon },
  { value: "dark", label: "Dark", icon: MoonIcon },
  { value: "system", label: "System", icon: ComputerDesktopIcon },
];

const refreshOptions: { value: RefreshInterval; label: string }[] = [
  { value: "off", label: "Off" },
  { value: "1min", label: "1 minute" },
  { value: "5min", label: "5 minutes" },
  { value: "15min", label: "15 minutes" },
];

type SettingsView = "general" | "gpo" | "health";

export function SettingsPanel() {
  const [activeView, setActiveView] = useState<SettingsView>("general");
  const {
    theme,
    staleAccountThresholdDays,
    autoRefreshInterval,
    setTheme,
    setStaleAccountThreshold,
    setAutoRefreshInterval,
    resetToDefaults,
  } = useSettingsStore();

  const { domainInfo } = useTierStore();

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header with tabs */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center gap-2">
            <Cog6ToothIcon className="w-5 h-5" />
            Settings
          </h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Configure application preferences
          </p>
        </div>
        <div className="flex rounded-lg bg-gray-100 dark:bg-surface-800 p-1">
          <button
            onClick={() => setActiveView("general")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeView === "general"
                ? "bg-white dark:bg-surface-700 text-gray-900 dark:text-white shadow-sm"
                : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
            }`}
          >
            <Cog6ToothIcon className="w-4 h-4" />
            General
          </button>
          <button
            onClick={() => setActiveView("gpo")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeView === "gpo"
                ? "bg-white dark:bg-surface-700 text-gray-900 dark:text-white shadow-sm"
                : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
            }`}
          >
            <ShieldCheckIcon className="w-4 h-4" />
            GPO Management
          </button>
          <button
            onClick={() => setActiveView("health")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeView === "health"
                ? "bg-white dark:bg-surface-700 text-gray-900 dark:text-white shadow-sm"
                : "text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
            }`}
          >
            <SignalIcon className="w-4 h-4" />
            Health
          </button>
        </div>
      </div>

      {activeView === "health" ? (
        <HealthCheckPanel />
      ) : activeView === "gpo" ? (
        <GpoManagementPanel />
      ) : (
        <div className="max-w-2xl space-y-6">

      {/* Domain Connection Info */}
      <section className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
          Domain Connection
        </h3>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">Domain</p>
            <p className="text-sm font-medium text-gray-900 dark:text-white">
              {domainInfo?.dnsRoot || "Not connected"}
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">NetBIOS Name</p>
            <p className="text-sm font-medium text-gray-900 dark:text-white">
              {domainInfo?.netbiosName || "-"}
            </p>
          </div>
          <div className="col-span-2">
            <p className="text-xs text-gray-500 dark:text-gray-400">Domain DN</p>
            <p className="text-sm font-mono text-gray-600 dark:text-gray-400">
              {domainInfo?.domainDn || "-"}
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 dark:text-gray-400">Status</p>
            <span
              className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded ${
                domainInfo?.connected
                  ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                  : "bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
              }`}
            >
              {domainInfo?.connected ? "Connected" : "Mock Mode"}
            </span>
          </div>
        </div>
      </section>

      {/* Appearance */}
      <section className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
          <SunIcon className="w-4 h-4" />
          Appearance
        </h3>
        <div>
          <label className="block text-xs text-gray-500 dark:text-gray-400 mb-2">
            Theme
          </label>
          <div className="flex gap-2">
            {themeOptions.map((option) => (
              <button
                key={option.value}
                onClick={() => setTheme(option.value)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  theme === option.value
                    ? "bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-200"
                    : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                }`}
              >
                <option.icon className="w-4 h-4" />
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {/* Compliance Settings */}
      <section className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
          <ShieldExclamationIcon className="w-4 h-4" />
          Compliance
        </h3>
        <div>
          <label className="block text-xs text-gray-500 dark:text-gray-400 mb-2">
            Stale Account Threshold: {staleAccountThresholdDays} days
          </label>
          <div className="flex items-center gap-4">
            <input
              type="range"
              min={30}
              max={365}
              step={15}
              value={staleAccountThresholdDays}
              onChange={(e) => setStaleAccountThreshold(parseInt(e.target.value))}
              className="flex-1 h-2 bg-gray-200 dark:bg-surface-700 rounded-lg appearance-none cursor-pointer"
            />
            <span className="text-sm text-gray-600 dark:text-gray-400 w-16 text-right">
              {staleAccountThresholdDays}d
            </span>
          </div>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
            Accounts that haven't logged in within this period will be flagged as stale.
          </p>
        </div>
      </section>

      {/* Auto Refresh */}
      <section className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
          <ArrowPathIcon className="w-4 h-4" />
          Auto Refresh
        </h3>
        <div>
          <label className="block text-xs text-gray-500 dark:text-gray-400 mb-2">
            Refresh Interval
          </label>
          <div className="flex gap-2">
            {refreshOptions.map((option) => (
              <button
                key={option.value}
                onClick={() => setAutoRefreshInterval(option.value)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  autoRefreshInterval === option.value
                    ? "bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-200"
                    : "bg-gray-100 dark:bg-surface-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-surface-600"
                }`}
              >
                {option.value !== "off" && <ClockIcon className="w-4 h-4" />}
                {option.label}
              </button>
            ))}
          </div>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
            Automatically refresh tier data and compliance status.
          </p>
        </div>
      </section>

      {/* Reset */}
      <section className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Reset Settings
            </h3>
            <p className="text-xs text-gray-400 dark:text-gray-500">
              Restore all settings to their default values
            </p>
          </div>
          <button
            onClick={resetToDefaults}
            className="px-4 py-2 text-sm font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors"
          >
            Reset to Defaults
          </button>
        </div>
      </section>

      {/* Version Info */}
      <div className="text-center text-xs text-gray-400 dark:text-gray-500">
        AD Tier Model Manager v1.0.0
      </div>
        </div>
      )}
    </div>
  );
}
