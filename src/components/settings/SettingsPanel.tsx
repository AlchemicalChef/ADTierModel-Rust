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
  BuildingOfficeIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  XCircleIcon,
} from "@heroicons/react/24/outline";
import { useSettingsStore, type ThemeMode, type RefreshInterval } from "../../store/settingsStore";
import { useTierStore } from "../../store/tierStore";
import { GpoManagementPanel } from "../gpo";
import { HealthCheckPanel } from "../health";
import { initializeAdTierModel, checkTierInitialization } from "../../services/tauri";
import type { InitializationResult, InitializationStatus } from "../../types/tier";

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
  const [initStatus, setInitStatus] = useState<InitializationStatus | null>(null);
  const [initResult, setInitResult] = useState<InitializationResult | null>(null);
  const [isInitializing, setIsInitializing] = useState(false);
  const [isCheckingStatus, setIsCheckingStatus] = useState(false);

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

  const handleCheckStatus = async () => {
    setIsCheckingStatus(true);
    try {
      const status = await checkTierInitialization();
      setInitStatus(status);
    } catch (error) {
      console.error("Failed to check initialization status:", error);
    } finally {
      setIsCheckingStatus(false);
    }
  };

  const handleInitialize = async (options: {
    createOuStructure: boolean;
    createGroups: boolean;
    setPermissions: boolean;
    createGpos: boolean;
  }) => {
    setIsInitializing(true);
    setInitResult(null);
    try {
      const result = await initializeAdTierModel({
        ...options,
        force: false,
      });
      setInitResult(result);
      // Refresh status after initialization
      await handleCheckStatus();
    } catch (error) {
      console.error("Initialization failed:", error);
      setInitResult({
        success: false,
        ousCreated: [],
        groupsCreated: [],
        permissionsSet: [],
        gposCreated: [],
        warnings: [],
        errors: [String(error)],
      });
    } finally {
      setIsInitializing(false);
    }
  };

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

      {/* Tier Structure Initialization */}
      <section className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3 flex items-center gap-2">
          <BuildingOfficeIcon className="w-4 h-4" />
          Tier Structure Initialization
        </h3>
        <p className="text-xs text-gray-400 dark:text-gray-500 mb-4">
          Initialize or reinitialize the AD tier model structure including OUs, groups, and GPOs.
        </p>

        {/* Check Status Button */}
        <div className="mb-4">
          <button
            onClick={handleCheckStatus}
            disabled={isCheckingStatus}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/30 transition-colors disabled:opacity-50"
          >
            {isCheckingStatus ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <SignalIcon className="w-4 h-4" />
            )}
            Check Current Status
          </button>
        </div>

        {/* Status Display */}
        {initStatus && (
          <div className="mb-4 p-3 bg-gray-50 dark:bg-surface-800 rounded-lg">
            <h4 className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Current Status</h4>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-1">
                {initStatus.tier0OuExists ? (
                  <CheckCircleIcon className="w-4 h-4 text-green-500" />
                ) : (
                  <XCircleIcon className="w-4 h-4 text-red-500" />
                )}
                <span className="text-gray-600 dark:text-gray-400">Tier 0 OU</span>
              </div>
              <div className="flex items-center gap-1">
                {initStatus.tier1OuExists ? (
                  <CheckCircleIcon className="w-4 h-4 text-green-500" />
                ) : (
                  <XCircleIcon className="w-4 h-4 text-red-500" />
                )}
                <span className="text-gray-600 dark:text-gray-400">Tier 1 OU</span>
              </div>
              <div className="flex items-center gap-1">
                {initStatus.tier2OuExists ? (
                  <CheckCircleIcon className="w-4 h-4 text-green-500" />
                ) : (
                  <XCircleIcon className="w-4 h-4 text-red-500" />
                )}
                <span className="text-gray-600 dark:text-gray-400">Tier 2 OU</span>
              </div>
              <div className="flex items-center gap-1">
                {initStatus.groupsExist ? (
                  <CheckCircleIcon className="w-4 h-4 text-green-500" />
                ) : (
                  <XCircleIcon className="w-4 h-4 text-red-500" />
                )}
                <span className="text-gray-600 dark:text-gray-400">Groups</span>
              </div>
            </div>
            {initStatus.missingComponents.length > 0 && (
              <div className="mt-2 text-xs text-amber-600 dark:text-amber-400">
                Missing: {initStatus.missingComponents.join(", ")}
              </div>
            )}
          </div>
        )}

        {/* Initialize Buttons */}
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => handleInitialize({
              createOuStructure: true,
              createGroups: true,
              setPermissions: true,
              createGpos: true,
            })}
            disabled={isInitializing}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
          >
            {isInitializing ? (
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
            ) : (
              <ShieldCheckIcon className="w-4 h-4" />
            )}
            Initialize All
          </button>
          <button
            onClick={() => handleInitialize({
              createOuStructure: true,
              createGroups: false,
              setPermissions: false,
              createGpos: false,
            })}
            disabled={isInitializing}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-surface-700 rounded-lg hover:bg-gray-200 dark:hover:bg-surface-600 transition-colors disabled:opacity-50"
          >
            OUs Only
          </button>
          <button
            onClick={() => handleInitialize({
              createOuStructure: false,
              createGroups: true,
              setPermissions: false,
              createGpos: false,
            })}
            disabled={isInitializing}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-surface-700 rounded-lg hover:bg-gray-200 dark:hover:bg-surface-600 transition-colors disabled:opacity-50"
          >
            Groups Only
          </button>
          <button
            onClick={() => handleInitialize({
              createOuStructure: false,
              createGroups: false,
              setPermissions: false,
              createGpos: true,
            })}
            disabled={isInitializing}
            className="flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-surface-700 rounded-lg hover:bg-gray-200 dark:hover:bg-surface-600 transition-colors disabled:opacity-50"
          >
            GPOs Only
          </button>
        </div>

        {/* Initialization Result */}
        {initResult && (
          <div className={`mt-4 p-3 rounded-lg ${
            initResult.success
              ? "bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800"
              : "bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800"
          }`}>
            <div className="flex items-center gap-2 mb-2">
              {initResult.success ? (
                <CheckCircleIcon className="w-5 h-5 text-green-600 dark:text-green-400" />
              ) : (
                <XCircleIcon className="w-5 h-5 text-red-600 dark:text-red-400" />
              )}
              <span className={`text-sm font-medium ${
                initResult.success
                  ? "text-green-700 dark:text-green-300"
                  : "text-red-700 dark:text-red-300"
              }`}>
                {initResult.success ? "Initialization Complete" : "Initialization Failed"}
              </span>
            </div>

            {initResult.ousCreated.length > 0 && (
              <div className="text-xs text-gray-600 dark:text-gray-400 mb-1">
                OUs Created: {initResult.ousCreated.length}
              </div>
            )}
            {initResult.groupsCreated.length > 0 && (
              <div className="text-xs text-gray-600 dark:text-gray-400 mb-1">
                Groups Created: {initResult.groupsCreated.length}
              </div>
            )}
            {initResult.gposCreated.length > 0 && (
              <div className="text-xs text-gray-600 dark:text-gray-400 mb-1">
                GPOs Created: {initResult.gposCreated.length}
              </div>
            )}

            {initResult.warnings.length > 0 && (
              <div className="mt-2">
                <div className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400 mb-1">
                  <ExclamationTriangleIcon className="w-3 h-3" />
                  Warnings:
                </div>
                <ul className="text-xs text-amber-700 dark:text-amber-300 list-disc list-inside">
                  {initResult.warnings.map((w, i) => (
                    <li key={i}>{w}</li>
                  ))}
                </ul>
              </div>
            )}

            {initResult.errors.length > 0 && (
              <div className="mt-2">
                <div className="flex items-center gap-1 text-xs text-red-600 dark:text-red-400 mb-1">
                  <XCircleIcon className="w-3 h-3" />
                  Errors:
                </div>
                <ul className="text-xs text-red-700 dark:text-red-300 list-disc list-inside">
                  {initResult.errors.map((e, i) => (
                    <li key={i}>{e}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
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
