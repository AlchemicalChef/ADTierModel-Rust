import { useState } from "react";
import { Tab } from "@headlessui/react";
import {
  ShieldCheckIcon,
  ServerIcon,
  ComputerDesktopIcon,
  QuestionMarkCircleIcon,
  ShieldExclamationIcon,
  ClockIcon,
  Cog6ToothIcon,
  HomeIcon,
  FingerPrintIcon,
} from "@heroicons/react/24/outline";
import { useTierStore } from "./store/tierStore";
import { tierConfig } from "./types/tier";
import type { TierLevel } from "./types/tier";
import { Header } from "./components/layout/Header";
import { TierTabPanel } from "./components/tier/TierTabPanel";
import { ComplianceDashboard } from "./components/compliance";
import { AuditLogPanel } from "./components/audit";
import { SettingsPanel } from "./components/settings";
import { DashboardOverview } from "./components/dashboard";
import { EndpointProtectionPanel } from "./components/endpoint-protection";
import { InitializationWizard } from "./components/initialization/InitializationWizard";
import { ToastContainer } from "./components/notifications";
import { useDomainConnection, useTierCounts, useAllTierData, useInitializationStatus, useAutoRefresh } from "./hooks/useTierData";

interface TierTab {
  id: string;
  type: "tier";
  tier: TierLevel | "Unassigned";
  icon: React.ElementType;
}

interface ComplianceTab {
  id: string;
  type: "compliance";
  icon: React.ElementType;
  label: string;
}

interface AuditTab {
  id: string;
  type: "audit";
  icon: React.ElementType;
  label: string;
}

interface SettingsTab {
  id: string;
  type: "settings";
  icon: React.ElementType;
  label: string;
}

interface DashboardTab {
  id: string;
  type: "dashboard";
  icon: React.ElementType;
  label: string;
}

interface EndpointProtectionTab {
  id: string;
  type: "endpoint-protection";
  icon: React.ElementType;
  label: string;
}

type AppTab = TierTab | ComplianceTab | AuditTab | SettingsTab | DashboardTab | EndpointProtectionTab;

const tabs: AppTab[] = [
  { id: "dashboard", type: "dashboard", icon: HomeIcon, label: "Dashboard" },
  { id: "tier0", type: "tier", tier: "Tier0", icon: ShieldCheckIcon },
  { id: "tier1", type: "tier", tier: "Tier1", icon: ServerIcon },
  { id: "tier2", type: "tier", tier: "Tier2", icon: ComputerDesktopIcon },
  { id: "unassigned", type: "tier", tier: "Unassigned", icon: QuestionMarkCircleIcon },
  { id: "endpoint-protection", type: "endpoint-protection", icon: FingerPrintIcon, label: "Endpoint Protection" },
  { id: "compliance", type: "compliance", icon: ShieldExclamationIcon, label: "Compliance" },
  { id: "audit", type: "audit", icon: ClockIcon, label: "Audit Log" },
  { id: "settings", type: "settings", icon: Cog6ToothIcon, label: "Settings" },
];

function App() {
  const { setSelectedTier, tierCounts } = useTierStore();
  const [showWizard, setShowWizard] = useState(true);
  const [wizardSkipped, setWizardSkipped] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("dashboard");

  // Initialize connection and fetch data
  useDomainConnection();
  useTierCounts();
  useAllTierData();
  useAutoRefresh(); // Auto-refresh based on settings

  // Check initialization status
  const { data: initStatus, refetch: refetchInitStatus } = useInitializationStatus();

  // Find the selected index based on activeTab
  const selectedIndex = tabs.findIndex((t) => t.id === activeTab);

  const handleTabChange = (index: number) => {
    const tab = tabs[index];
    setActiveTab(tab.id);
    if (tab.type === "tier") {
      setSelectedTier(tab.tier);
    }
  };

  // Show wizard if not initialized and not skipped
  const shouldShowWizard =
    showWizard && !wizardSkipped && initStatus && !initStatus.isInitialized;

  const handleWizardComplete = () => {
    setShowWizard(false);
    refetchInitStatus();
  };

  const handleWizardSkip = () => {
    setWizardSkipped(true);
    setShowWizard(false);
  };

  return (
    <div className="flex flex-col h-screen bg-gray-50 dark:bg-surface-900 overflow-hidden">
      <Header />
      <main className="flex-1 flex flex-col min-h-0 p-4">
        <Tab.Group
          selectedIndex={selectedIndex >= 0 ? selectedIndex : 0}
          onChange={handleTabChange}
          className="flex flex-col flex-1 min-h-0"
        >
          <Tab.List className="flex space-x-1 rounded-xl bg-white dark:bg-surface-800 p-1 shadow-sm mb-4 flex-shrink-0">
            {tabs.map((tab) => {
              if (tab.type === "dashboard") {
                // Dashboard tab
                return (
                  <Tab
                    key={tab.id}
                    className={({ selected }) =>
                      `flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all outline-none
                       ${
                         selected
                           ? "bg-blue-100 dark:bg-blue-900/50 text-blue-800 dark:text-blue-200 shadow-sm"
                           : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
                       }`
                    }
                  >
                    <tab.icon className="h-5 w-5" />
                    <span className="hidden sm:inline">{tab.label}</span>
                  </Tab>
                );
              } else if (tab.type === "tier") {
                const config = tierConfig[tab.tier];
                const count = tierCounts[tab.tier] || 0;

                return (
                  <Tab
                    key={tab.id}
                    className={({ selected }) =>
                      `flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all outline-none
                       ${
                         selected
                           ? `${config.bgColor} ${config.textColor} shadow-sm`
                           : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
                       }`
                    }
                  >
                    <tab.icon className="h-5 w-5" />
                    <span className="hidden sm:inline">{config.label}</span>
                    <span className="sm:hidden">{config.shortLabel}</span>
                    <span
                      className={`ml-1 rounded-full px-2 py-0.5 text-xs font-semibold ${config.badgeColor}`}
                    >
                      {count}
                    </span>
                  </Tab>
                );
              } else if (tab.type === "endpoint-protection") {
                // Endpoint Protection tab
                return (
                  <Tab
                    key={tab.id}
                    className={({ selected }) =>
                      `flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all outline-none
                       ${
                         selected
                           ? "bg-cyan-100 dark:bg-cyan-900/50 text-cyan-800 dark:text-cyan-200 shadow-sm"
                           : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
                       }`
                    }
                  >
                    <tab.icon className="h-5 w-5" />
                    <span className="hidden sm:inline">{tab.label}</span>
                  </Tab>
                );
              } else if (tab.type === "compliance") {
                // Compliance tab
                return (
                  <Tab
                    key={tab.id}
                    className={({ selected }) =>
                      `flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all outline-none ml-auto
                       ${
                         selected
                           ? "bg-purple-100 dark:bg-purple-900/50 text-purple-800 dark:text-purple-200 shadow-sm"
                           : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
                       }`
                    }
                  >
                    <tab.icon className="h-5 w-5" />
                    <span className="hidden sm:inline">{tab.label}</span>
                  </Tab>
                );
              } else if (tab.type === "audit") {
                // Audit tab
                return (
                  <Tab
                    key={tab.id}
                    className={({ selected }) =>
                      `flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all outline-none
                       ${
                         selected
                           ? "bg-indigo-100 dark:bg-indigo-900/50 text-indigo-800 dark:text-indigo-200 shadow-sm"
                           : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
                       }`
                    }
                  >
                    <tab.icon className="h-5 w-5" />
                    <span className="hidden sm:inline">{tab.label}</span>
                  </Tab>
                );
              } else {
                // Settings tab
                return (
                  <Tab
                    key={tab.id}
                    className={({ selected }) =>
                      `flex items-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all outline-none
                       ${
                         selected
                           ? "bg-gray-200 dark:bg-surface-700 text-gray-800 dark:text-gray-200 shadow-sm"
                           : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-surface-700"
                       }`
                    }
                  >
                    <tab.icon className="h-5 w-5" />
                    <span className="hidden sm:inline">{tab.label}</span>
                  </Tab>
                );
              }
            })}
          </Tab.List>

          <Tab.Panels className="flex-1 overflow-y-auto min-h-0">
            {tabs.map((tab) => (
              <Tab.Panel key={tab.id} className="pb-6">
                {tab.type === "dashboard" ? (
                  <DashboardOverview
                    onNavigateToTier={(tier) => {
                      const tierTabId = tier === "Tier0" ? "tier0" : tier === "Tier1" ? "tier1" : tier === "Tier2" ? "tier2" : "unassigned";
                      setActiveTab(tierTabId);
                      setSelectedTier(tier);
                    }}
                    onNavigateToCompliance={() => setActiveTab("compliance")}
                  />
                ) : tab.type === "tier" ? (
                  <TierTabPanel tier={tab.tier} />
                ) : tab.type === "endpoint-protection" ? (
                  <EndpointProtectionPanel />
                ) : tab.type === "compliance" ? (
                  <ComplianceDashboard />
                ) : tab.type === "audit" ? (
                  <AuditLogPanel />
                ) : (
                  <SettingsPanel />
                )}
              </Tab.Panel>
            ))}
          </Tab.Panels>
        </Tab.Group>
      </main>

      {/* Initialization Wizard */}
      {shouldShowWizard && (
        <InitializationWizard
          onComplete={handleWizardComplete}
          onSkip={handleWizardSkip}
        />
      )}

      {/* Toast Notifications */}
      <ToastContainer />
    </div>
  );
}

export default App;
