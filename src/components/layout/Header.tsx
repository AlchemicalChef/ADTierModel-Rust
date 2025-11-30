import { useTierStore } from "../../store/tierStore";
import {
  ArrowPathIcon,
  ExclamationTriangleIcon,
} from "@heroicons/react/24/outline";

export function Header() {
  const { isConnected, domainInfo, isLoading, error } = useTierStore();

  return (
    <header className="bg-white dark:bg-surface-850 border-b border-gray-200 dark:border-gray-700 px-4 py-3">
      <div className="flex items-center justify-between">
        {/* Logo and Title */}
        <div className="flex items-center gap-3">
          <img
            src="/logo.png"
            alt="AD Tier Model"
            className="w-10 h-10 rounded-lg"
          />
          <div>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              AD Tier Model
            </h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Active Directory Security Tiering
            </p>
          </div>
        </div>

        {/* Connection Status */}
        <div className="flex items-center gap-4">
          {error && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 text-sm">
              <ExclamationTriangleIcon className="w-4 h-4" />
              <span>{error}</span>
            </div>
          )}

          {isLoading && (
            <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-sm">
              <ArrowPathIcon className="w-4 h-4 animate-spin" />
              <span>Loading...</span>
            </div>
          )}

          <div
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm ${
              isConnected
                ? "bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                : "bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400"
            }`}
          >
            <div
              className={`w-2 h-2 rounded-full ${
                isConnected ? "bg-green-500" : "bg-gray-400"
              }`}
            />
            {isConnected && domainInfo ? (
              <span>{domainInfo.netbiosName || domainInfo.dnsRoot}</span>
            ) : (
              <span>Not Connected</span>
            )}
          </div>
        </div>
      </div>
    </header>
  );
}
