import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ServerIcon,
  KeyIcon,
  CloudIcon,
  ShieldCheckIcon,
  CpuChipIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ArrowRightIcon,
  ArrowPathIcon,
  StarIcon,
  ClockIcon,
  IdentificationIcon,
  BoltIcon,
  CogIcon,
} from "@heroicons/react/24/outline";
import { getTier0Infrastructure, moveTier0Component, type Tier0Component } from "../../services/tauri";

function getRoleIcon(roleType: string) {
  switch (roleType) {
    case "DomainController":
      return ServerIcon;
    case "ADFS":
      return KeyIcon;
    case "EntraConnect":
      return CloudIcon;
    case "CertificateAuthority":
      return ShieldCheckIcon;
    case "PAW":
      return CpuChipIcon;
    // FSMO Roles
    case "SchemaMaster":
      return StarIcon;
    case "DomainNamingMaster":
      return IdentificationIcon;
    case "RIDMaster":
      return ClockIcon;
    case "PDCEmulator":
      return BoltIcon;
    case "InfrastructureMaster":
      return CogIcon;
    default:
      return ServerIcon;
  }
}

function getRoleLabel(roleType: string): string {
  switch (roleType) {
    case "DomainController":
      return "Domain Controller";
    case "ADFS":
      return "AD FS";
    case "EntraConnect":
      return "Entra Connect";
    case "CertificateAuthority":
      return "Certificate Authority";
    case "PAW":
      return "PAW";
    // FSMO Roles
    case "SchemaMaster":
      return "Schema Master";
    case "DomainNamingMaster":
      return "Domain Naming Master";
    case "RIDMaster":
      return "RID Master";
    case "PDCEmulator":
      return "PDC Emulator";
    case "InfrastructureMaster":
      return "Infrastructure Master";
    default:
      return roleType;
  }
}

function isFsmoRole(roleType: string): boolean {
  return [
    "SchemaMaster",
    "DomainNamingMaster",
    "RIDMaster",
    "PDCEmulator",
    "InfrastructureMaster",
  ].includes(roleType);
}

interface InfrastructureCardProps {
  component: Tier0Component;
  onRemediate: () => void;
}

function InfrastructureCard({ component, onRemediate }: InfrastructureCardProps) {
  const [isMoving, setIsMoving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const Icon = getRoleIcon(component.roleType);

  const handleMove = async () => {
    if (component.roleType === "DomainController" || isFsmoRole(component.roleType)) {
      setError("Domain Controllers and FSMO role holders should remain in the Domain Controllers OU");
      return;
    }

    setIsMoving(true);
    setError(null);

    try {
      await moveTier0Component(component.distinguishedName, component.roleType);
      onRemediate();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to move component");
    } finally {
      setIsMoving(false);
    }
  };

  const isDCOrFSMO = component.roleType === "DomainController" || isFsmoRole(component.roleType);

  return (
    <div
      className={`bg-white dark:bg-surface-850 rounded-lg border p-4 ${
        component.isInTier0
          ? "border-green-200 dark:border-green-800"
          : "border-amber-200 dark:border-amber-800"
      }`}
    >
      <div className="flex items-start gap-3">
        {/* Icon */}
        <div
          className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
            component.isInTier0
              ? "bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400"
              : "bg-amber-100 dark:bg-amber-900/30 text-amber-600 dark:text-amber-400"
          }`}
        >
          <Icon className="w-5 h-5" />
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {component.name}
            </h4>
            <span
              className={`px-2 py-0.5 text-xs font-medium rounded ${
                component.isInTier0
                  ? "bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                  : "bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
              }`}
            >
              {getRoleLabel(component.roleType)}
            </span>
          </div>

          {component.description && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              {component.description}
            </p>
          )}

          <div className="flex items-center gap-2 mt-2">
            {component.isInTier0 ? (
              <span className="flex items-center gap-1 text-xs text-green-600 dark:text-green-400">
                <CheckCircleIcon className="w-4 h-4" />
                In Tier 0
              </span>
            ) : (
              <span className="flex items-center gap-1 text-xs text-amber-600 dark:text-amber-400">
                <ExclamationTriangleIcon className="w-4 h-4" />
                Not in Tier 0 OU
              </span>
            )}
          </div>

          <p className="text-xs text-gray-400 dark:text-gray-500 mt-1 font-mono truncate">
            {component.currentOu}
          </p>

          {error && (
            <p className="text-xs text-red-600 dark:text-red-400 mt-2">{error}</p>
          )}
        </div>

        {/* Action */}
        {!component.isInTier0 && !isDCOrFSMO && (
          <button
            onClick={handleMove}
            disabled={isMoving}
            className="flex-shrink-0 flex items-center gap-1 px-3 py-1.5 bg-amber-600 text-white text-xs font-medium rounded-lg hover:bg-amber-700 transition-colors disabled:opacity-50"
          >
            {isMoving ? (
              <>
                <ArrowPathIcon className="w-3 h-3 animate-spin" />
                Moving...
              </>
            ) : (
              <>
                <ArrowRightIcon className="w-3 h-3" />
                Move to Tier 0
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}

export function Tier0InfrastructurePanel() {
  const {
    data: infrastructure,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ["tier0Infrastructure"],
    queryFn: getTier0Infrastructure,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-32">
        <ArrowPathIcon className="w-6 h-6 animate-spin text-gray-400" />
      </div>
    );
  }

  if (!infrastructure || infrastructure.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500 dark:text-gray-400">
        No Tier 0 infrastructure components detected.
      </div>
    );
  }

  const inTier0 = infrastructure.filter((c) => c.isInTier0);
  const notInTier0 = infrastructure.filter((c) => !c.isInTier0);

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center">
              <ServerIcon className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {infrastructure.length}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Total Components
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
              <CheckCircleIcon className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {inTier0.length}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                In Tier 0
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-surface-850 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-amber-100 dark:bg-amber-900/30 flex items-center justify-center">
              <ExclamationTriangleIcon className="w-5 h-5 text-amber-600 dark:text-amber-400" />
            </div>
            <div>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                {notInTier0.length}
              </p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Need Remediation
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Misplaced Components */}
      {notInTier0.length > 0 && (
        <section>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-amber-700 dark:text-amber-300 mb-3">
            <ExclamationTriangleIcon className="w-4 h-4" />
            Components Requiring Remediation ({notInTier0.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {notInTier0.map((component) => (
              <InfrastructureCard
                key={component.distinguishedName}
                component={component}
                onRemediate={() => refetch()}
              />
            ))}
          </div>
        </section>
      )}

      {/* Properly Placed Components */}
      {inTier0.length > 0 && (
        <section>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-green-700 dark:text-green-300 mb-3">
            <CheckCircleIcon className="w-4 h-4" />
            Properly Configured ({inTier0.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {inTier0.map((component) => (
              <InfrastructureCard
                key={component.distinguishedName}
                component={component}
                onRemediate={() => refetch()}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
