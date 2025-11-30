// Tier levels matching the PowerShell module
export type TierLevel = "Tier0" | "Tier1" | "Tier2";

// Object types in Active Directory
export type ObjectType =
  | "User"
  | "Computer"
  | "AdminWorkstation"
  | "Group"
  | "ServiceAccount";

// Tier 0 infrastructure role types
export type Tier0RoleType =
  | "DomainController"
  | "ADFS"
  | "EntraConnect"
  | "CertificateAuthority"
  | "PAW";

// Risk levels for compliance
export type RiskLevel = "Critical" | "High" | "Medium" | "Low";

// A member of a tier (user, computer, group, etc.)
export interface TierMember {
  name: string;
  samAccountName: string;
  objectType: ObjectType;
  tier: TierLevel | null;
  enabled: boolean;
  lastLogon: string | null;
  distinguishedName: string;
  description: string | null;
  // Computer-specific
  operatingSystem: string | null;
  // Tier 0 specific
  roleType: Tier0RoleType | null;
  // Group-specific
  memberCount: number | null;
}

// Tier configuration
export interface TierConfiguration {
  name: string;
  description: string;
  ouPath: string;
  color: string;
  riskLevel: RiskLevel;
}

// Tier counts for display
export interface TierCounts {
  Tier0: number;
  Tier1: number;
  Tier2: number;
  Unassigned: number;
}

// Domain info from AD connection
export interface DomainInfo {
  domainDn: string;
  dnsRoot: string;
  netbiosName: string;
  connected: boolean;
}

// Tier display configuration
// Initialization options
export interface InitializationOptions {
  createOuStructure: boolean;
  createGroups: boolean;
  setPermissions: boolean;
  createGpos: boolean;
  force: boolean;
}

// Initialization result
export interface InitializationResult {
  success: boolean;
  ousCreated: string[];
  groupsCreated: string[];
  permissionsSet: string[];
  gposCreated: string[];
  errors: string[];
  warnings: string[];
}

// Initialization status check
export interface InitializationStatus {
  isInitialized: boolean;
  tier0OuExists: boolean;
  tier1OuExists: boolean;
  tier2OuExists: boolean;
  groupsExist: boolean;
  missingComponents: string[];
}

export const tierConfig: Record<
  TierLevel | "Unassigned",
  {
    label: string;
    shortLabel: string;
    description: string;
    bgColor: string;
    borderColor: string;
    textColor: string;
    badgeColor: string;
    iconColor: string;
    barColor: string;
    riskLevel: RiskLevel | "Unknown";
  }
> = {
  Tier0: {
    label: "Tier 0 - Infrastructure",
    shortLabel: "T0",
    description: "Domain Controllers, ADFS, Entra Connect, CAs, PAWs",
    bgColor: "bg-tier0-light dark:bg-tier0-dark/20",
    borderColor: "border-tier0-border dark:border-tier0-dark",
    textColor: "text-tier0-text dark:text-red-400",
    badgeColor: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
    iconColor: "text-red-600 dark:text-red-400",
    barColor: "bg-red-500",
    riskLevel: "Critical",
  },
  Tier1: {
    label: "Tier 1 - Servers",
    shortLabel: "T1",
    description: "Application servers, database servers, file servers",
    bgColor: "bg-tier1-light dark:bg-tier1-dark/20",
    borderColor: "border-tier1-border dark:border-tier1-dark",
    textColor: "text-tier1-text dark:text-amber-400",
    badgeColor:
      "bg-amber-100 text-amber-800 dark:bg-amber-900/50 dark:text-amber-200",
    iconColor: "text-amber-600 dark:text-amber-400",
    barColor: "bg-amber-500",
    riskLevel: "High",
  },
  Tier2: {
    label: "Tier 2 - Workstations",
    shortLabel: "T2",
    description: "User workstations and endpoints",
    bgColor: "bg-tier2-light dark:bg-tier2-dark/20",
    borderColor: "border-tier2-border dark:border-tier2-dark",
    textColor: "text-tier2-text dark:text-green-400",
    badgeColor:
      "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200",
    iconColor: "text-green-600 dark:text-green-400",
    barColor: "bg-green-500",
    riskLevel: "Medium",
  },
  Unassigned: {
    label: "Unassigned",
    shortLabel: "UA",
    description: "Objects not in any tier OU",
    bgColor: "bg-gray-100 dark:bg-gray-800/50",
    borderColor: "border-gray-300 dark:border-gray-600",
    textColor: "text-gray-600 dark:text-gray-400",
    badgeColor: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300",
    iconColor: "text-gray-500 dark:text-gray-400",
    barColor: "bg-gray-400",
    riskLevel: "Unknown",
  },
};
