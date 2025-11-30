// Endpoint protection GPO types

export type EndpointGpoType =
  | "AuditBaseline"
  | "AuditEnhanced"
  | "DcAuditEssential"
  | "DcAuditComprehensive"
  | "DefenderProtection";

export type EndpointGpoCategory = "audit" | "dc-audit" | "defender";

export type EndpointGpoLinkScope = "per-tier" | "dc-only" | "domain-wide";

// Status of a tier's link for per-tier GPOs
export interface TierLinkStatus {
  tier: string;
  linked: boolean;
  linkEnabled: boolean;
}

// Status of an endpoint protection GPO
export interface EndpointGpoStatus {
  gpoType: string;
  name: string;
  description: string;
  exists: boolean;
  linked: boolean;
  linkTarget: string;
  linkScope: string;
  created: string | null;
  modified: string | null;
  tierStatus: TierLinkStatus[] | null;
}

// Result from endpoint GPO configuration
export interface EndpointGpoConfigResult {
  success: boolean;
  gpoType: string;
  gpoName: string;
  created: boolean;
  linked: boolean;
  configured: boolean;
  errors: string[];
  warnings: string[];
}

// GPO configuration metadata
export interface EndpointGpoConfig {
  type: EndpointGpoType;
  name: string;
  description: string;
  category: EndpointGpoCategory;
  linkScope: EndpointGpoLinkScope;
  features: string[];
}

// Configuration metadata for all endpoint protection GPOs
export const ENDPOINT_GPO_CONFIGS: EndpointGpoConfig[] = [
  {
    type: "AuditBaseline",
    name: "SEC-Audit-Baseline",
    description: "Microsoft recommended baseline audit policies",
    category: "audit",
    linkScope: "per-tier",
    features: [
      "Account Logon: Success/Failure",
      "Account Management: Success/Failure",
      "Logon/Logoff: Success/Failure",
      "Object Access: Failure",
      "Policy Change: Success/Failure",
      "Privilege Use: Failure",
      "System: Success/Failure",
    ],
  },
  {
    type: "AuditEnhanced",
    name: "SEC-Audit-Enhanced",
    description: "ACSC/NSA hardened audit policies with PowerShell logging",
    category: "audit",
    linkScope: "per-tier",
    features: [
      "All Baseline settings",
      "Process Creation with Command Line",
      "PowerShell Script Block Logging",
      "PowerShell Module Logging",
      "PowerShell Transcription",
      "Detailed File Share Access",
      "Registry Auditing",
      "Removable Storage",
      "DPAPI Activity",
    ],
  },
  {
    type: "DcAuditEssential",
    name: "SEC-DC-Audit-Essential",
    description: "Essential security audit policies for Domain Controllers",
    category: "dc-audit",
    linkScope: "dc-only",
    features: [
      "Directory Service Access",
      "Directory Service Changes",
      "Directory Service Replication",
      "Kerberos Account Logon",
      "Credential Validation",
      "Security Group Management",
      "User Account Management",
    ],
  },
  {
    type: "DcAuditComprehensive",
    name: "SEC-DC-Audit-Comprehensive",
    description: "Comprehensive forensic audit policies for Domain Controllers",
    category: "dc-audit",
    linkScope: "dc-only",
    features: [
      "All Essential settings",
      "Kerberos Authentication Service",
      "Kerberos Service Ticket Operations",
      "LDAP Interface Events",
      "Detailed Replication",
      "SAM Operations",
      "Process Creation with Command Line",
      "Certification Services",
    ],
  },
  {
    type: "DefenderProtection",
    name: "SEC-Defender-Protection",
    description: "Microsoft Defender Antivirus balanced protection settings",
    category: "defender",
    linkScope: "domain-wide",
    features: [
      "Real-time Protection",
      "Cloud-delivered Protection",
      "Automatic Sample Submission",
      "PUA Protection (Block)",
      "Behavior Monitoring",
      "Email Scanning",
      "Removable Drive Scanning",
      "Archive Scanning",
    ],
  },
];

// Get config by type
export function getEndpointGpoConfig(type: EndpointGpoType): EndpointGpoConfig | undefined {
  return ENDPOINT_GPO_CONFIGS.find((c) => c.type === type);
}

// Get configs by category
export function getEndpointGposByCategory(category: EndpointGpoCategory): EndpointGpoConfig[] {
  return ENDPOINT_GPO_CONFIGS.filter((c) => c.category === category);
}
