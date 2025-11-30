import { invoke } from "@tauri-apps/api/core";
import type {
  TierLevel,
  TierMember,
  TierCounts,
  DomainInfo,
  InitializationOptions,
  InitializationResult,
  InitializationStatus
} from "../../types/tier";

// Error type from Tauri commands
export interface CommandError {
  code: string;
  message: string;
}

// Generic wrapper for Tauri commands
async function tauriCommand<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args);
  } catch (error) {
    console.error(`Tauri command failed: ${command}`, error);
    throw error;
  }
}

// Domain connection
export async function getDomainInfo(): Promise<DomainInfo> {
  return tauriCommand("get_domain_info");
}

// Tier counts
export async function getTierCounts(): Promise<TierCounts> {
  return tauriCommand("get_tier_counts");
}

// Get tier members
export async function getTierMembers(tierName: TierLevel | "Unassigned"): Promise<TierMember[]> {
  return tauriCommand("get_tier_members", { tierName });
}

// Get Tier 0 infrastructure
export interface Tier0Component {
  name: string;
  roleType: "DomainController" | "ADFS" | "EntraConnect" | "CertificateAuthority" | "PAW";
  operatingSystem: string | null;
  lastLogon: string | null;
  currentOu: string;
  isInTier0: boolean;
  distinguishedName: string;
  description: string | null;
}

export async function getTier0Infrastructure(): Promise<Tier0Component[]> {
  return tauriCommand("get_tier0_infrastructure");
}

// Initialization commands
export async function checkTierInitialization(): Promise<InitializationStatus> {
  return tauriCommand("check_tier_initialization");
}

export async function initializeAdTierModel(options: InitializationOptions): Promise<InitializationResult> {
  return tauriCommand("initialize_ad_tier_model", { options });
}

export async function getExpectedOuStructure(): Promise<string[]> {
  return tauriCommand("get_expected_ou_structure");
}

export async function getExpectedGroups(): Promise<string[]> {
  return tauriCommand("get_expected_groups");
}

// Connection management
export async function reconnectAd(): Promise<DomainInfo> {
  return tauriCommand("reconnect_ad");
}

// Write operations - Move objects
export type SubOUType = "Users" | "Computers" | "Groups" | "ServiceAccounts" | "AdminWorkstations";

export async function moveObjectToTier(
  objectDn: string,
  targetTier: TierLevel,
  subOu?: SubOUType
): Promise<string> {
  return tauriCommand("move_object_to_tier", { objectDn, targetTier, subOu });
}

export async function moveTier0Component(
  objectDn: string,
  roleType: string
): Promise<string> {
  return tauriCommand("move_tier0_component", { objectDn, roleType });
}

// Write operations - Group membership
export type GroupSuffix = "Admins" | "Operators" | "Readers" | "ServiceAccounts" | "JumpServers";

export async function addToTierGroup(
  memberDn: string,
  tierName: TierLevel,
  groupSuffix: GroupSuffix
): Promise<void> {
  return tauriCommand("add_to_tier_group", { memberDn, tierName, groupSuffix });
}

export async function removeFromTierGroup(
  memberDn: string,
  tierName: TierLevel,
  groupSuffix: GroupSuffix
): Promise<void> {
  return tauriCommand("remove_from_tier_group", { memberDn, tierName, groupSuffix });
}

// Compliance types
export type ViolationType =
  | "crossTierAccess"
  | "misplacedTier0Infrastructure"
  | "wrongTierPlacement"
  | "missingGroupMembership"
  | "staleAccount"
  | "serviceAccountInteractiveLogon";

export type ViolationSeverity = "critical" | "high" | "medium" | "low";

export interface ComplianceViolation {
  violationType: ViolationType;
  severity: ViolationSeverity;
  objectName: string;
  objectDn: string;
  samAccountName: string;
  description: string;
  tiersInvolved: TierLevel[];
  remediation: string;
}

export interface CrossTierAccess {
  accountName: string;
  accountDn: string;
  tiers: TierLevel[];
  groups: string[];
}

export interface ComplianceStatus {
  score: number;
  totalViolations: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  violations: ComplianceViolation[];
  crossTierAccess: CrossTierAccess[];
  lastChecked: string;
}

// Compliance commands
export async function getComplianceStatus(): Promise<ComplianceStatus> {
  return tauriCommand("get_compliance_status");
}

export async function getCrossTierViolations(): Promise<CrossTierAccess[]> {
  return tauriCommand("get_cross_tier_violations");
}

// Group membership types
export interface GroupMembership {
  groupName: string;
  groupDn: string;
  tier: string | null;
  groupType: string;
}

// Get group memberships for an object
export async function getObjectGroups(objectDn: string): Promise<GroupMembership[]> {
  return tauriCommand("get_object_groups", { objectDn });
}

// Admin account creation types
export interface CreateAdminAccountOptions {
  baseUsername: string;
  displayName: string;
  targetTier: TierLevel;
  accountType: "admin" | "service";
  description?: string;
  password: string;
  groups: GroupSuffix[];
  enabled: boolean;
}

export interface CreateAdminAccountResult {
  success: boolean;
  accountDn: string | null;
  samAccountName: string;
  groupsAdded: string[];
  warnings: string[];
  error: string | null;
}

// Create a new tiered admin account
export async function createAdminAccount(
  options: CreateAdminAccountOptions
): Promise<CreateAdminAccountResult> {
  return tauriCommand("create_admin_account", { options });
}

// GPO Management types
export interface GpoStatus {
  exists: boolean;
  name: string;
  linked: boolean;
  linkPath: string | null;
}

export interface TierGpoStatus {
  tier: string;
  basePolicy: GpoStatus;
  logonRestrictions: GpoStatus;
  restrictionsConfigured: boolean;
  denyLocalLogon: string[];
  denyRdpLogon: string[];
  denyNetworkLogon: string[];
}

export interface GpoConfigResult {
  success: boolean;
  gposCreated: string[];
  gposLinked: string[];
  restrictionsApplied: boolean;
  errors: string[];
}

// GPO Management commands
export async function getGpoStatus(): Promise<TierGpoStatus[]> {
  return tauriCommand("get_gpo_status");
}

export async function configureTierGpo(tierName: TierLevel): Promise<GpoConfigResult> {
  return tauriCommand("configure_tier_gpo", { tierName });
}

export async function configureAllGpos(): Promise<GpoConfigResult> {
  return tauriCommand("configure_all_gpos");
}

export async function deleteTierGpo(tierName: TierLevel): Promise<string[]> {
  return tauriCommand("delete_tier_gpo", { tierName });
}

// Account Management types
export interface BulkDisableResult {
  successCount: number;
  failureCount: number;
  disabledAccounts: string[];
  errors: string[];
}

// Bulk disable stale accounts
export async function bulkDisableStaleAccounts(objectDns: string[]): Promise<BulkDisableResult> {
  return tauriCommand("bulk_disable_stale_accounts", { objectDns });
}

// Service account hardening types
export interface HardenAccountsResult {
  successCount: number;
  failureCount: number;
  hardenedAccounts: string[];
  errors: string[];
}

// Harden service accounts (mark as sensitive, cannot be delegated)
export async function hardenServiceAccounts(objectDns: string[]): Promise<HardenAccountsResult> {
  return tauriCommand("harden_service_accounts", { objectDns });
}

// Endpoint Protection GPO types
export interface TierLinkStatus {
  tier: string;
  linked: boolean;
  linkEnabled: boolean;
}

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

// Endpoint Protection GPO commands
export async function getEndpointProtectionStatus(): Promise<EndpointGpoStatus[]> {
  return tauriCommand("get_endpoint_protection_status");
}

export async function configureEndpointGpo(
  gpoType: string,
  tier?: TierLevel
): Promise<EndpointGpoConfigResult> {
  return tauriCommand("configure_endpoint_gpo", { gpoType, tier });
}

export async function configureAllEndpointGpos(): Promise<EndpointGpoConfigResult[]> {
  return tauriCommand("configure_all_endpoint_gpos");
}

export async function deleteEndpointGpo(
  gpoType: string,
  tier?: TierLevel
): Promise<void> {
  return tauriCommand("delete_endpoint_gpo_cmd", { gpoType, tier });
}

// AD Diagnostics types
export interface TierOuStatus {
  tier: string;
  ou_path: string;
  exists: boolean;
  object_count: number;
  error: string | null;
}

export interface AdDiagnostics {
  domain_dn: string;
  com_init_status: string;
  ldap_bind_status: string;
  ldap_search_status: string;
  objects_found: number;
  error_code: string | null;
  error_message: string | null;
  steps_completed: string[];
  tier_ou_status: TierOuStatus[];
}

// Diagnose AD connection - returns detailed diagnostic info for debugging
export async function diagnoseAdConnection(): Promise<AdDiagnostics> {
  return tauriCommand("diagnose_ad_connection");
}
