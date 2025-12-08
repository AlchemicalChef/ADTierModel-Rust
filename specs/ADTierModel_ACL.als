/*
 * ADTierModel_ACL.als - Alloy Formal Specification for AD ACL/Permission Modeling
 *
 * This specification models Active Directory access control lists and permission
 * structures to detect privilege escalation attack paths across the tiered
 * administrative model.
 *
 * Complements the TLA+ model (ADTierModel.tla) which handles:
 * - Temporal state transitions
 * - Credential/session tracking
 * - Operational behavior
 *
 * This Alloy model handles:
 * - Structural ACL analysis
 * - Attack path discovery (BloodHound-style)
 * - Permission chain verification
 * - AdminSDHolder/SDProp analysis
 *
 * Usage:
 *   - Open in Alloy Analyzer 6.x
 *   - Run "check" commands to verify security properties
 *   - Run "run" commands to visualize attack paths
 *
 * Version: 1.1 - Fixed syntax errors, logical issues, and hallucinations
 * Matches Rust enums in: src-tauri/src/infrastructure/ad_write.rs
 */

module ADTierModel_ACL

// ============================================================================
// PART 1: Core AD Objects and Type Hierarchy
// ============================================================================

// Boolean type for Alloy
abstract sig Bool {}
one sig True, False extends Bool {}

// Abstract base for all AD objects (everything in AD has a security descriptor)
abstract sig ADObject {
    tier: one Tier,
    owner: one ADObject,              // Owner is another AD object (principal)
    securityDescriptor: one SecurityDescriptor,
    parent: lone Container            // OU or domain containing this object
}

// Abstract base for security principals (can be granted permissions)
abstract sig Principal extends ADObject {
    enabled: one Bool
}

// User accounts
sig User extends Principal {
    primaryGroup: one Group,
    memberOf: set Group,
    isServiceAccount: one Bool,
    isSensitive: one Bool             // NOT_DELEGATED flag (AccountNotDelegated)
}

// Computer accounts
sig Computer extends Principal {
    primaryGroup: one Group,
    memberOfC: set Group              // Computers have separate membership relation
}

// Security groups
sig Group extends Principal {
    members: set Principal,           // Direct members only (users, computers, groups)
    nestedGroups: set Group           // Groups that are direct members of this group
}

// Container objects (can hold other objects)
abstract sig Container extends ADObject {
    children: set ADObject
}

sig OrganizationalUnit extends Container {}
sig Domain extends Container {}

// ============================================================================
// PART 2: Tier Model (matches existing Rust/TLA+ model)
// ============================================================================

abstract sig Tier {}
one sig Tier0, Tier1, Tier2, Unassigned extends Tier {}

// Tier ordering for privilege escalation analysis
// Lower number = higher privilege
fun tierLevel[t: Tier]: one Int {
    (t = Tier0) => 0 else (
    (t = Tier1) => 1 else (
    (t = Tier2) => 2 else 3))
}

// Check if t1 is higher privilege than t2 (lower tier number)
pred higherPrivilege[t1, t2: Tier] {
    tierLevel[t1] < tierLevel[t2]
}

// Check if t1 is same or higher privilege than t2
pred sameOrHigherPrivilege[t1, t2: Tier] {
    tierLevel[t1] <= tierLevel[t2]
}

// ============================================================================
// PART 3: Permission Rights (matches Rust AdRights enum + extensions)
// ============================================================================

abstract sig Right {}

// Standard rights from Windows AD (matches Rust AdRights enum)
one sig GenericAll extends Right {}      // 0x10000000 - Full control
one sig GenericRead extends Right {}     // 0x80000000 - Read all properties
one sig GenericWrite extends Right {}    // 0x40000000 - Write all properties
one sig Delete extends Right {}          // 0x10000 - Delete the object
one sig ReadControl extends Right {}     // 0x20000 - Read security descriptor
one sig WriteDacl extends Right {}       // 0x40000 - Modify the DACL
one sig WriteOwner extends Right {}      // 0x80000 - Take ownership
one sig CreateChild extends Right {}     // 0x1 - Create child objects
one sig DeleteChild extends Right {}     // 0x2 - Delete child objects

// Additional rights for attack path analysis
one sig WriteProperty extends Right {}   // Write specific properties
one sig ReadProperty extends Right {}    // Read specific properties
one sig Self_ extends Right {}           // Self-write (validated writes)
one sig ExtendedRight extends Right {}   // Extended rights (GUIDs)

// AD Properties that are security-sensitive
abstract sig Property {}
one sig MemberProperty extends Property {}                          // Group membership
one sig ServicePrincipalNameProperty extends Property {}            // SPN (Kerberoasting)
one sig MsDS_AllowedToActOnBehalfProperty extends Property {}       // RBCD
one sig MsDS_AllowedToDelegateTo extends Property {}                // Constrained delegation
one sig UserPasswordProperty extends Property {}                    // Password
one sig AdminCountProperty extends Property {}                      // Protected user marker
one sig GpLinkProperty extends Property {}                          // GPO linking
one sig UserAccountControlProperty extends Property {}              // UAC flags

// Extended rights GUIDs (critical for attack paths)
abstract sig ExtendedRightGUID {}
one sig UserForceChangePassword extends ExtendedRightGUID {}        // Reset password (00299570-246d-11d0-a768-00aa006e0529)
one sig DS_Replication_Get_Changes extends ExtendedRightGUID {}     // DCSync (part 1)
one sig DS_Replication_Get_Changes_All extends ExtendedRightGUID {} // DCSync (part 2)
one sig WriteMember extends ExtendedRightGUID {}                    // Write member attribute on groups

// ============================================================================
// PART 4: ACL Structure
// ============================================================================

// Security Descriptor - the main security container for each object
sig SecurityDescriptor {
    sdOwner: one Principal,
    dacl: one DACL,
    sacl: lone SACL                  // System ACL (auditing) - optional
}

// Discretionary Access Control List - controls access permissions
sig DACL {
    aces: set ACE
}

// System Access Control List - for auditing (not used for access control)
sig SACL {
    auditAces: set ACE
}

// Access Control Entry - individual permission grant or denial
sig ACE {
    trustee: one Principal,          // Who the permission applies to
    rights: set Right,               // What rights are granted/denied
    aceType: one ACEType,            // Allow or Deny
    inheritance: one InheritanceFlags,
    objectType: lone ExtendedRightGUID,      // For object-specific ACEs
    inheritedObjectType: lone ObjectClass,   // Limit inheritance to specific object types
    targetProperty: lone Property            // For property-specific ACEs
}

// ACE Types (matches Rust AceType enum)
abstract sig ACEType {}
one sig Allow, Deny extends ACEType {}

// Inheritance Flags (matches Rust AceFlags enum)
abstract sig InheritanceFlags {}
one sig NoInheritance extends InheritanceFlags {}      // 0x0
one sig InheritChildren extends InheritanceFlags {}    // 0x2
one sig InheritAll extends InheritanceFlags {}         // 0x3

// Object classes for inheritance filtering
abstract sig ObjectClass {}
one sig UserClass, ComputerClass, GroupClass, OUClass extends ObjectClass {}

// ============================================================================
// PART 5: AdminSDHolder and Protected Objects
// ============================================================================

// AdminSDHolder is a special container whose ACL is copied to protected objects
one sig AdminSDHolder {
    protectedACL: one DACL
}

// Protected groups - well-known security groups protected by SDProp
// Reference: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
abstract sig ProtectedGroup extends Group {}

// Well-known protected groups in Active Directory (verified list)
sig DomainAdmins extends ProtectedGroup {}
sig EnterpriseAdmins extends ProtectedGroup {}
sig SchemaAdmins extends ProtectedGroup {}
sig Administrators extends ProtectedGroup {}
sig AccountOperators extends ProtectedGroup {}
sig BackupOperators extends ProtectedGroup {}
sig PrintOperators extends ProtectedGroup {}
sig ServerOperators extends ProtectedGroup {}
sig Replicators extends ProtectedGroup {}
// Note: Domain Controllers group members (computer accounts) are protected
// KeyAdmins and EnterpriseKeyAdmins are protected in Server 2016+
sig KeyAdmins extends ProtectedGroup {}
sig EnterpriseKeyAdmins extends ProtectedGroup {}

// The Domain Controllers group (contains DC computer accounts)
sig DomainControllersGroup extends ProtectedGroup {}

// Check if a principal is protected (member of protected group or the group itself)
pred isProtectedPrincipal[p: Principal] {
    p in ProtectedGroup or
    some pg: ProtectedGroup | p in allMembers[pg]
}

// ============================================================================
// PART 6: Transitive Group Membership (LDAP_MATCHING_RULE_IN_CHAIN equivalent)
// ============================================================================

// Get all groups a user is a member of (direct + nested + primary)
fun allGroupsUser[u: User]: set Group {
    u.primaryGroup + u.memberOf + u.memberOf.^nestedGroups
}

// Get all groups a computer is a member of
fun allGroupsComputer[c: Computer]: set Group {
    c.primaryGroup + c.memberOfC + c.memberOfC.^nestedGroups
}

// Get all groups a group is nested in
fun allGroupsGroup[g: Group]: set Group {
    g.^nestedGroups
}

// Generic: get all groups for any principal
fun allGroups[p: Principal]: set Group {
    (p in User) => allGroupsUser[p] else (
    (p in Computer) => allGroupsComputer[p] else (
    (p in Group) => allGroupsGroup[p] else none))
}

// Get all effective members of a group (transitive)
// Note: ^nestedGroups already includes nestedGroups (transitive closure includes first hop)
fun allMembers[g: Group]: set Principal {
    g.members + g.^nestedGroups.members
}

// Check if principal is member of group (directly or transitively)
pred isMemberOf[p: Principal, g: Group] {
    g in allGroups[p]
}

// ============================================================================
// PART 7: Effective Permissions Calculation
// ============================================================================

// Get the DACL for a principal (via their security descriptor)
fun getDACL[p: Principal]: one DACL {
    p.securityDescriptor.dacl
}

// Get all ACEs that could apply to a principal (attacker) on a target's DACL
fun applicableACEs[attacker: Principal, targetDacl: DACL]: set ACE {
    let groups = allGroups[attacker] |
    { ace: targetDacl.aces |
        ace.trustee = attacker or ace.trustee in groups
    }
}

// Check if a specific right is granted (Deny takes precedence over Allow)
pred hasRight[attacker: Principal, targetDacl: DACL, r: Right] {
    // An Allow ACE exists for this right
    some ace: applicableACEs[attacker, targetDacl] |
        ace.aceType = Allow and r in ace.rights
    // AND no Deny ACE blocks it
    no ace: applicableACEs[attacker, targetDacl] |
        ace.aceType = Deny and r in ace.rights
}

// Check if principal has an extended right on target
pred hasExtendedRight[attacker: Principal, targetDacl: DACL, guid: ExtendedRightGUID] {
    some ace: applicableACEs[attacker, targetDacl] |
        ace.aceType = Allow and
        ExtendedRight in ace.rights and
        ace.objectType = guid
    no ace: applicableACEs[attacker, targetDacl] |
        ace.aceType = Deny and
        ExtendedRight in ace.rights and
        ace.objectType = guid
}

// Check if principal can write a specific property on target
pred hasPropertyWriteRight[attacker: Principal, targetDacl: DACL, prop: Property] {
    // GenericWrite or GenericAll grants all property writes
    hasRight[attacker, targetDacl, GenericWrite] or
    hasRight[attacker, targetDacl, GenericAll] or
    // Or specific WriteProperty for this property
    (some ace: applicableACEs[attacker, targetDacl] |
        ace.aceType = Allow and
        WriteProperty in ace.rights and
        ace.targetProperty = prop)
}

// Check for GenericAll or equivalent full control
pred hasFullControl[attacker: Principal, targetDacl: DACL] {
    hasRight[attacker, targetDacl, GenericAll]
}

// ============================================================================
// PART 8: Dangerous Permission Patterns (Attack Paths)
// ============================================================================

// --- WriteDACL Abuse ---
// WriteDACL allows granting self any permission including GenericAll
pred canModifyDACL[attacker: Principal, target: Principal] {
    let targetDacl = getDACL[target] |
    hasRight[attacker, targetDacl, WriteDacl] or
    hasFullControl[attacker, targetDacl]
}

// --- WriteOwner Abuse ---
// WriteOwner allows taking ownership, then the owner can modify DACL
pred canTakeOwnership[attacker: Principal, target: Principal] {
    let targetDacl = getDACL[target] |
    hasRight[attacker, targetDacl, WriteOwner] or
    hasFullControl[attacker, targetDacl]
}

// --- Group Membership Modification ---
// Can add self or others to a group
pred canModifyGroupMembership[attacker: Principal, g: Group] {
    let gDacl = getDACL[g] |
    hasFullControl[attacker, gDacl] or
    hasRight[attacker, gDacl, GenericWrite] or
    hasPropertyWriteRight[attacker, gDacl, MemberProperty] or
    hasExtendedRight[attacker, gDacl, WriteMember]
}

// --- SPN Manipulation (Kerberoasting Setup) ---
// Can set SPN on a user to make them Kerberoastable
pred canSetSPN[attacker: Principal, target: User] {
    let targetDacl = getDACL[target] |
    hasFullControl[attacker, targetDacl] or
    hasRight[attacker, targetDacl, GenericWrite] or
    hasPropertyWriteRight[attacker, targetDacl, ServicePrincipalNameProperty]
}

// --- Resource-Based Constrained Delegation (RBCD) ---
// Can configure msDS-AllowedToActOnBehalfOfOtherIdentity
pred canConfigureRBCD[attacker: Principal, target: Computer] {
    let targetDacl = getDACL[target] |
    hasFullControl[attacker, targetDacl] or
    hasRight[attacker, targetDacl, GenericWrite] or
    hasPropertyWriteRight[attacker, targetDacl, MsDS_AllowedToActOnBehalfProperty]
}

// --- Password Reset ---
// Can force password change on target user
pred canForcePasswordChange[attacker: Principal, target: User] {
    let targetDacl = getDACL[target] |
    hasFullControl[attacker, targetDacl] or
    hasExtendedRight[attacker, targetDacl, UserForceChangePassword]
}

// --- DCSync Rights ---
// Has both replication rights needed for DCSync attack on a domain
pred hasDCSyncRights[attacker: Principal, d: Domain] {
    let domainDacl = d.securityDescriptor.dacl |
    hasFullControl[attacker, domainDacl] or
    (hasExtendedRight[attacker, domainDacl, DS_Replication_Get_Changes] and
     hasExtendedRight[attacker, domainDacl, DS_Replication_Get_Changes_All])
}

// --- Shadow Credentials ---
// Can write msDS-KeyCredentialLink for shadow credentials attack
pred canWriteKeyCredentials[attacker: Principal, target: Principal] {
    let targetDacl = getDACL[target] |
    hasFullControl[attacker, targetDacl] or
    hasRight[attacker, targetDacl, GenericWrite]
}

// --- Constrained Delegation Abuse ---
// Can modify delegation settings
pred canModifyDelegation[attacker: Principal, target: Principal] {
    let targetDacl = getDACL[target] |
    hasFullControl[attacker, targetDacl] or
    hasRight[attacker, targetDacl, GenericWrite] or
    hasPropertyWriteRight[attacker, targetDacl, MsDS_AllowedToDelegateTo] or
    hasPropertyWriteRight[attacker, targetDacl, UserAccountControlProperty]
}

// ============================================================================
// PART 9: Attack Path Analysis - canCompromise Relation
// ============================================================================

// Direct compromise through explicit admin rights (GenericAll)
pred directCompromise[attacker: Principal, target: Principal] {
    hasFullControl[attacker, getDACL[target]]
}

// Compromise through WriteDACL chain
// Attacker can modify DACL to grant themselves GenericAll
pred writeDACLCompromise[attacker: Principal, target: Principal] {
    canModifyDACL[attacker, target]
}

// Compromise through WriteOwner chain
// Attacker can take ownership, then modify DACL
pred writeOwnerCompromise[attacker: Principal, target: Principal] {
    canTakeOwnership[attacker, target]
}

// Compromise through password reset (users only)
pred passwordResetCompromise[attacker: Principal, target: User] {
    canForcePasswordChange[attacker, target]
}

// Single-hop canCompromise relation for any principal
pred canCompromise[attacker: Principal, target: Principal] {
    directCompromise[attacker, target] or
    writeDACLCompromise[attacker, target] or
    writeOwnerCompromise[attacker, target] or
    (target in User and passwordResetCompromise[attacker, target])
}

// Compromise via group membership (add self to privileged group)
pred groupMembershipCompromise[attacker: Principal, g: ProtectedGroup] {
    canModifyGroupMembership[attacker, g]
}

// ============================================================================
// PART 10: Cross-Tier Violation Detection
// ============================================================================

// A cross-tier violation occurs when a lower-privileged tier can compromise
// a higher-privileged tier
pred crossTierViolation[attacker: Principal, target: Principal] {
    // Attacker is in a lower privilege tier than target
    higherPrivilege[target.tier, attacker.tier] and
    // And attacker can compromise the target
    canCompromise[attacker, target]
}

// Check if any cross-tier path exists
pred anyCrossTierPath {
    some attacker: Principal, target: Principal |
        crossTierViolation[attacker, target]
}

// Specific tier violation checks
pred tier2ToTier0Path {
    some attacker: Principal, target: Principal |
        attacker.tier = Tier2 and
        target.tier = Tier0 and
        canCompromise[attacker, target]
}

pred tier2ToTier1Path {
    some attacker: Principal, target: Principal |
        attacker.tier = Tier2 and
        target.tier = Tier1 and
        canCompromise[attacker, target]
}

pred tier1ToTier0Path {
    some attacker: Principal, target: Principal |
        attacker.tier = Tier1 and
        target.tier = Tier0 and
        canCompromise[attacker, target]
}

// Group escalation to protected groups
pred protectedGroupEscalation {
    some attacker: Principal, pg: ProtectedGroup |
        attacker.tier != Tier0 and
        groupMembershipCompromise[attacker, pg]
}

// DCSync from non-Tier0
pred unauthorizedDCSync {
    some attacker: Principal, d: Domain |
        attacker.tier != Tier0 and
        hasDCSyncRights[attacker, d]
}

// RBCD abuse to higher tier
pred rbcdEscalation {
    some attacker: Principal, target: Computer |
        higherPrivilege[target.tier, attacker.tier] and
        canConfigureRBCD[attacker, target]
}

// ============================================================================
// PART 11: Facts (Structural Constraints)
// ============================================================================

// No circular group membership
fact NoCircularGroups {
    no g: Group | g in g.^nestedGroups
}

// All groups must have valid tiers (can be Unassigned)
fact GroupTiersValid {
    all g: Group | g.tier in Tier
}

// Protected groups are Tier 0
fact ProtectedGroupsAreTier0 {
    all pg: ProtectedGroup | pg.tier = Tier0
}

// Domain Controller computer accounts (members of DomainControllersGroup) are Tier 0
fact DomainControllerMembersAreTier0 {
    all c: Computer | c in DomainControllersGroup.members implies c.tier = Tier0
}

// Security descriptor owner must be a principal
fact ValidSecurityDescriptorOwners {
    all sd: SecurityDescriptor | sd.sdOwner in Principal
}

// ADObject owners must be principals
fact ValidObjectOwners {
    all obj: ADObject | obj.owner in Principal
}

// ACE trustees must be principals
fact ValidACETrustees {
    all ace: ACE | ace.trustee in Principal
}

// Each principal has exactly one security descriptor (implicit from sig definition)
// Each security descriptor has exactly one DACL (implicit from sig definition)

// Connect security descriptor owner to the SD's owner field consistency
fact SecurityDescriptorOwnerConsistency {
    all p: Principal | p.securityDescriptor.sdOwner in Principal
}

// ============================================================================
// PART 12: Security Assertions to Verify
// ============================================================================

// ASSERT-1: No path from Tier2 to compromise Tier0
assert NoTier2ToTier0Path {
    not tier2ToTier0Path
}

// ASSERT-2: No path from Tier1 to compromise Tier0
assert NoTier1ToTier0Path {
    not tier1ToTier0Path
}

// ASSERT-3: No path from Tier2 to compromise Tier1
assert NoTier2ToTier1Path {
    not tier2ToTier1Path
}

// ASSERT-4: All owners are valid principals
assert NoDanglingOwners {
    all sd: SecurityDescriptor | sd.sdOwner in Principal
}

// ASSERT-5: Non-Tier0 cannot grant themselves protected group membership
assert NoSelfEscalationToProtectedGroups {
    not protectedGroupEscalation
}

// ASSERT-6: Tier isolation is maintained
assert TierIsolationMaintained {
    not anyCrossTierPath
}

// ASSERT-7: DCSync rights only for Tier0 principals
assert DCSyncOnlyTier0 {
    all attacker: Principal, d: Domain |
        hasDCSyncRights[attacker, d] implies attacker.tier = Tier0
}

// ASSERT-8: No RBCD escalation to higher tiers
assert NoRBCDEscalation {
    not rbcdEscalation
}

// ASSERT-9: Protected groups cannot be modified by non-Tier0
assert ProtectedGroupsSecure {
    no attacker: Principal, pg: ProtectedGroup |
        attacker.tier != Tier0 and
        canModifyGroupMembership[attacker, pg]
}

// ============================================================================
// PART 13: Predicates for Attack Discovery
// ============================================================================

// Find any attack path from attacker to target
pred findAttackPath[attacker: Principal, target: Principal] {
    canCompromise[attacker, target]
}

// Find principals that can escalate privilege
pred canEscalatePrivilege[p: Principal] {
    some target: Principal |
        higherPrivilege[target.tier, p.tier] and
        canCompromise[p, target]
}

// Find WriteDACL chains to Tier0
pred findWriteDACLChainToTier0[p: Principal] {
    p.tier != Tier0 and
    some target: Principal |
        target.tier = Tier0 and
        canModifyDACL[p, target]
}

// Find WriteOwner abuse paths to Tier0
pred findWriteOwnerAbuseToTier0[p: Principal] {
    p.tier != Tier0 and
    some target: Principal |
        target.tier = Tier0 and
        canTakeOwnership[p, target]
}

// Find group membership escalation paths
pred findGroupEscalation[p: Principal] {
    some pg: ProtectedGroup |
        canModifyGroupMembership[p, pg]
}

// Find Kerberoastable targets that can be set up
pred findKerberoastSetup[attacker: Principal, target: User] {
    canSetSPN[attacker, target] and
    target.tier = Tier0
}

// Find RBCD abuse opportunities
pred findRBCDAbuse[attacker: Principal, target: Computer] {
    canConfigureRBCD[attacker, target] and
    higherPrivilege[target.tier, attacker.tier]
}

// Find password reset paths to Tier0
pred findPasswordResetToTier0[attacker: Principal, target: User] {
    attacker.tier != Tier0 and
    target.tier = Tier0 and
    canForcePasswordChange[attacker, target]
}

// ============================================================================
// PART 14: Run Commands for Visualization and Attack Discovery
// ============================================================================

// --- Basic Model Visualization ---

// Show a basic model structure
run showBasicModel {
    #User >= 2
    #Computer >= 1
    #Group >= 2
    some ace: ACE | ace.aceType = Allow
} for 5 but exactly 4 Tier, exactly 2 ACEType, exactly 3 InheritanceFlags

// --- Cross-Tier Attack Discovery ---

// Find any cross-tier attack path
run findCrossTierAttack {
    anyCrossTierPath
} for 6 but exactly 4 Tier, exactly 2 ACEType

// Find Tier2 to Tier0 attack path
run findTier2ToTier0Attack {
    tier2ToTier0Path
} for 6 but exactly 4 Tier, exactly 2 ACEType

// Find Tier1 to Tier0 attack path
run findTier1ToTier0Attack {
    tier1ToTier0Path
} for 6 but exactly 4 Tier, exactly 2 ACEType

// --- Specific Attack Pattern Discovery ---

// Find WriteDACL abuse scenario
run showWriteDACLAbuse {
    some attacker: Principal, target: Principal |
        attacker.tier = Tier2 and
        target.tier = Tier0 and
        canModifyDACL[attacker, target]
} for 5 but exactly 4 Tier, exactly 2 ACEType

// Find WriteOwner abuse scenario
run showWriteOwnerAbuse {
    some attacker: Principal, target: Principal |
        attacker.tier = Tier2 and
        target.tier = Tier0 and
        canTakeOwnership[attacker, target]
} for 5 but exactly 4 Tier, exactly 2 ACEType

// Find RBCD attack path
run showRBCDAttack {
    some attacker: Principal, target: Computer |
        attacker.tier = Tier2 and
        target.tier = Tier0 and
        canConfigureRBCD[attacker, target]
} for 6 but exactly 4 Tier, exactly 2 ACEType

// Find group membership escalation
run showGroupEscalation {
    some p: Principal, pg: ProtectedGroup |
        p.tier = Tier2 and
        canModifyGroupMembership[p, pg]
} for 5 but exactly 4 Tier, exactly 2 ACEType

// Find DCSync abuse by non-Tier0
run showDCSyncAbuse {
    unauthorizedDCSync
} for 5 but exactly 4 Tier, exactly 2 ACEType

// Find password reset to Tier0
run showPasswordResetAbuse {
    some attacker: Principal, target: User |
        attacker.tier = Tier2 and
        target.tier = Tier0 and
        canForcePasswordChange[attacker, target]
} for 5 but exactly 4 Tier, exactly 2 ACEType

// Find Kerberoasting setup opportunity
run showKerberoastSetup {
    some attacker: Principal, target: User |
        attacker.tier != Tier0 and
        target.tier = Tier0 and
        canSetSPN[attacker, target]
} for 5 but exactly 4 Tier, exactly 2 ACEType

// --- Security Verification Commands ---

// Verify no Tier2 to Tier0 path exists (should find no counterexample in secure config)
check NoTier2ToTier0Path for 8 but exactly 4 Tier, exactly 2 ACEType

// Verify no Tier1 to Tier0 path exists
check NoTier1ToTier0Path for 8 but exactly 4 Tier, exactly 2 ACEType

// Verify tier isolation is maintained
check TierIsolationMaintained for 8 but exactly 4 Tier, exactly 2 ACEType

// Verify DCSync is Tier0 only
check DCSyncOnlyTier0 for 6 but exactly 4 Tier, exactly 2 ACEType

// Verify no RBCD escalation
check NoRBCDEscalation for 6 but exactly 4 Tier, exactly 2 ACEType

// Verify protected groups are secure
check ProtectedGroupsSecure for 6 but exactly 4 Tier, exactly 2 ACEType

// Verify no dangling owners
check NoDanglingOwners for 5 but exactly 4 Tier, exactly 2 ACEType

// Verify no self-escalation to protected groups
check NoSelfEscalationToProtectedGroups for 6 but exactly 4 Tier, exactly 2 ACEType

// ============================================================================
// End of ADTierModel_ACL.als
// ============================================================================
