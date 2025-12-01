---------------------------- MODULE ADTierModel ----------------------------
(***************************************************************************)
(* TLA+ Formal Specification for Active Directory Tier Model               *)
(*                                                                         *)
(* This specification models the security properties of a tiered           *)
(* administrative model for Active Directory, verifying that:              *)
(* - No user has administrative access to multiple tiers                   *)
(* - Critical infrastructure remains in Tier 0                             *)
(* - GPO restrictions are properly configured                              *)
(* - Object tier assignments match their group memberships                 *)
(* - Credential exposure across tiers is prevented                         *)
(* - Nested group memberships are properly resolved (transitive closure)   *)
(* - Primary groups are accounted for in tier calculations                 *)
(* - Service accounts have appropriate restrictions                        *)
(*                                                                         *)
(* Version 2.0 - Added nested group membership, primary groups,            *)
(*               service accounts, and compliance violation detection      *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* CONSTANTS                                                               *)
(***************************************************************************)

CONSTANTS
    Objects,        \* Set of all AD objects (users, computers, groups)
    Users,          \* Subset: user objects
    Computers,      \* Subset: computer objects
    Groups,         \* Subset: group objects (tier security groups)
    ServiceAccounts \* Subset: service account objects (subset of Users)

(***************************************************************************)
(* ASSUMPTIONS - Static constraints on constants                           *)
(***************************************************************************)

ASSUME UsersSubsetOfObjects == Users \subseteq Objects
ASSUME ComputersSubsetOfObjects == Computers \subseteq Objects
ASSUME GroupsSubsetOfObjects == Groups \subseteq Objects
ASSUME ServiceAccountsSubsetOfUsers == ServiceAccounts \subseteq Users
ASSUME DisjointSets == Users \cap Computers = {} /\ Users \cap Groups = {} /\ Computers \cap Groups = {}

(***************************************************************************)
(* VARIABLES                                                               *)
(***************************************************************************)

VARIABLES
    tierAssignment,     \* Function: Object -> {"Tier0", "Tier1", "Tier2", "Unassigned"}
    groupMembership,    \* Function: Object -> SUBSET Groups (direct membership)
    nestedGroupMembership, \* Function: Group -> SUBSET Groups (group nesting)
    primaryGroup,       \* Function: (Users \cup Computers) -> Groups (primary group like "Domain Users")
    tier0Infrastructure,\* Set of Tier 0 critical components (DCs, PKI, etc.)
    gpoRestrictions,    \* Function: Tier -> SUBSET Tiers (denied tiers)
    enabled,            \* Function: Object -> BOOLEAN
    lastLogon,          \* Function: Object -> Nat (days since last logon, for stale detection)
    \* Credential tracking for security analysis
    activeSessions,     \* Set of (account, resource) pairs representing active sessions
    credentialCache,    \* Mapping: computer -> set of cached credentials
    \* Service account properties
    serviceAccountSensitive, \* Function: ServiceAccounts -> BOOLEAN (cannot be delegated)
    serviceAccountInteractive \* Function: ServiceAccounts -> BOOLEAN (allows interactive logon)

vars == <<tierAssignment, groupMembership, nestedGroupMembership, primaryGroup,
          tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
          activeSessions, credentialCache, serviceAccountSensitive,
          serviceAccountInteractive>>

adminVars == <<tierAssignment, groupMembership, nestedGroupMembership, primaryGroup,
               tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
               serviceAccountSensitive, serviceAccountInteractive>>

sessionVars == <<activeSessions, credentialCache>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Type Definitions                                                        *)
(***************************************************************************)

Tiers == {"Tier0", "Tier1", "Tier2", "Unassigned"}
ActiveTiers == {"Tier0", "Tier1", "Tier2"}
GroupSuffixes == {"Admins", "Operators", "Readers", "ServiceAccounts", "JumpServers"}

\* Well-known primary groups (by RID conceptually)
WellKnownPrimaryGroups == {"Domain Users", "Domain Computers", "Domain Controllers",
                           "Domain Admins", "Domain Guests"}

TypeInvariant ==
    /\ tierAssignment \in [Objects -> Tiers]
    /\ groupMembership \in [Objects -> SUBSET Groups]
    /\ nestedGroupMembership \in [Groups -> SUBSET Groups]
    \* Primary group can be a Group, "None", or a well-known group name
    /\ primaryGroup \in [(Users \cup Computers) -> Groups \cup {"None", "Domain Users", "Domain Computers"}]
    /\ tier0Infrastructure \subseteq Computers
    /\ gpoRestrictions \in [ActiveTiers -> SUBSET ActiveTiers]
    /\ enabled \in [Objects -> BOOLEAN]
    /\ lastLogon \in [Objects -> Nat]
    /\ activeSessions \subseteq (Users \X Computers)
    /\ credentialCache \in [Computers -> SUBSET Users]
    \* Note: ServiceAccounts \subseteq Users is checked in ASSUME
    /\ serviceAccountSensitive \in [ServiceAccounts -> BOOLEAN]
    /\ serviceAccountInteractive \in [ServiceAccounts -> BOOLEAN]

-----------------------------------------------------------------------------
(***************************************************************************)
(* Helper Functions - Group Classification                                 *)
(***************************************************************************)

\* Tier group sets - define which groups belong to which tier
\* These can be overridden in the .cfg file for model checking
Tier0Groups == {"Tier0-Admins", "Tier0-Operators", "Tier0-Readers",
                "Tier0-ServiceAccounts", "Tier0-JumpServers"}
Tier1Groups == {"Tier1-Admins", "Tier1-Operators", "Tier1-Readers",
                "Tier1-ServiceAccounts", "Tier1-JumpServers"}
Tier2Groups == {"Tier2-Admins", "Tier2-Operators", "Tier2-Readers",
                "Tier2-ServiceAccounts", "Tier2-JumpServers"}

\* Admin groups that grant privileged access
AdminGroups == {"Tier0-Admins", "Tier1-Admins", "Tier2-Admins",
                "Tier0-Operators", "Tier1-Operators", "Tier2-Operators"}

\* Get the tier of a group based on its membership in tier group sets
TierOfGroup(g) ==
    CASE g \in Tier0Groups -> "Tier0"
      [] g \in Tier1Groups -> "Tier1"
      [] g \in Tier2Groups -> "Tier2"
      [] OTHER -> "Unassigned"

\* Check if a group grants admin privileges
IsAdminGroup(g) == g \in AdminGroups

\* Check if a group is a tier-specific group (not a well-known group)
IsTierGroup(g) == TierOfGroup(g) /= "Unassigned"

-----------------------------------------------------------------------------
(***************************************************************************)
(* TRANSITIVE GROUP MEMBERSHIP (LDAP_MATCHING_RULE_IN_CHAIN equivalent)    *)
(* This models the nested group expansion functionality                     *)
(***************************************************************************)

\* Compute transitive closure of nested group membership
\* This is equivalent to using LDAP_MATCHING_RULE_IN_CHAIN (OID 1.2.840.113556.1.4.1941)
\* Only processes groups that are in the Groups constant (ignores well-known groups like "Domain Users")
RECURSIVE TransitiveGroupClosure(_)
TransitiveGroupClosure(groups) ==
    LET \* Only look up nested membership for groups that are in Groups constant
        groupsInDomain == groups \cap Groups
        directlyNested == UNION {nestedGroupMembership[g] : g \in groupsInDomain}
        newGroups == groups \cup directlyNested
    IN IF newGroups = groups
       THEN groups  \* Fixed point reached
       ELSE TransitiveGroupClosure(newGroups)

\* Get all groups an object is a member of (including through nesting and primary group)
\* This is the equivalent of get_object_group_memberships with LDAP_MATCHING_RULE_IN_CHAIN
AllGroupMemberships(obj) ==
    LET directGroups == groupMembership[obj]
        \* Include primary group if it's set and is a real group (not "None")
        \* Note: Well-known groups like "Domain Users" are included but won't have nested members
        primaryGrp == IF obj \in (Users \cup Computers)
                         /\ primaryGroup[obj] /= "None"
                      THEN {primaryGroup[obj]}
                      ELSE {}
        allDirect == directGroups \cup primaryGrp
    IN TransitiveGroupClosure(allDirect)

\* Get all tiers an object has admin access to (considering transitive membership)
AdminTiers(obj) ==
    {TierOfGroup(g) : g \in {grp \in AllGroupMemberships(obj) : IsAdminGroup(grp)}}

\* Get the effective tier of a user based on their admin group memberships
\* Returns "Unassigned" if no admin groups
EffectiveAdminTier(obj) ==
    LET adminTiers == AdminTiers(obj)
    IN IF adminTiers = {} THEN "Unassigned"
       ELSE IF Cardinality(adminTiers) = 1
            THEN CHOOSE t \in adminTiers : TRUE
            ELSE "VIOLATION"  \* Multiple tiers indicates a violation

-----------------------------------------------------------------------------
(***************************************************************************)
(* Helper Functions - Access Control                                       *)
(***************************************************************************)

\* Check if an account can access a resource based on tier model
\* An account can only access resources in their assigned tier
AccessAllowed(account, resource) ==
    LET accountTier == tierAssignment[account]
        resourceTier == tierAssignment[resource]
    IN /\ accountTier /= "Unassigned"
       /\ resourceTier /= "Unassigned"
       /\ accountTier = resourceTier
       /\ enabled[account]
       /\ ~(accountTier \in gpoRestrictions[resourceTier])

\* Check if GPO would block this access (cross-tier deny)
GpoDeniesAccess(accountTier, resourceTier) ==
    /\ accountTier /= "Unassigned"
    /\ resourceTier /= "Unassigned"
    /\ accountTier \in gpoRestrictions[resourceTier]

-----------------------------------------------------------------------------
(***************************************************************************)
(* STALE ACCOUNT DETECTION                                                 *)
(***************************************************************************)

\* Threshold for stale accounts (in days)
STALE_THRESHOLD == 90

\* Check if an account is stale (hasn't logged on recently)
IsStaleAccount(obj) ==
    /\ obj \in Users
    /\ enabled[obj]
    /\ lastLogon[obj] > STALE_THRESHOLD

\* Set of all stale accounts
StaleAccounts == {obj \in Users : IsStaleAccount(obj)}

-----------------------------------------------------------------------------
(***************************************************************************)
(* SERVICE ACCOUNT SECURITY                                                *)
(***************************************************************************)

\* A service account should not allow interactive logon if it's in a privileged tier
ServiceAccountSecure(sa) ==
    /\ sa \in ServiceAccounts
    /\ tierAssignment[sa] \in {"Tier0", "Tier1"} =>
        /\ serviceAccountSensitive[sa] = TRUE
        /\ serviceAccountInteractive[sa] = FALSE

\* All service accounts in privileged tiers should be hardened
AllServiceAccountsSecure ==
    \A sa \in ServiceAccounts:
        tierAssignment[sa] \in {"Tier0", "Tier1"} => ServiceAccountSecure(sa)

-----------------------------------------------------------------------------
(***************************************************************************)
(* SAFETY INVARIANTS - Core Security Properties                            *)
(***************************************************************************)

\* INV-1: Tier Isolation - No user has admin rights in multiple tiers
\* This is the fundamental security property of the tiered model
\* Now accounts for transitive/nested group membership
TierIsolation ==
    \A obj \in Users:
        Cardinality(AdminTiers(obj)) <= 1

\* INV-2: Tier 0 Infrastructure Placement
\* All critical infrastructure must be in Tier 0
\* Domain Controllers, PKI, and other critical infrastructure must never
\* be moved to lower tiers
Tier0InfrastructurePlacement ==
    \A comp \in tier0Infrastructure:
        tierAssignment[comp] = "Tier0"

\* INV-3: GPO Restrictions Properly Configured
\* Each tier must deny logon from all other tiers to enforce isolation
GpoRestrictionsValid ==
    /\ gpoRestrictions["Tier0"] = {"Tier1", "Tier2"}
    /\ gpoRestrictions["Tier1"] = {"Tier0", "Tier2"}
    /\ gpoRestrictions["Tier2"] = {"Tier0", "Tier1"}

\* INV-4: Object-Tier Consistency
\* An object's administrative group memberships should match its tier assignment
\* Now considers transitive membership through nested groups
ObjectTierConsistency ==
    \A obj \in Objects:
        tierAssignment[obj] /= "Unassigned" =>
            \A g \in AllGroupMemberships(obj):
                IsAdminGroup(g) => TierOfGroup(g) = tierAssignment[obj]

\* INV-5: No Cross-Tier Sessions
\* Active sessions must respect tier boundaries
NoCrossTierSessions ==
    \A <<account, resource>> \in activeSessions:
        tierAssignment[account] = tierAssignment[resource]

\* INV-6: Tier 0 Credentials Protected
\* Tier 0 credentials are NEVER cached on lower tier resources
\* This is the primary defense against credential theft attacks
Tier0CredentialsProtected ==
    \A comp \in Computers:
        tierAssignment[comp] /= "Tier0" =>
            \A user \in credentialCache[comp]:
                tierAssignment[user] /= "Tier0"

\* INV-7: Tier 1 Credentials Protected
\* Tier 1 credentials are never cached on Tier 2 resources
Tier1CredentialsProtected ==
    \A comp \in Computers:
        tierAssignment[comp] = "Tier2" =>
            \A user \in credentialCache[comp]:
                tierAssignment[user] /= "Tier1"

\* INV-8: No Circular Group Nesting
\* A group cannot be (transitively) a member of itself
NoCircularGroupNesting ==
    \A g \in Groups:
        g \notin TransitiveGroupClosure(nestedGroupMembership[g])

\* INV-9: Primary Group Consistency
\* An object's primary group should match its tier (if tier-specific)
PrimaryGroupConsistency ==
    \A obj \in (Users \cup Computers):
        /\ primaryGroup[obj] /= "None"
        /\ IsTierGroup(primaryGroup[obj])
        /\ tierAssignment[obj] /= "Unassigned"
        => TierOfGroup(primaryGroup[obj]) = tierAssignment[obj]

\* INV-10: Service Account Hardening
\* Service accounts in privileged tiers must be hardened
ServiceAccountHardening ==
    \A sa \in ServiceAccounts:
        tierAssignment[sa] \in {"Tier0", "Tier1"} =>
            serviceAccountSensitive[sa] = TRUE

\* Combined Administrative Safety Invariant
AdminSafetyInvariant ==
    /\ TypeInvariant
    /\ TierIsolation
    /\ Tier0InfrastructurePlacement
    /\ GpoRestrictionsValid
    /\ ObjectTierConsistency
    /\ NoCircularGroupNesting
    /\ PrimaryGroupConsistency
    /\ ServiceAccountHardening

\* Combined Session/Credential Safety Invariant
SessionSafetyInvariant ==
    /\ NoCrossTierSessions
    /\ Tier0CredentialsProtected
    /\ Tier1CredentialsProtected

\* Full Safety Invariant
SafetyInvariant ==
    /\ AdminSafetyInvariant
    /\ SessionSafetyInvariant

-----------------------------------------------------------------------------
(***************************************************************************)
(* COMPLIANCE VIOLATION DETECTION                                          *)
(* These predicates identify violations for the compliance dashboard       *)
(***************************************************************************)

\* Detect cross-tier access violations (accounts with access to multiple tiers)
CrossTierViolations ==
    {obj \in Users : Cardinality(AdminTiers(obj)) > 1}

\* Detect misplaced Tier 0 infrastructure
MisplacedTier0Infrastructure ==
    {comp \in tier0Infrastructure : tierAssignment[comp] /= "Tier0"}

\* Detect objects in wrong tier based on group membership
WrongTierPlacement ==
    {obj \in Objects :
        /\ tierAssignment[obj] /= "Unassigned"
        /\ \E g \in AllGroupMemberships(obj):
            /\ IsAdminGroup(g)
            /\ TierOfGroup(g) /= tierAssignment[obj]}

\* Detect unhardened service accounts in privileged tiers
UnhardenedServiceAccounts ==
    {sa \in ServiceAccounts :
        /\ tierAssignment[sa] \in {"Tier0", "Tier1"}
        /\ ~serviceAccountSensitive[sa]}

\* Detect service accounts with interactive logon enabled
InteractiveServiceAccounts ==
    {sa \in ServiceAccounts :
        /\ tierAssignment[sa] \in {"Tier0", "Tier1"}
        /\ serviceAccountInteractive[sa]}

\* Total compliance score (0-100, higher is better)
\* Deducts points for various violations
ComplianceScore ==
    LET totalObjects == Cardinality(Objects)
        crossTierCount == Cardinality(CrossTierViolations)
        misplacedCount == Cardinality(MisplacedTier0Infrastructure)
        wrongTierCount == Cardinality(WrongTierPlacement)
        unhardenedCount == Cardinality(UnhardenedServiceAccounts)
        interactiveCount == Cardinality(InteractiveServiceAccounts)
        staleCount == Cardinality(StaleAccounts)
        \* Weight violations by severity
        violationPoints == (crossTierCount * 20) + (misplacedCount * 25) +
                          (wrongTierCount * 15) + (unhardenedCount * 10) +
                          (interactiveCount * 10) + (staleCount * 5)
        maxScore == 100
    IN IF totalObjects = 0 THEN 100
       ELSE maxScore - (violationPoints * 100) \div (totalObjects * 10)

\* Compliance is perfect (no violations)
FullCompliance ==
    /\ CrossTierViolations = {}
    /\ MisplacedTier0Infrastructure = {}
    /\ WrongTierPlacement = {}
    /\ UnhardenedServiceAccounts = {}
    /\ InteractiveServiceAccounts = {}
    /\ StaleAccounts = {}

-----------------------------------------------------------------------------
(***************************************************************************)
(* INITIAL STATE                                                           *)
(***************************************************************************)

Init ==
    /\ tierAssignment = [obj \in Objects |-> "Unassigned"]
    /\ groupMembership = [obj \in Objects |-> {}]
    /\ nestedGroupMembership = [g \in Groups |-> {}]
    /\ primaryGroup = [obj \in (Users \cup Computers) |-> "Domain Users"]
    /\ tier0Infrastructure = {}
    /\ gpoRestrictions = [t \in ActiveTiers |-> ActiveTiers \ {t}]
    /\ enabled = [obj \in Objects |-> TRUE]
    /\ lastLogon = [obj \in Objects |-> 0]
    /\ activeSessions = {}
    /\ credentialCache = [comp \in Computers |-> {}]
    /\ serviceAccountSensitive = [sa \in ServiceAccounts |-> FALSE]
    /\ serviceAccountInteractive = [sa \in ServiceAccounts |-> TRUE]

-----------------------------------------------------------------------------
(***************************************************************************)
(* ADMINISTRATIVE ACTIONS                                                  *)
(***************************************************************************)

\* Action: Move an object to a tier
\* When moving to a tier, conflicting admin group memberships are removed
\* Service accounts must be hardened before moving to privileged tiers (Tier0, Tier1)
MoveObjectToTier(obj, targetTier) ==
    /\ targetTier \in ActiveTiers
    \* Service accounts must be hardened before moving to Tier0 or Tier1
    /\ (obj \in ServiceAccounts /\ targetTier \in {"Tier0", "Tier1"}) =>
        serviceAccountSensitive[obj] = TRUE
    /\ tierAssignment' = [tierAssignment EXCEPT ![obj] = targetTier]
    \* Must remove conflicting group memberships to maintain safety
    /\ groupMembership' = [groupMembership EXCEPT ![obj] =
                           {g \in @ : ~IsAdminGroup(g) \/ TierOfGroup(g) = targetTier}]
    /\ UNCHANGED <<nestedGroupMembership, primaryGroup, tier0Infrastructure,
                   gpoRestrictions, enabled, lastLogon, sessionVars,
                   serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Add object to a tier group
\* Guards ensure tier isolation is maintained (considering transitive membership)
AddToTierGroup(obj, group) ==
    /\ group \in Groups
    /\ IsAdminGroup(group) =>
        \* If adding to admin group, must not already have admin in another tier
        \* This now considers transitive membership
        LET currentAdminTiers == AdminTiers(obj)
            newTier == TierOfGroup(group)
        IN \/ currentAdminTiers = {}
           \/ currentAdminTiers = {newTier}
    /\ groupMembership' = [groupMembership EXCEPT ![obj] = @ \cup {group}]
    /\ UNCHANGED <<tierAssignment, nestedGroupMembership, primaryGroup,
                   tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Remove object from a tier group
RemoveFromTierGroup(obj, group) ==
    /\ group \in groupMembership[obj]
    /\ groupMembership' = [groupMembership EXCEPT ![obj] = @ \ {group}]
    /\ UNCHANGED <<tierAssignment, nestedGroupMembership, primaryGroup,
                   tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Add a group as a nested member of another group
\* Guards prevent circular nesting
AddNestedGroupMembership(parentGroup, childGroup) ==
    /\ parentGroup \in Groups
    /\ childGroup \in Groups
    /\ parentGroup /= childGroup
    \* Prevent circular nesting
    /\ parentGroup \notin TransitiveGroupClosure({childGroup})
    /\ nestedGroupMembership' = [nestedGroupMembership EXCEPT ![parentGroup] = @ \cup {childGroup}]
    /\ UNCHANGED <<tierAssignment, groupMembership, primaryGroup,
                   tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Remove nested group membership
RemoveNestedGroupMembership(parentGroup, childGroup) ==
    /\ childGroup \in nestedGroupMembership[parentGroup]
    /\ nestedGroupMembership' = [nestedGroupMembership EXCEPT ![parentGroup] = @ \ {childGroup}]
    /\ UNCHANGED <<tierAssignment, groupMembership, primaryGroup,
                   tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Valid primary groups include tier groups, well-known groups, and "None"
ValidPrimaryGroups == Groups \cup {"None", "Domain Users", "Domain Computers"}

\* Action: Set primary group for an object
SetPrimaryGroup(obj, group) ==
    /\ obj \in (Users \cup Computers)
    /\ group \in ValidPrimaryGroups
    \* If setting to a tier group, should match object's tier
    /\ (IsTierGroup(group) /\ tierAssignment[obj] /= "Unassigned") =>
        TierOfGroup(group) = tierAssignment[obj]
    /\ primaryGroup' = [primaryGroup EXCEPT ![obj] = group]
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   tier0Infrastructure, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Designate a computer as Tier 0 infrastructure
\* Computer must already be in Tier 0 to be designated as critical
DesignateTier0Infrastructure(comp) ==
    /\ comp \in Computers
    /\ tierAssignment[comp] = "Tier0"  \* Must already be in Tier 0
    /\ tier0Infrastructure' = tier0Infrastructure \cup {comp}
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   primaryGroup, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Remove Tier 0 infrastructure designation
\* Allows demoting non-critical systems
RemoveTier0Infrastructure(comp) ==
    /\ comp \in tier0Infrastructure
    /\ tier0Infrastructure' = tier0Infrastructure \ {comp}
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   primaryGroup, gpoRestrictions, enabled, lastLogon,
                   sessionVars, serviceAccountSensitive, serviceAccountInteractive>>

\* Action: Disable an account
DisableAccount(obj) ==
    /\ enabled' = [enabled EXCEPT ![obj] = FALSE]
    \* Disabling an account ends all active sessions
    /\ activeSessions' = {<<a, r>> \in activeSessions : a /= obj}
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   primaryGroup, tier0Infrastructure, gpoRestrictions,
                   lastLogon, credentialCache, serviceAccountSensitive,
                   serviceAccountInteractive>>

\* Action: Enable an account
EnableAccount(obj) ==
    /\ ~enabled[obj]
    /\ enabled' = [enabled EXCEPT ![obj] = TRUE]
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   primaryGroup, tier0Infrastructure, gpoRestrictions,
                   lastLogon, sessionVars, serviceAccountSensitive,
                   serviceAccountInteractive>>

\* Action: Harden a service account (mark as sensitive, disable interactive)
HardenServiceAccount(sa) ==
    /\ sa \in ServiceAccounts
    /\ serviceAccountSensitive' = [serviceAccountSensitive EXCEPT ![sa] = TRUE]
    /\ serviceAccountInteractive' = [serviceAccountInteractive EXCEPT ![sa] = FALSE]
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   primaryGroup, tier0Infrastructure, gpoRestrictions,
                   enabled, lastLogon, sessionVars>>

\* Action: Update last logon time (simulates account activity)
UpdateLastLogon(obj, newTime) ==
    /\ obj \in Users
    /\ newTime >= 0
    /\ lastLogon' = [lastLogon EXCEPT ![obj] = newTime]
    /\ UNCHANGED <<tierAssignment, groupMembership, nestedGroupMembership,
                   primaryGroup, tier0Infrastructure, gpoRestrictions,
                   enabled, sessionVars, serviceAccountSensitive,
                   serviceAccountInteractive>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* SESSION ACTIONS                                                         *)
(***************************************************************************)

\* Successful logon: account logs into a resource (only if allowed by tier model)
Logon(account, resource) ==
    /\ account \in Users
    /\ resource \in Computers
    /\ AccessAllowed(account, resource)
    \* Service accounts with interactive logon disabled cannot log on interactively
    /\ account \in ServiceAccounts => serviceAccountInteractive[account]
    /\ activeSessions' = activeSessions \cup {<<account, resource>>}
    \* Credentials get cached on the resource (realistic Windows behavior)
    /\ credentialCache' = [credentialCache EXCEPT ![resource] = @ \cup {account}]
    /\ UNCHANGED adminVars

\* Logoff: account logs off from a resource
Logoff(account, resource) ==
    /\ <<account, resource>> \in activeSessions
    /\ activeSessions' = activeSessions \ {<<account, resource>>}
    \* Note: Credentials may remain cached even after logoff (mimikatz risk)
    /\ UNCHANGED <<adminVars, credentialCache>>

\* Clear credential cache (e.g., via reboot or security tool)
ClearCredentialCache(resource) ==
    /\ resource \in Computers
    /\ credentialCache' = [credentialCache EXCEPT ![resource] = {}]
    /\ UNCHANGED <<adminVars, activeSessions>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* NEXT STATE RELATION                                                     *)
(***************************************************************************)

AdminNext ==
    \/ \E obj \in Objects, tier \in ActiveTiers:
        MoveObjectToTier(obj, tier)
    \/ \E obj \in Objects, grp \in Groups:
        AddToTierGroup(obj, grp)
    \/ \E obj \in Objects, grp \in Groups:
        RemoveFromTierGroup(obj, grp)
    \/ \E parent \in Groups, child \in Groups:
        AddNestedGroupMembership(parent, child)
    \/ \E parent \in Groups, child \in Groups:
        RemoveNestedGroupMembership(parent, child)
    \/ \E obj \in (Users \cup Computers), grp \in ValidPrimaryGroups:
        SetPrimaryGroup(obj, grp)
    \/ \E comp \in Computers:
        DesignateTier0Infrastructure(comp)
    \/ \E comp \in Computers:
        RemoveTier0Infrastructure(comp)
    \/ \E obj \in Objects:
        DisableAccount(obj)
    \/ \E obj \in Objects:
        EnableAccount(obj)
    \/ \E sa \in ServiceAccounts:
        HardenServiceAccount(sa)
    \/ \E obj \in Users, time \in 0..365:
        UpdateLastLogon(obj, time)

SessionNext ==
    \/ \E user \in Users, comp \in Computers:
        Logon(user, comp)
    \/ \E user \in Users, comp \in Computers:
        Logoff(user, comp)
    \/ \E comp \in Computers:
        ClearCredentialCache(comp)

Next == AdminNext \/ SessionNext

-----------------------------------------------------------------------------
(***************************************************************************)
(* SPECIFICATION                                                           *)
(***************************************************************************)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* FAIRNESS CONDITIONS                                                     *)
(***************************************************************************)

\* Weak fairness ensures that if an action is continuously enabled,
\* it will eventually be taken
Fairness ==
    /\ WF_vars(AdminNext)
    /\ WF_vars(SessionNext)

FairSpec == Spec /\ Fairness

-----------------------------------------------------------------------------
(***************************************************************************)
(* LIVENESS PROPERTIES                                                     *)
(***************************************************************************)

\* Eventually, all service accounts in privileged tiers will be hardened
EventuallyAllServiceAccountsHardened ==
    <>[](\A sa \in ServiceAccounts:
        tierAssignment[sa] \in {"Tier0", "Tier1"} => ServiceAccountSecure(sa))

\* Eventually, there are no stale accounts
EventuallyNoStaleAccounts ==
    <>[](StaleAccounts = {})

\* Eventually, full compliance is achieved
EventuallyFullCompliance ==
    <>[]FullCompliance

-----------------------------------------------------------------------------
(***************************************************************************)
(* THEOREMS TO VERIFY                                                      *)
(***************************************************************************)

\* The administrative safety invariant is preserved by all transitions
THEOREM Spec => []AdminSafetyInvariant

\* The session safety invariant is preserved by all transitions
THEOREM Spec => []SessionSafetyInvariant

\* The combined safety invariant is preserved by all transitions
THEOREM Spec => []SafetyInvariant

\* Tier isolation is never violated
THEOREM Spec => []TierIsolation

\* Tier 0 infrastructure always remains in Tier 0
THEOREM Spec => []Tier0InfrastructurePlacement

\* GPO restrictions are always properly configured
THEOREM Spec => []GpoRestrictionsValid

\* Tier 0 credentials are never exposed on lower tier systems
THEOREM Spec => []Tier0CredentialsProtected

\* No circular group nesting is ever introduced
THEOREM Spec => []NoCircularGroupNesting

\* With fairness, eventually all service accounts are hardened
THEOREM FairSpec => EventuallyAllServiceAccountsHardened

=============================================================================
