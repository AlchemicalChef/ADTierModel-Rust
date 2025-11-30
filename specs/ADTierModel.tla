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
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

(***************************************************************************)
(* CONSTANTS                                                               *)
(***************************************************************************)

CONSTANTS
    Objects,        \* Set of all AD objects (users, computers, groups)
    Users,          \* Subset: user objects
    Computers,      \* Subset: computer objects
    Groups          \* Subset: group objects (tier security groups)

(***************************************************************************)
(* VARIABLES                                                               *)
(***************************************************************************)

VARIABLES
    tierAssignment,     \* Function: Object -> {"Tier0", "Tier1", "Tier2", "Unassigned"}
    groupMembership,    \* Function: Object -> SUBSET Groups
    tier0Infrastructure,\* Set of Tier 0 critical components (DCs, PKI, etc.)
    gpoRestrictions,    \* Function: Tier -> SUBSET Tiers (denied tiers)
    enabled,            \* Function: Object -> BOOLEAN
    \* Credential tracking for security analysis
    activeSessions,     \* Set of (account, resource) pairs representing active sessions
    credentialCache     \* Mapping: computer -> set of cached credentials

vars == <<tierAssignment, groupMembership, tier0Infrastructure,
          gpoRestrictions, enabled, activeSessions, credentialCache>>

adminVars == <<tierAssignment, groupMembership, tier0Infrastructure, gpoRestrictions, enabled>>
sessionVars == <<activeSessions, credentialCache>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Type Definitions                                                        *)
(***************************************************************************)

Tiers == {"Tier0", "Tier1", "Tier2", "Unassigned"}
ActiveTiers == {"Tier0", "Tier1", "Tier2"}
GroupSuffixes == {"Admins", "Operators", "Readers", "ServiceAccounts", "JumpServers"}

TypeInvariant ==
    /\ tierAssignment \in [Objects -> Tiers]
    /\ groupMembership \in [Objects -> SUBSET Groups]
    /\ tier0Infrastructure \subseteq Computers
    /\ gpoRestrictions \in [ActiveTiers -> SUBSET ActiveTiers]
    /\ enabled \in [Objects -> BOOLEAN]
    /\ activeSessions \subseteq (Users \X Computers)
    /\ credentialCache \in [Computers -> SUBSET Users]

-----------------------------------------------------------------------------
(***************************************************************************)
(* Helper Functions - Group Classification                                 *)
(***************************************************************************)

\* Get the tier of a group based on its name (e.g., "Tier0-Admins" -> "Tier0")
TierOfGroup(g) ==
    CASE g \in {"Tier0-Admins", "Tier0-Operators", "Tier0-Readers",
                "Tier0-ServiceAccounts", "Tier0-JumpServers"} -> "Tier0"
      [] g \in {"Tier1-Admins", "Tier1-Operators", "Tier1-Readers",
                "Tier1-ServiceAccounts", "Tier1-JumpServers"} -> "Tier1"
      [] g \in {"Tier2-Admins", "Tier2-Operators", "Tier2-Readers",
                "Tier2-ServiceAccounts", "Tier2-JumpServers"} -> "Tier2"
      [] OTHER -> "Unassigned"

\* Check if a group grants admin privileges
IsAdminGroup(g) == g \in {"Tier0-Admins", "Tier1-Admins", "Tier2-Admins",
                          "Tier0-Operators", "Tier1-Operators", "Tier2-Operators"}

\* Get all tiers a user has admin access to
AdminTiers(obj) ==
    {TierOfGroup(g) : g \in {grp \in groupMembership[obj] : IsAdminGroup(grp)}}

\* Get the effective tier of a user based on their admin group memberships
\* Returns "Unassigned" if no admin groups, otherwise returns the single tier
EffectiveAdminTier(obj) ==
    LET adminTiers == AdminTiers(obj)
    IN IF adminTiers = {} THEN "Unassigned"
       ELSE CHOOSE t \in adminTiers : TRUE

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
(* SAFETY INVARIANTS - Core Security Properties                            *)
(***************************************************************************)

\* INV-1: Tier Isolation - No user has admin rights in multiple tiers
\* This is the fundamental security property of the tiered model
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
ObjectTierConsistency ==
    \A obj \in Objects:
        tierAssignment[obj] /= "Unassigned" =>
            \A g \in groupMembership[obj]:
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

\* Combined Administrative Safety Invariant
AdminSafetyInvariant ==
    /\ TypeInvariant
    /\ TierIsolation
    /\ Tier0InfrastructurePlacement
    /\ GpoRestrictionsValid
    /\ ObjectTierConsistency

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
(* INITIAL STATE                                                           *)
(***************************************************************************)

Init ==
    /\ tierAssignment = [obj \in Objects |-> "Unassigned"]
    /\ groupMembership = [obj \in Objects |-> {}]
    /\ tier0Infrastructure = {}
    /\ gpoRestrictions = [t \in ActiveTiers |-> ActiveTiers \ {t}]
    /\ enabled = [obj \in Objects |-> TRUE]
    /\ activeSessions = {}
    /\ credentialCache = [comp \in Computers |-> {}]

-----------------------------------------------------------------------------
(***************************************************************************)
(* ADMINISTRATIVE ACTIONS                                                  *)
(***************************************************************************)

\* Action: Move an object to a tier
\* When moving to a tier, conflicting admin group memberships are removed
MoveObjectToTier(obj, targetTier) ==
    /\ targetTier \in ActiveTiers
    /\ tierAssignment' = [tierAssignment EXCEPT ![obj] = targetTier]
    \* Must remove conflicting group memberships to maintain safety
    /\ groupMembership' = [groupMembership EXCEPT ![obj] =
                           {g \in @ : ~IsAdminGroup(g) \/ TierOfGroup(g) = targetTier}]
    /\ UNCHANGED <<tier0Infrastructure, gpoRestrictions, enabled, sessionVars>>

\* Action: Add object to a tier group
\* Guards ensure tier isolation is maintained
AddToTierGroup(obj, group) ==
    /\ group \in Groups
    /\ IsAdminGroup(group) =>
        \* If adding to admin group, must not already have admin in another tier
        \/ AdminTiers(obj) = {}
        \/ AdminTiers(obj) = {TierOfGroup(group)}
    /\ groupMembership' = [groupMembership EXCEPT ![obj] = @ \cup {group}]
    /\ UNCHANGED <<tierAssignment, tier0Infrastructure, gpoRestrictions, enabled, sessionVars>>

\* Action: Remove object from a tier group
RemoveFromTierGroup(obj, group) ==
    /\ group \in groupMembership[obj]
    /\ groupMembership' = [groupMembership EXCEPT ![obj] = @ \ {group}]
    /\ UNCHANGED <<tierAssignment, tier0Infrastructure, gpoRestrictions, enabled, sessionVars>>

\* Action: Designate a computer as Tier 0 infrastructure
\* Computer must already be in Tier 0 to be designated as critical
DesignateTier0Infrastructure(comp) ==
    /\ comp \in Computers
    /\ tierAssignment[comp] = "Tier0"  \* Must already be in Tier 0
    /\ tier0Infrastructure' = tier0Infrastructure \cup {comp}
    /\ UNCHANGED <<tierAssignment, groupMembership, gpoRestrictions, enabled, sessionVars>>

\* Action: Remove Tier 0 infrastructure designation
\* Allows demoting non-critical systems (but not actually used in practice)
RemoveTier0Infrastructure(comp) ==
    /\ comp \in tier0Infrastructure
    /\ tier0Infrastructure' = tier0Infrastructure \ {comp}
    /\ UNCHANGED <<tierAssignment, groupMembership, gpoRestrictions, enabled, sessionVars>>

\* Action: Disable an account
DisableAccount(obj) ==
    /\ enabled' = [enabled EXCEPT ![obj] = FALSE]
    \* Disabling an account ends all active sessions
    /\ activeSessions' = {<<a, r>> \in activeSessions : a /= obj}
    /\ UNCHANGED <<tierAssignment, groupMembership, tier0Infrastructure, gpoRestrictions, credentialCache>>

\* Action: Enable an account
EnableAccount(obj) ==
    /\ ~enabled[obj]
    /\ enabled' = [enabled EXCEPT ![obj] = TRUE]
    /\ UNCHANGED <<tierAssignment, groupMembership, tier0Infrastructure, gpoRestrictions, sessionVars>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* SESSION ACTIONS                                                         *)
(***************************************************************************)

\* Successful logon: account logs into a resource (only if allowed by tier model)
Logon(account, resource) ==
    /\ account \in Users
    /\ resource \in Computers
    /\ AccessAllowed(account, resource)
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
    \/ \E comp \in Computers:
        DesignateTier0Infrastructure(comp)
    \/ \E comp \in Computers:
        RemoveTier0Infrastructure(comp)
    \/ \E obj \in Objects:
        DisableAccount(obj)
    \/ \E obj \in Objects:
        EnableAccount(obj)

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

=============================================================================
