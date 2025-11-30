---------------------------- MODULE ADTierModel ----------------------------
(***************************************************************************)
(* TLA+ Formal Specification of the AD Tier Model                          *)
(*                                                                         *)
(* This specification models the security properties of a tiered           *)
(* administrative model for Active Directory, ensuring tier isolation      *)
(* and preventing credential theft attacks.                                *)
(***************************************************************************)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    Accounts,       \* Set of all accounts (users, admins, service accounts)
    Resources,      \* Set of all resources (computers, servers, DCs)
    Tier0Accounts,  \* Accounts assigned to Tier 0
    Tier1Accounts,  \* Accounts assigned to Tier 1
    Tier2Accounts,  \* Accounts assigned to Tier 2
    Tier0Resources, \* Resources in Tier 0 (Domain Controllers, etc.)
    Tier1Resources, \* Resources in Tier 1 (Servers)
    Tier2Resources  \* Resources in Tier 2 (Workstations)

VARIABLES
    activeSessions,     \* Set of (account, resource) pairs representing active sessions
    credentialCache,    \* Mapping: resource -> set of cached credentials
    compromisedAccounts \* Set of accounts whose credentials have been stolen

vars == <<activeSessions, credentialCache, compromisedAccounts>>

-----------------------------------------------------------------------------
(***************************************************************************)
(* Type Invariants                                                         *)
(***************************************************************************)

TypeInvariant ==
    /\ activeSessions \subseteq (Accounts \X Resources)
    /\ credentialCache \in [Resources -> SUBSET Accounts]
    /\ compromisedAccounts \subseteq Accounts

-----------------------------------------------------------------------------
(***************************************************************************)
(* Helper Functions                                                        *)
(***************************************************************************)

\* Get the tier of an account (0, 1, 2, or -1 if unassigned)
TierOfAccount(a) ==
    IF a \in Tier0Accounts THEN 0
    ELSE IF a \in Tier1Accounts THEN 1
    ELSE IF a \in Tier2Accounts THEN 2
    ELSE -1

\* Get the tier of a resource
TierOfResource(r) ==
    IF r \in Tier0Resources THEN 0
    ELSE IF r \in Tier1Resources THEN 1
    ELSE IF r \in Tier2Resources THEN 2
    ELSE -1

\* Check if an account is an admin account (simplified: all tiered accounts are admins)
IsAdminAccount(a) ==
    a \in (Tier0Accounts \union Tier1Accounts \union Tier2Accounts)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Access Control Policy                                                   *)
(*                                                                         *)
(* The tier model enforces that accounts can ONLY access resources in      *)
(* their own tier. This prevents:                                          *)
(* - Credential exposure on lower tiers (higher tier creds on lower tier)  *)
(* - Privilege escalation (lower tier accessing higher tier)               *)
(***************************************************************************)

\* An account is allowed to access a resource only if they're in the same tier
AccessAllowed(account, resource) ==
    LET accountTier == TierOfAccount(account)
        resourceTier == TierOfResource(resource)
    IN
        /\ accountTier >= 0          \* Account must be assigned to a tier
        /\ resourceTier >= 0         \* Resource must be assigned to a tier
        /\ accountTier = resourceTier \* Account and resource must be in same tier

\* Access is denied if tiers don't match
AccessDenied(account, resource) ==
    ~AccessAllowed(account, resource)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Initial State                                                           *)
(***************************************************************************)

Init ==
    /\ activeSessions = {}
    /\ credentialCache = [r \in Resources |-> {}]
    /\ compromisedAccounts = {}

-----------------------------------------------------------------------------
(***************************************************************************)
(* Actions                                                                 *)
(***************************************************************************)

\* Successful logon: account logs into a resource (only if allowed)
Logon(account, resource) ==
    /\ AccessAllowed(account, resource)
    /\ activeSessions' = activeSessions \union {<<account, resource>>}
    \* Credentials get cached on the resource (realistic Windows behavior)
    /\ credentialCache' = [credentialCache EXCEPT ![resource] = @ \union {account}]
    /\ UNCHANGED compromisedAccounts

\* Logoff: account logs off from a resource
Logoff(account, resource) ==
    /\ <<account, resource>> \in activeSessions
    /\ activeSessions' = activeSessions \ {<<account, resource>>}
    \* Note: Credentials may remain cached even after logoff (mimikatz risk)
    /\ UNCHANGED <<credentialCache, compromisedAccounts>>

\* Credential theft: attacker on a compromised resource steals cached credentials
\* This models attacks like mimikatz, pass-the-hash, etc.
StealCredentials(resource) ==
    /\ credentialCache[resource] /= {}
    /\ compromisedAccounts' = compromisedAccounts \union credentialCache[resource]
    /\ UNCHANGED <<activeSessions, credentialCache>>

\* Denied logon attempt (for modeling - doesn't change state)
DeniedLogonAttempt(account, resource) ==
    /\ AccessDenied(account, resource)
    /\ UNCHANGED vars

-----------------------------------------------------------------------------
(***************************************************************************)
(* Next State Relation                                                     *)
(***************************************************************************)

Next ==
    \/ \E a \in Accounts, r \in Resources : Logon(a, r)
    \/ \E a \in Accounts, r \in Resources : Logoff(a, r)
    \/ \E r \in Resources : StealCredentials(r)
    \/ \E a \in Accounts, r \in Resources : DeniedLogonAttempt(a, r)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Safety Properties (Invariants)                                          *)
(***************************************************************************)

\* CRITICAL: Tier 0 credentials are NEVER exposed on lower tier resources
\* This is the primary security goal of the tier model
Tier0CredentialsProtected ==
    \A r \in (Tier1Resources \union Tier2Resources) :
        credentialCache[r] \intersect Tier0Accounts = {}

\* Tier 1 credentials are never exposed on Tier 2 resources
Tier1CredentialsProtected ==
    \A r \in Tier2Resources :
        credentialCache[r] \intersect Tier1Accounts = {}

\* No cross-tier sessions should ever exist
NoCrossTierSessions ==
    \A <<a, r>> \in activeSessions :
        TierOfAccount(a) = TierOfResource(r)

\* Combined tier isolation invariant
TierIsolation ==
    /\ Tier0CredentialsProtected
    /\ Tier1CredentialsProtected
    /\ NoCrossTierSessions

-----------------------------------------------------------------------------
(***************************************************************************)
(* Liveness Properties                                                     *)
(***************************************************************************)

\* Accounts can eventually access resources in their own tier
\* (The system is not so restrictive that it blocks all access)
EventualAccess ==
    \A a \in Accounts, r \in Resources :
        (TierOfAccount(a) = TierOfResource(r) /\ TierOfAccount(a) >= 0) =>
            <>(<<a, r>> \in activeSessions)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Temporal Properties                                                     *)
(***************************************************************************)

\* The tier isolation invariant always holds
AlwaysTierIsolation == []TierIsolation

\* If tier isolation holds, Tier 0 accounts are never compromised via lower tiers
\* (They can only be compromised if Tier 0 resources themselves are breached)
Tier0NeverCompromisedViaLowerTiers ==
    [](Tier0CredentialsProtected =>
        (compromisedAccounts \intersect Tier0Accounts = {}
         \/ \E r \in Tier0Resources : credentialCache[r] \intersect Tier0Accounts /= {}))

-----------------------------------------------------------------------------
(***************************************************************************)
(* Specification                                                           *)
(***************************************************************************)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(***************************************************************************)
(* Theorems                                                                *)
(***************************************************************************)

\* The main theorem: Under this specification, tier isolation is maintained
THEOREM Spec => []TierIsolation

=============================================================================
