//! Active Directory search operations using Windows ADSI IDirectorySearch
//!
//! This module provides LDAP search functionality for querying AD objects.

use crate::domain::{ObjectType, Tier, Tier0RoleType, TierMember, Tier0Component};
use crate::error::{AppError, AppResult};
use std::collections::HashMap;
use std::collections::HashSet;
use serde::Serialize;

/// LDAP Matching Rule OID for transitive group membership (nested groups)
/// This allows a single LDAP query to find all groups an object belongs to,
/// including through nested group membership.
pub const LDAP_MATCHING_RULE_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";
use super::ensure_com_initialized;
use windows::{
    core::{BSTR, Interface, PCWSTR},
    Win32::Networking::ActiveDirectory::*,
    Win32::System::Com::*,
};
use std::ffi::OsString;

use std::os::windows::ffi::OsStringExt;

/// Diagnostic information for AD connection issues
#[derive(Debug, Clone, Serialize)]
pub struct AdDiagnostics {
    pub domain_dn: String,
    pub com_init_status: String,
    pub ldap_bind_status: String,
    pub ldap_search_status: String,
    pub objects_found: usize,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub steps_completed: Vec<String>,
    pub tier_ou_status: Vec<TierOuStatus>,
}

/// Status of a tier OU query
#[derive(Debug, Clone, Serialize)]
pub struct TierOuStatus {
    pub tier: String,
    pub ou_path: String,
    pub exists: bool,
    pub object_count: usize,
    pub error: Option<String>,
}

/// Search result row containing attribute values
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub attributes: HashMap<String, Vec<String>>,
}

impl SearchResult {
    pub fn new() -> Self {
        Self {
            attributes: HashMap::new(),
        }
    }

    pub fn get(&self, attr: &str) -> Option<&String> {
        self.attributes.get(&attr.to_lowercase()).and_then(|v| v.first())
    }

    pub fn get_all(&self, attr: &str) -> Option<&Vec<String>> {
        self.attributes.get(&attr.to_lowercase())
    }
}

/// Perform an LDAP search

pub fn ldap_search(
    base_dn: &str,
    filter: &str,
    attributes: &[&str],
    scope: SearchScope,
) -> AppResult<Vec<SearchResult>> {
    tracing::info!(
        base_dn = base_dn,
        filter = filter,
        scope = ?scope,
        "LDAP SEARCH: Starting query"
    );
    // SAFETY: This unsafe block performs LDAP searches against Active Directory via ADSI/COM.
    // This is safe because:
    // 1. COM is initialized via ensure_com_initialized() before any ADSI calls
    // 2. path_bstr is a valid BSTR created from a valid Rust string
    // 3. ADsOpenObject returns a valid IDirectorySearch interface or an error
    // 4. Search preferences use well-known ADS_SEARCHPREF constants
    // 5. All BSTR values for attributes are created from valid Rust strings
    // 6. ExecuteSearch, GetFirstRow, GetNextRow follow ADSI search patterns
    // 7. GetColumn and FreeColumn properly manage column memory per ADSI contract
    // 8. CloseSearchHandle releases the search handle when done
    // 9. All COM reference counting is handled automatically by the windows crate
    // 10. Memory for ADS_SEARCH_COLUMN is managed via std::mem::zeroed and FreeColumn
    unsafe {
        // Initialize COM - use APARTMENTTHREADED for ADSI compatibility
        ensure_com_initialized()?;

        let ldap_path = format!("LDAP://{}", base_dn);
        tracing::debug!(ldap_path = %ldap_path, "Opening LDAP connection");
        let path_bstr = BSTR::from(ldap_path.as_str());

        let mut search: Option<IDirectorySearch> = None;
        ADsOpenObject(
            PCWSTR(path_bstr.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            ADS_SECURE_AUTHENTICATION,
            &<IDirectorySearch as Interface>::IID,
            &mut search as *mut _ as *mut *mut std::ffi::c_void,
        )
        .map_err(|e| {
            let hresult = e.code().0 as u32;
            tracing::error!(
                base_dn = base_dn,
                ldap_path = %ldap_path,
                error = %e,
                hresult = format!("0x{:08X}", hresult),
                "LDAP SEARCH FAILED: ADsOpenObject error"
            );
            AppError::LdapError(format!("Failed to open {}: {} (HRESULT: 0x{:08X})", base_dn, e, hresult))
        })?;

        let search = search.ok_or_else(|| {
            tracing::error!(base_dn = base_dn, "Search interface not available");
            AppError::LdapError(format!("Search interface not available for {}", base_dn))
        })?;

        // Set search preferences
        let mut prefs = [
            ADS_SEARCHPREF_INFO {
                dwSearchPref: ADS_SEARCHPREF_SEARCH_SCOPE,
                vValue: ADSVALUE {
                    dwType: ADSTYPE_INTEGER,
                    Anonymous: ADSVALUE_0 {
                        Integer: scope.to_ads_scope() as u32,
                    },
                },
                dwStatus: ADS_STATUS_S_OK,
            },
            ADS_SEARCHPREF_INFO {
                dwSearchPref: ADS_SEARCHPREF_PAGESIZE,
                vValue: ADSVALUE {
                    dwType: ADSTYPE_INTEGER,
                    Anonymous: ADSVALUE_0 { Integer: 1000 },
                },
                dwStatus: ADS_STATUS_S_OK,
            },
        ];

        if let Err(e) = search.SetSearchPreference(prefs.as_mut_ptr(), prefs.len() as u32) {
            tracing::warn!(error = %e, "Failed to set search preferences, continuing with defaults");
        }

        // Build attribute list
        let attr_bstrs: Vec<BSTR> = attributes.iter().map(|a| BSTR::from(*a)).collect();
        let attr_ptrs: Vec<PCWSTR> = attr_bstrs.iter().map(|b| PCWSTR(b.as_ptr())).collect();

        // Execute search
        let filter_bstr = BSTR::from(filter);

        let search_handle = search.ExecuteSearch(
            PCWSTR(filter_bstr.as_ptr()),
            attr_ptrs.as_ptr(),
            attributes.len() as u32,
        )
        .map_err(|e| {
            let hresult = e.code().0 as u32;
            tracing::error!(
                base_dn = base_dn,
                filter = filter,
                error = %e,
                hresult = format!("0x{:08X}", hresult),
                "LDAP SEARCH FAILED: ExecuteSearch error"
            );
            AppError::LdapError(format!("Search execution failed: {} (HRESULT: 0x{:08X})", e, hresult))
        })?;

        let mut results = Vec::new();
        // Enterprise domains can have 100,000+ objects - set limit high enough
        // The ADSI paging (set above with PAGESIZE=1000) handles the actual pagination
        const MAX_RESULTS: usize = 500_000; // Safety limit for enterprise domains
        const LOG_INTERVAL: usize = 5000; // Log progress every N results

        // Iterate through results with safety limits
        let mut row_count = 0;
        loop {
            // Check if we've hit the safety limit
            if row_count >= MAX_RESULTS {
                tracing::warn!(
                    base_dn = base_dn,
                    limit = MAX_RESULTS,
                    "LDAP search hit result limit, stopping - this may indicate an issue"
                );
                break;
            }

            // Try to get next row
            let row_hr = search.GetNextRow(search_handle);
            if row_hr.is_err() || row_hr.0 as u32 == 0x00005012 {
                // S_ADS_NOMORE_ROWS or error - we're done
                break;
            }

            row_count += 1;

            // Log progress periodically for large queries
            if row_count % LOG_INTERVAL == 0 {
                tracing::info!(
                    base_dn = base_dn,
                    rows_processed = row_count,
                    "LDAP search in progress (large result set)..."
                );
            }

            let mut result = SearchResult::new();

            for attr in attributes {
                let attr_bstr = BSTR::from(*attr);
                let mut column: ADS_SEARCH_COLUMN = std::mem::zeroed();

                if search.GetColumn(search_handle, PCWSTR(attr_bstr.as_ptr()), &mut column).is_ok() {
                    let values = extract_column_values(&column);
                    if !values.is_empty() {
                        result.attributes.insert(attr.to_lowercase(), values);
                    }
                    if let Err(e) = search.FreeColumn(&mut column) {
                        tracing::warn!(attr = attr, error = %e, "Failed to free LDAP column");
                    }
                }
            }

            results.push(result);
        }

        if let Err(e) = search.CloseSearchHandle(search_handle) {
            tracing::warn!(error = %e, "Failed to close LDAP search handle");
        }
        tracing::info!(
            base_dn = base_dn,
            result_count = results.len(),
            "LDAP search completed"
        );
        Ok(results)
    }
}

/// Default range size for retrieving multi-valued attributes in AD
/// AD's default MaxValRange is typically 1500
const AD_RANGE_SIZE: usize = 1500;

/// LDAP search scope
#[derive(Debug, Clone, Copy)]
pub enum SearchScope {
    Base,
    OneLevel,
    Subtree,
}

impl SearchScope {

    fn to_ads_scope(&self) -> i32 {
        match self {
            SearchScope::Base => ADS_SCOPE_BASE.0,
            SearchScope::OneLevel => ADS_SCOPE_ONELEVEL.0,
            SearchScope::Subtree => ADS_SCOPE_SUBTREE.0,
        }
    }
}

/// Extract values from an ADS_SEARCH_COLUMN

unsafe fn extract_column_values(column: &ADS_SEARCH_COLUMN) -> Vec<String> {
    let mut values = Vec::new();

    if column.pADsValues.is_null() || column.dwNumValues == 0 {
        return values;
    }

    for i in 0..column.dwNumValues as usize {
        let value = &*column.pADsValues.add(i);

        if let Some(s) = extract_adsvalue(value) {
            values.push(s);
        }
    }

    values
}

/// Extract a string from an ADSVALUE

unsafe fn extract_adsvalue(value: &ADSVALUE) -> Option<String> {
    match value.dwType {
        ADSTYPE_DN_STRING | ADSTYPE_CASE_EXACT_STRING | ADSTYPE_CASE_IGNORE_STRING
        | ADSTYPE_PRINTABLE_STRING | ADSTYPE_NUMERIC_STRING => {
            let ptr = value.Anonymous.CaseIgnoreString;
            if ptr.is_null() {
                return None;
            }
            let len = (0..).take_while(|&i| *ptr.add(i) != 0).count();
            let slice = std::slice::from_raw_parts(ptr, len);
            Some(String::from_utf16_lossy(slice))
        }
        ADSTYPE_BOOLEAN => {
            Some(if value.Anonymous.Boolean != 0 { "TRUE" } else { "FALSE" }.to_string())
        }
        ADSTYPE_INTEGER => {
            Some(value.Anonymous.Integer.to_string())
        }
        ADSTYPE_LARGE_INTEGER => {
            // LargeInteger is now i64 directly in windows 0.59
            let val = value.Anonymous.LargeInteger;
            Some(val.to_string())
        }
        ADSTYPE_UTC_TIME => {
            let st = &value.Anonymous.UTCTime;
            Some(format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
            ))
        }
        _ => None,
    }
}

/// Convert a search result to a TierMember
pub fn search_result_to_tier_member(result: &SearchResult, tier: Option<Tier>) -> Option<TierMember> {
    let name = result.get("name")?.clone();
    let sam = result.get("samaccountname")?.clone();
    let dn = result.get("distinguishedname")?.clone();

    // Determine object type from objectClass
    let object_classes = result.get_all("objectclass").cloned().unwrap_or_default();
    let object_type = determine_object_type(&object_classes, &dn);

    // Get userAccountControl for enabled/disabled status
    let uac: u32 = result.get("useraccountcontrol")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let enabled = (uac & 0x2) == 0; // ACCOUNTDISABLE flag

    // Parse lastLogonTimestamp (Windows FILETIME)
    let last_logon = result.get("lastlogontimestamp")
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|ft| filetime_to_iso8601(ft));

    // Get description
    let description = result.get("description").cloned();

    // Get OS for computers
    let operating_system = result.get("operatingsystem").cloned();

    // Get member count for groups
    let member_count = result.get_all("member").map(|v| v.len());

    // Detect Tier 0 role type
    let role_type = detect_tier0_role(result, &dn);

    Some(TierMember {
        name,
        sam_account_name: sam,
        object_type,
        tier,
        enabled,
        last_logon,
        distinguished_name: dn,
        description,
        operating_system,
        role_type,
        member_count,
    })
}

/// Determine ObjectType from objectClass list
fn determine_object_type(object_classes: &[String], dn: &str) -> ObjectType {
    let classes_lower: Vec<String> = object_classes.iter().map(|s| s.to_lowercase()).collect();

    if classes_lower.contains(&"computer".to_string()) {
        // Check if it's a PAW/AdminWorkstation
        let dn_lower = dn.to_lowercase();
        if dn_lower.contains("adminworkstation") || dn_lower.contains("paw") {
            ObjectType::AdminWorkstation
        } else {
            ObjectType::Computer
        }
    } else if classes_lower.contains(&"group".to_string()) {
        ObjectType::Group
    } else if classes_lower.contains(&"user".to_string()) {
        // Check if it's a service account
        let dn_lower = dn.to_lowercase();
        if dn_lower.contains("serviceaccount") || dn_lower.contains("ou=service") {
            ObjectType::ServiceAccount
        } else {
            ObjectType::User
        }
    } else {
        ObjectType::Computer // Default
    }
}

/// Detect Tier 0 role type from search result
fn detect_tier0_role(result: &SearchResult, dn: &str) -> Option<Tier0RoleType> {
    let dn_lower = dn.to_lowercase();

    // Domain Controller - in Domain Controllers OU
    if dn_lower.contains("ou=domain controllers") {
        return Some(Tier0RoleType::DomainController);
    }

    // Check SPNs for ADFS
    if let Some(spns) = result.get_all("serviceprincipalname") {
        for spn in spns {
            let spn_lower = spn.to_lowercase();
            if spn_lower.contains("http/sts") || spn_lower.contains("http/adfs") {
                return Some(Tier0RoleType::ADFS);
            }
        }
    }

    // Check description for Entra Connect / Azure AD Connect
    if let Some(desc) = result.get("description") {
        let desc_lower = desc.to_lowercase();
        if desc_lower.contains("azure ad connect")
            || desc_lower.contains("aad connect")
            || desc_lower.contains("entra connect")
        {
            return Some(Tier0RoleType::EntraConnect);
        }
        if desc_lower.contains("certificate authority") || desc_lower.contains("ca server") {
            return Some(Tier0RoleType::CertificateAuthority);
        }
    }

    // Check name for PAW
    if let Some(name) = result.get("name") {
        let name_lower = name.to_lowercase();
        if name_lower.contains("paw") || name_lower.contains("privileged access") {
            return Some(Tier0RoleType::PAW);
        }
    }

    None
}

/// Convert Windows FILETIME to ISO 8601 string
fn filetime_to_iso8601(filetime: i64) -> Option<String> {
    if filetime <= 0 {
        return None;
    }

    // Windows FILETIME is 100-nanosecond intervals since January 1, 1601
    // Unix epoch is January 1, 1970
    // Difference is 11644473600 seconds
    const FILETIME_UNIX_DIFF: i64 = 11644473600;

    let seconds_since_1601 = filetime / 10_000_000;
    let unix_timestamp = seconds_since_1601 - FILETIME_UNIX_DIFF;

    if unix_timestamp < 0 {
        return None;
    }

    // Convert to datetime
    let datetime = chrono::DateTime::from_timestamp(unix_timestamp, 0)?;
    Some(datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Convert search result to Tier0Component
pub fn search_result_to_tier0_component(result: &SearchResult, domain_dn: &str) -> Option<Tier0Component> {
    let name = result.get("name")?.clone();
    let dn = result.get("distinguishedname")?.clone();

    let role_type = detect_tier0_role(result, &dn)?;

    let operating_system = result.get("operatingsystem").cloned();

    let last_logon = result.get("lastlogontimestamp")
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|ft| filetime_to_iso8601(ft));

    let description = result.get("description").cloned();

    // Extract current OU from DN
    let current_ou = dn
        .split(',')
        .skip(1)
        .collect::<Vec<_>>()
        .join(",");

    // Check if in Tier0 OU
    let tier0_ou = format!("OU=Tier0,{}", domain_dn).to_lowercase();
    let is_in_tier0 = dn.to_lowercase().contains(&tier0_ou)
        || dn.to_lowercase().contains("ou=domain controllers");

    Some(Tier0Component {
        name,
        role_type,
        operating_system,
        last_logon,
        current_ou,
        is_in_tier0,
        distinguished_name: dn,
        description,
    })
}

/// Get all objects in a tier OU
pub fn get_tier_objects(domain_dn: &str, tier: Option<Tier>) -> AppResult<Vec<TierMember>> {
    tracing::debug!(tier = ?tier, domain_dn = domain_dn, "Getting tier objects");
    let base_dn = match tier {
        Some(t) => format!("{},{}", t.ou_path(), domain_dn),
        None => domain_dn.to_string(), // Search whole domain for unassigned
    };

    let filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group))";
    let attributes = [
        "name",
        "sAMAccountName",
        "distinguishedName",
        "objectClass",
        "userAccountControl",
        "lastLogonTimestamp",
        "description",
        "operatingSystem",
        "servicePrincipalName",
        "member",
    ];

    let results = ldap_search(&base_dn, filter, &attributes, SearchScope::Subtree)?;

    let mut members: Vec<TierMember> = results
        .iter()
        .filter_map(|r| search_result_to_tier_member(r, tier))
        .collect();

    // For unassigned, filter out objects that ARE in tier OUs
    if tier.is_none() {
        let tier_ous: Vec<String> = Tier::all()
            .iter()
            .map(|t| format!("{},{}", t.ou_path(), domain_dn).to_lowercase())
            .collect();

        members.retain(|m| {
            let dn_lower = m.distinguished_name.to_lowercase();
            !tier_ous.iter().any(|ou| dn_lower.contains(ou))
        });
    }

    tracing::debug!(tier = ?tier, member_count = members.len(), "Retrieved tier objects");
    Ok(members)
}

/// Discover FSMO role holders
fn discover_fsmo_roles(domain_dn: &str) -> Vec<Tier0Component> {
    let mut fsmo_components = Vec::new();

    // Extract forest root DN (for schema and domain naming masters)
    // For simplicity, we'll use the current domain - in a real forest you'd query the root
    let config_dn = format!("CN=Configuration,{}", domain_dn);

    // FSMO role locations and their role types
    let fsmo_queries = [
        // Domain-level FSMO roles
        (domain_dn.to_string(), "fSMORoleOwner", Tier0RoleType::PDCEmulator, "PDC Emulator"),
        (format!("CN=RID Manager$,CN=System,{}", domain_dn), "fSMORoleOwner", Tier0RoleType::RIDMaster, "RID Master"),
        (format!("CN=Infrastructure,{}", domain_dn), "fSMORoleOwner", Tier0RoleType::InfrastructureMaster, "Infrastructure Master"),
        // Forest-level FSMO roles (in Configuration)
        (format!("CN=Schema,{}", config_dn), "fSMORoleOwner", Tier0RoleType::SchemaMaster, "Schema Master"),
        (format!("CN=Partitions,{}", config_dn), "fSMORoleOwner", Tier0RoleType::DomainNamingMaster, "Domain Naming Master"),
    ];

    for (base_dn, attr, role_type, role_name) in fsmo_queries {
        // Query the container to get the fSMORoleOwner attribute
        if let Ok(results) = ldap_search(
            &base_dn,
            "(objectClass=*)",
            &[attr, "distinguishedName"],
            SearchScope::Base,
        ) {
            if let Some(result) = results.first() {
                if let Some(role_owner_dn) = result.get("fsmoroleowner") {
                    // The fSMORoleOwner points to the NTDS Settings object
                    // Extract the server name from the DN: CN=NTDS Settings,CN=SERVER,CN=Servers,...
                    if let Some(server_name) = extract_server_from_ntds_settings(role_owner_dn) {
                        // Now get the computer object for this server
                        let server_dn = format!("OU=Domain Controllers,{}", domain_dn);
                        if let Ok(server_results) = ldap_search(
                            &server_dn,
                            &format!("(&(objectClass=computer)(name={}))", escape_ldap_filter(&server_name)),
                            &["name", "distinguishedName", "operatingSystem", "lastLogonTimestamp", "description"],
                            SearchScope::OneLevel,
                        ) {
                            if let Some(server_result) = server_results.first() {
                                let name = server_result.get("name").cloned().unwrap_or_else(|| server_name.clone());
                                let dn = server_result.get("distinguishedname").cloned().unwrap_or_default();
                                let os = server_result.get("operatingsystem").cloned();
                                let last_logon = server_result.get("lastlogontimestamp")
                                    .and_then(|s| s.parse::<i64>().ok())
                                    .and_then(filetime_to_iso8601);

                                let current_ou = dn.split(',').skip(1).collect::<Vec<_>>().join(",");

                                fsmo_components.push(Tier0Component {
                                    name: format!("{} ({})", name, role_name),
                                    role_type,
                                    operating_system: os,
                                    last_logon,
                                    current_ou,
                                    is_in_tier0: true, // DCs are always in Tier 0
                                    distinguished_name: dn,
                                    description: Some(format!("FSMO Role: {}", role_name)),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    fsmo_components
}

/// Extract server name from NTDS Settings DN
/// Example: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=...
fn extract_server_from_ntds_settings(ntds_dn: &str) -> Option<String> {
    let parts: Vec<&str> = ntds_dn.split(',').collect();
    // The server name is the second CN after "CN=NTDS Settings"
    if parts.len() >= 2 && parts[0].to_lowercase().starts_with("cn=ntds settings") {
        if let Some(server_part) = parts.get(1) {
            if let Some(name) = server_part.strip_prefix("CN=").or_else(|| server_part.strip_prefix("cn=")) {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Discover Tier 0 infrastructure components
pub fn discover_tier0_infrastructure(domain_dn: &str) -> AppResult<Vec<Tier0Component>> {
    tracing::info!(domain_dn = domain_dn, "Discovering Tier 0 infrastructure components");
    let mut components = Vec::new();

    // 0. FSMO Role Holders
    tracing::debug!("Discovering FSMO role holders");
    let fsmo_components = discover_fsmo_roles(domain_dn);
    tracing::debug!(count = fsmo_components.len(), "Found FSMO role holders");
    components.extend(fsmo_components);

    // 1. Domain Controllers (in Domain Controllers OU)
    let dc_base = format!("OU=Domain Controllers,{}", domain_dn);
    let dc_results = match ldap_search(
        &dc_base,
        "(objectClass=computer)",
        &[
            "name",
            "distinguishedName",
            "operatingSystem",
            "lastLogonTimestamp",
            "description",
            "servicePrincipalName",
        ],
        SearchScope::OneLevel,
    ) {
        Ok(results) => {
            tracing::info!(count = results.len(), base = %dc_base, "Found Domain Controllers");
            results
        }
        Err(e) => {
            tracing::error!(error = %e, base = %dc_base, "FAILED to query Domain Controllers - this is a critical error");
            Vec::new()
        }
    };

    for result in dc_results {
        if let Some(comp) = search_result_to_tier0_component(&result, domain_dn) {
            components.push(comp);
        }
    }

    // 2. ADFS servers (computers with ADFS SPNs)
    let adfs_results = match ldap_search(
        domain_dn,
        "(&(objectClass=computer)(|(servicePrincipalName=*http/sts*)(servicePrincipalName=*http/adfs*)))",
        &[
            "name",
            "distinguishedName",
            "operatingSystem",
            "lastLogonTimestamp",
            "description",
            "servicePrincipalName",
        ],
        SearchScope::Subtree,
    ) {
        Ok(results) => {
            tracing::debug!(count = results.len(), "Found ADFS servers");
            results
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to query ADFS servers - continuing");
            Vec::new()
        }
    };

    for result in adfs_results {
        if let Some(comp) = search_result_to_tier0_component(&result, domain_dn) {
            // Avoid duplicates
            if !components.iter().any(|c| c.distinguished_name == comp.distinguished_name) {
                components.push(comp);
            }
        }
    }

    // 3. Entra Connect / Azure AD Connect servers
    let entra_results = match ldap_search(
        domain_dn,
        "(&(objectClass=computer)(|(description=*Azure AD Connect*)(description=*AAD Connect*)(description=*Entra Connect*)))",
        &[
            "name",
            "distinguishedName",
            "operatingSystem",
            "lastLogonTimestamp",
            "description",
            "servicePrincipalName",
        ],
        SearchScope::Subtree,
    ) {
        Ok(results) => {
            tracing::debug!(count = results.len(), "Found Entra Connect servers");
            results
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to query Entra Connect servers - continuing");
            Vec::new()
        }
    };

    for result in entra_results {
        if let Some(comp) = search_result_to_tier0_component(&result, domain_dn) {
            if !components.iter().any(|c| c.distinguished_name == comp.distinguished_name) {
                components.push(comp);
            }
        }
    }

    // 4. Certificate Authorities
    let ca_results = match ldap_search(
        domain_dn,
        "(&(objectClass=computer)(|(description=*Certificate Authority*)(description=*CA Server*)))",
        &[
            "name",
            "distinguishedName",
            "operatingSystem",
            "lastLogonTimestamp",
            "description",
            "servicePrincipalName",
        ],
        SearchScope::Subtree,
    ) {
        Ok(results) => {
            tracing::debug!(count = results.len(), "Found Certificate Authorities");
            results
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to query Certificate Authorities - continuing");
            Vec::new()
        }
    };

    for result in ca_results {
        if let Some(comp) = search_result_to_tier0_component(&result, domain_dn) {
            if !components.iter().any(|c| c.distinguished_name == comp.distinguished_name) {
                components.push(comp);
            }
        }
    }

    // 5. PAWs (Privileged Access Workstations)
    let paw_results = match ldap_search(
        domain_dn,
        "(&(objectClass=computer)(|(name=*PAW*)(description=*Privileged Access*)(description=*PAW*)))",
        &[
            "name",
            "distinguishedName",
            "operatingSystem",
            "lastLogonTimestamp",
            "description",
            "servicePrincipalName",
        ],
        SearchScope::Subtree,
    ) {
        Ok(results) => {
            tracing::debug!(count = results.len(), "Found PAWs");
            results
        }
        Err(e) => {
            tracing::warn!(error = %e, "Failed to query PAWs - continuing");
            Vec::new()
        }
    };

    for result in paw_results {
        if let Some(comp) = search_result_to_tier0_component(&result, domain_dn) {
            if !components.iter().any(|c| c.distinguished_name == comp.distinguished_name) {
                components.push(comp);
            }
        }
    }

    tracing::info!(
        total_components = components.len(),
        "Tier 0 infrastructure discovery complete"
    );
    Ok(components)
}

/// Get group memberships for an AD object (including nested/transitive memberships)
///
/// This function uses a hybrid approach for best performance and reliability:
/// 1. Reads the `memberOf` attribute directly from the object (fast, direct memberships)
/// 2. Uses LDAP_MATCHING_RULE_IN_CHAIN for transitive/nested group expansion (single query)
/// 3. Resolves the primary group from `primaryGroupID` attribute
/// 4. Batch fetches group details to avoid N+1 query patterns

pub fn get_object_group_memberships(
    object_dn: &str,
) -> crate::error::AppResult<Vec<crate::commands::tier_management::GroupMembership>> {
    let domain_dn = extract_domain_dn(object_dn);
    let mut all_group_dns: HashSet<String> = HashSet::new();

    tracing::debug!(object_dn = object_dn, "Getting group memberships for object");

    // Step 1: Query object for memberOf and primaryGroupID attributes directly
    let object_results = ldap_search(
        object_dn,
        "(objectClass=*)",
        &["memberOf", "primaryGroupID"],
        SearchScope::Base,
    )?;

    if let Some(result) = object_results.first() {
        // Get direct memberOf values
        if let Some(member_of_dns) = result.get_all("memberof") {
            tracing::debug!(count = member_of_dns.len(), "Found direct memberOf entries");
            for dn in member_of_dns {
                all_group_dns.insert(dn.clone());
            }
        }

        // Handle primary group (e.g., Domain Users)
        if let Some(rid) = result.get("primarygroupid") {
            tracing::debug!(rid = rid, "Found primaryGroupID, resolving primary group");
            if let Some(pg_dn) = resolve_primary_group(&domain_dn, rid) {
                tracing::debug!(primary_group_dn = %pg_dn, "Resolved primary group");
                all_group_dns.insert(pg_dn);
            }
        }
    }

    // Step 2: Get transitive/nested memberships using LDAP_MATCHING_RULE_IN_CHAIN
    // This single query finds ALL groups the object belongs to through any level of nesting
    let filter = format!(
        "(&(objectClass=group)(member:{}:={}))",
        LDAP_MATCHING_RULE_IN_CHAIN,
        escape_ldap_filter(object_dn)
    );

    tracing::debug!(filter = %filter, "Executing transitive group membership query");

    match ldap_search(
        &domain_dn,
        &filter,
        &["distinguishedName"],
        SearchScope::Subtree,
    ) {
        Ok(nested_results) => {
            tracing::debug!(count = nested_results.len(), "Found transitive group memberships");
            for result in nested_results {
                if let Some(dn) = result.get("distinguishedname") {
                    all_group_dns.insert(dn.clone());
                }
            }
        }
        Err(e) => {
            // Log but don't fail - we still have direct memberships
            tracing::warn!(error = %e, "Failed to get transitive memberships, using direct memberships only");
        }
    }

    tracing::info!(total_groups = all_group_dns.len(), "Total unique group memberships found");

    // Step 3: Batch fetch group details
    batch_get_group_details(&domain_dn, &all_group_dns)
}

/// Resolve primary group DN from a RID (Relative Identifier)
///
/// The primary group (e.g., "Domain Users") is not stored in memberOf but
/// in the primaryGroupID attribute as a RID. This function resolves the
/// RID to the full DN of the group.

fn resolve_primary_group(domain_dn: &str, rid_str: &str) -> Option<String> {
    let rid: u32 = match rid_str.parse() {
        Ok(r) => r,
        Err(_) => {
            tracing::warn!(rid = rid_str, "Failed to parse primaryGroupID as u32");
            return None;
        }
    };

    // Well-known RIDs - these are standard across all AD domains
    let group_name = match rid {
        512 => "Domain Admins",
        513 => "Domain Users",
        514 => "Domain Guests",
        515 => "Domain Computers",
        516 => "Domain Controllers",
        517 => "Cert Publishers",
        518 => "Schema Admins",
        519 => "Enterprise Admins",
        520 => "Group Policy Creator Owners",
        521 => "Read-only Domain Controllers",
        522 => "Cloneable Domain Controllers",
        553 => "RAS and IAS Servers",
        571 => "Allowed RODC Password Replication Group",
        572 => "Denied RODC Password Replication Group",
        _ => {
            // For custom groups, search by primaryGroupToken attribute
            tracing::debug!(rid = rid, "Searching for custom primary group by primaryGroupToken");
            let filter = format!("(&(objectClass=group)(primaryGroupToken={}))", rid);
            if let Ok(results) = ldap_search(domain_dn, &filter, &["distinguishedName"], SearchScope::Subtree) {
                return results.first().and_then(|r| r.get("distinguishedname")).cloned();
            }
            return None;
        }
    };

    // Search for well-known group by name
    let filter = format!("(&(objectClass=group)(sAMAccountName={}))", escape_ldap_filter(group_name));
    ldap_search(domain_dn, &filter, &["distinguishedName"], SearchScope::Subtree)
        .ok()
        .and_then(|r| r.first().and_then(|r| r.get("distinguishedname")).cloned())
}

/// Batch fetch group details from a set of group DNs
///
/// This reduces N+1 query patterns by fetching groups in batches
/// using OR filters.

/// Batch size for LDAP OR filter queries
/// Larger batches are more efficient but may hit LDAP filter size limits
const LDAP_BATCH_SIZE: usize = 100;
fn batch_get_group_details(
    domain_dn: &str,
    group_dns: &HashSet<String>,
) -> crate::error::AppResult<Vec<crate::commands::tier_management::GroupMembership>> {
    use crate::commands::tier_management::GroupMembership;

    if group_dns.is_empty() {
        return Ok(Vec::new());
    }

    let mut all_memberships = Vec::new();
    let dns_vec: Vec<_> = group_dns.iter().collect();
    let total_batches = (dns_vec.len() + LDAP_BATCH_SIZE - 1) / LDAP_BATCH_SIZE;

    tracing::debug!(
        total_groups = dns_vec.len(),
        batch_size = LDAP_BATCH_SIZE,
        total_batches = total_batches,
        "Starting batch group details fetch"
    );

    // Process in batches to avoid LDAP filter size limits
    for (batch_idx, chunk) in dns_vec.chunks(LDAP_BATCH_SIZE).enumerate() {
        if batch_idx > 0 && batch_idx % 10 == 0 {
            tracing::debug!(
                batch = batch_idx,
                total_batches = total_batches,
                groups_fetched = all_memberships.len(),
                "Batch progress..."
            );
        }

        let filter_parts: Vec<String> = chunk
            .iter()
            .map(|dn| format!("(distinguishedName={})", escape_ldap_filter(dn)))
            .collect();

        let filter = format!("(&(objectClass=group)(|{}))", filter_parts.join(""));

        match ldap_search(
            domain_dn,
            &filter,
            &["name", "distinguishedName", "groupType"],
            SearchScope::Subtree,
        ) {
            Ok(results) => {
                for result in results {
                    if let (Some(name), Some(dn)) = (result.get("name"), result.get("distinguishedname")) {
                        let tier = determine_tier_from_group(dn, name);
                        let group_type = parse_group_type_string(result.get("grouptype"));

                        all_memberships.push(GroupMembership {
                            group_name: name.clone(),
                            group_dn: dn.clone(),
                            tier,
                            group_type,
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    chunk_size = chunk.len(),
                    batch = batch_idx,
                    "Failed to fetch group batch, continuing"
                );
            }
        }
    }

    tracing::info!(
        total_groups = all_memberships.len(),
        "Completed batch group details fetch"
    );

    Ok(all_memberships)
}

/// Determine tier from group DN and name
///
/// Checks both the OU path and naming conventions to determine
/// which tier a group belongs to.
fn determine_tier_from_group(group_dn: &str, group_name: &str) -> Option<String> {
    let dn_lower = group_dn.to_lowercase();
    let name_lower = group_name.to_lowercase();

    // Check OU path first (most reliable)
    if dn_lower.contains("ou=tier0") || name_lower.starts_with("tier0-") {
        Some("Tier0".to_string())
    } else if dn_lower.contains("ou=tier1") || name_lower.starts_with("tier1-") {
        Some("Tier1".to_string())
    } else if dn_lower.contains("ou=tier2") || name_lower.starts_with("tier2-") {
        Some("Tier2".to_string())
    } else {
        None
    }
}

/// Parse group type integer to human-readable string
///
/// The groupType attribute is a bitmask:
/// - Bit 31 (sign bit): Security group if negative, Distribution if positive
/// - Bits 0-3: Scope (2=Global, 4=Domain Local, 8=Universal)
fn parse_group_type_string(group_type_str: Option<&String>) -> String {
    let val: i32 = group_type_str.and_then(|s| s.parse().ok()).unwrap_or(0);

    // Security groups have negative groupType values (bit 31 set)
    let is_security = val < 0;

    // Scope is in lower bits
    let scope = if (val.abs() & 0x2) != 0 {
        "Global"
    } else if (val.abs() & 0x4) != 0 {
        "Domain Local"
    } else if (val.abs() & 0x8) != 0 {
        "Universal"
    } else {
        "Global" // Default
    };

    format!("{} {}", scope, if is_security { "Security" } else { "Distribution" })
}

/// Group member information
#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GroupMemberInfo {
    pub name: String,
    pub sam_account_name: String,
    pub distinguished_name: String,
    pub object_type: String,
    pub enabled: bool,
}

/// Get members of a specific group
///
/// # Arguments
/// * `group_dn` - The distinguished name of the group
/// * `include_nested` - If true, includes members from nested groups (transitive)
///
/// When `include_nested` is true, uses LDAP_MATCHING_RULE_IN_CHAIN for a single
/// efficient query that finds all transitive members.

pub fn get_group_members(group_dn: &str, include_nested: bool) -> crate::error::AppResult<Vec<GroupMemberInfo>> {
    let domain_dn = extract_domain_dn(group_dn);

    tracing::debug!(group_dn = group_dn, include_nested = include_nested, "Getting group members");

    if include_nested {
        // Use LDAP_MATCHING_RULE_IN_CHAIN for transitive members
        // This single query finds ALL objects that are members through any level of nesting
        let filter = format!(
            "(memberOf:{}:={})",
            LDAP_MATCHING_RULE_IN_CHAIN,
            escape_ldap_filter(group_dn)
        );

        tracing::debug!(filter = %filter, "Executing transitive member query");

        let results = ldap_search(
            &domain_dn,
            &filter,
            &["name", "sAMAccountName", "distinguishedName", "objectClass", "userAccountControl"],
            SearchScope::Subtree,
        )?;

        tracing::debug!(count = results.len(), "Found transitive members");

        Ok(results.iter().filter_map(parse_member_info).collect())
    } else {
        // Direct members only - read member attribute and batch fetch details
        get_group_members_direct(group_dn, &domain_dn)
    }
}

/// Get direct members of a group (no nested expansion)
///
/// Uses ranged retrieval for large groups (>1500 members) to handle
/// AD's MaxValRange limit on multi-valued attributes.

fn get_group_members_direct(group_dn: &str, domain_dn: &str) -> crate::error::AppResult<Vec<GroupMemberInfo>> {
    // Get all member DNs using ranged retrieval for large groups
    let member_dns = get_group_member_dns_with_range(group_dn)?;

    if member_dns.is_empty() {
        return Ok(Vec::new());
    }

    tracing::info!(
        group_dn = group_dn,
        member_count = member_dns.len(),
        "Retrieved group member DNs, batch fetching details"
    );

    // Batch fetch member details to avoid N+1 queries
    // Use larger batches (100) for enterprise efficiency
    let mut members = Vec::new();
    let total_batches = (member_dns.len() + 99) / 100;

    for (batch_idx, chunk) in member_dns.chunks(100).enumerate() {
        if batch_idx > 0 && batch_idx % 10 == 0 {
            tracing::debug!(
                batch = batch_idx,
                total_batches = total_batches,
                members_fetched = members.len(),
                "Fetching member details..."
            );
        }

        let filter_parts: Vec<String> = chunk
            .iter()
            .map(|dn| format!("(distinguishedName={})", escape_ldap_filter(dn)))
            .collect();

        let filter = format!("(|{})", filter_parts.join(""));

        match ldap_search(
            domain_dn,
            &filter,
            &["name", "sAMAccountName", "distinguishedName", "objectClass", "userAccountControl"],
            SearchScope::Subtree,
        ) {
            Ok(results) => {
                for result in &results {
                    if let Some(member) = parse_member_info(result) {
                        members.push(member);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    chunk_size = chunk.len(),
                    batch = batch_idx,
                    "Failed to fetch member batch, continuing"
                );
            }
        }
    }

    tracing::info!(
        group_dn = group_dn,
        total_members = members.len(),
        "Completed fetching group member details"
    );

    Ok(members)
}

/// Get all member DNs from a group using ranged retrieval
///
/// Active Directory limits multi-valued attributes to MaxValRange (typically 1500).
/// For groups with more members, we must use ranged retrieval:
/// - First request: `member;range=0-1499`
/// - Second request: `member;range=1500-2999`
/// - Continue until AD returns `member;range=N-*` (asterisk indicates end)

fn get_group_member_dns_with_range(group_dn: &str) -> crate::error::AppResult<Vec<String>> {
    let mut all_members = Vec::new();
    let mut range_start: usize = 0;
    let range_size = AD_RANGE_SIZE;
    let mut more_members = true;

    tracing::debug!(group_dn = group_dn, "Starting ranged retrieval of group members");

    while more_members {
        let range_end = range_start + range_size - 1;
        let range_attr = format!("member;range={}-{}", range_start, range_end);

        // Try to get members in this range
        let results = ldap_search(
            group_dn,
            "(objectClass=group)",
            &[&range_attr],
            SearchScope::Base,
        )?;

        if let Some(result) = results.first() {
            // Check for members in the ranged attribute
            // The returned attribute name may be "member;range=0-1499" or "member;range=0-*"
            let mut found_members = false;

            for (attr_name, values) in &result.attributes {
                // Check if this is a member range attribute
                if attr_name.starts_with("member;range=") || attr_name == "member" {
                    if !values.is_empty() {
                        found_members = true;
                        all_members.extend(values.clone());

                        // Check if this is the final range (contains "*")
                        if attr_name.contains("-*") || attr_name == "member" {
                            more_members = false;
                        }

                        tracing::debug!(
                            range_attr = attr_name,
                            count = values.len(),
                            total = all_members.len(),
                            "Retrieved member range"
                        );
                    }
                    break;
                }
            }

            // If no members found in this range, we're done
            if !found_members {
                // Try without range for small groups
                if range_start == 0 {
                    if let Some(members) = result.get_all("member") {
                        all_members.extend(members.clone());
                    }
                }
                more_members = false;
            }
        } else {
            more_members = false;
        }

        range_start += range_size;

        // Safety limit to prevent infinite loops
        if range_start > 1_000_000 {
            tracing::warn!(
                group_dn = group_dn,
                members_so_far = all_members.len(),
                "Hit safety limit during ranged retrieval"
            );
            break;
        }
    }

    // If ranged retrieval didn't work, try regular member attribute
    if all_members.is_empty() {
        let results = ldap_search(
            group_dn,
            "(objectClass=group)",
            &["member"],
            SearchScope::Base,
        )?;

        if let Some(result) = results.first() {
            if let Some(members) = result.get_all("member") {
                all_members.extend(members.clone());
            }
        }
    }

    tracing::info!(
        group_dn = group_dn,
        total_members = all_members.len(),
        "Completed ranged retrieval of group members"
    );

    Ok(all_members)
}

/// Parse a search result into GroupMemberInfo
fn parse_member_info(result: &SearchResult) -> Option<GroupMemberInfo> {
    let name = result.get("name")?.clone();
    let sam = result.get("samaccountname")?.clone();
    let dn = result.get("distinguishedname")?.clone();

    let object_classes = result.get_all("objectclass").cloned().unwrap_or_default();
    let object_type = if object_classes.iter().any(|c| c.eq_ignore_ascii_case("computer")) {
        "Computer"
    } else if object_classes.iter().any(|c| c.eq_ignore_ascii_case("group")) {
        "Group"
    } else if object_classes.iter().any(|c| c.eq_ignore_ascii_case("user")) {
        "User"
    } else {
        "Unknown"
    }.to_string();

    let uac: u32 = result.get("useraccountcontrol")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let enabled = (uac & 0x2) == 0;

    Some(GroupMemberInfo {
        name,
        sam_account_name: sam,
        distinguished_name: dn,
        object_type,
        enabled,
    })
}

/// Escape special characters in LDAP filter values
///
/// Escapes characters that have special meaning in LDAP filters:
/// * `\` → `\5c`
/// * `*` → `\2a`
/// * `(` → `\28`
/// * `)` → `\29`
/// * `\0` → `\00`
pub fn escape_ldap_filter(value: &str) -> String {
    value
        .replace('\\', "\\5c")
        .replace('*', "\\2a")
        .replace('(', "\\28")
        .replace(')', "\\29")
        .replace('\0', "\\00")
}

/// Extract domain DN from an object DN
fn extract_domain_dn(object_dn: &str) -> String {
    // Find all DC= components and join them
    let dc_parts: Vec<&str> = object_dn
        .split(',')
        .filter(|part| part.trim().to_uppercase().starts_with("DC="))
        .collect();

    if dc_parts.is_empty() {
        object_dn.to_string()
    } else {
        dc_parts.join(",")
    }
}

/// Test AD connection and return detailed diagnostics

pub fn test_ad_connection(domain_dn: &str) -> AdDiagnostics {
    use crate::domain::Tier;

    let mut diagnostics = AdDiagnostics {
        domain_dn: domain_dn.to_string(),
        com_init_status: "Not attempted".to_string(),
        ldap_bind_status: "Not attempted".to_string(),
        ldap_search_status: "Not attempted".to_string(),
        objects_found: 0,
        error_code: None,
        error_message: None,
        steps_completed: Vec::new(),
        tier_ou_status: Vec::new(),
    };

    // SAFETY: This unsafe block performs diagnostic LDAP operations against Active Directory via ADSI/COM.
    // This is safe because:
    // 1. CoInitializeEx safely initializes COM for this thread (handles already-initialized case)
    // 2. ADsOpenObject binds to LDAP using secure authentication with current credentials
    // 3. path_bstr is a valid BSTR created from domain_dn string
    // 4. IDirectorySearch interface is properly obtained via COM QueryInterface
    // 5. ExecuteSearch, GetFirstRow use standard ADSI search patterns
    // 6. CloseSearchHandle releases the search handle when done
    // 7. All error conditions are captured in the diagnostics struct for reporting
    // 8. This is a read-only diagnostic function - no modifications are made
    // 9. COM reference counting is handled automatically by the windows crate
    unsafe {
        // Step 1: Initialize COM
        diagnostics.steps_completed.push("Attempting COM initialization...".to_string());
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let hr_code = hr.0 as u32;

        if hr.is_ok() {
            diagnostics.com_init_status = "OK (newly initialized)".to_string();
        } else if hr_code == 0x00000001 {
            diagnostics.com_init_status = "OK (already initialized - S_FALSE)".to_string();
        } else if hr_code == 0x80010106 {
            diagnostics.com_init_status = "OK (different threading model - RPC_E_CHANGED_MODE)".to_string();
        } else {
            diagnostics.com_init_status = format!("Failed with HRESULT: 0x{:08X}", hr_code);
            diagnostics.error_code = Some(format!("0x{:08X}", hr_code));
            diagnostics.error_message = Some("COM initialization failed".to_string());
            return diagnostics;
        }
        diagnostics.steps_completed.push(format!("COM init: {}", diagnostics.com_init_status));

        // Step 2: Try to bind to LDAP
        let ldap_path = format!("LDAP://{}", domain_dn);
        diagnostics.steps_completed.push(format!("Binding to: {}", ldap_path));

        let path_bstr = BSTR::from(ldap_path.as_str());
        let mut search: Option<IDirectorySearch> = None;

        let bind_result = ADsOpenObject(
            PCWSTR(path_bstr.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            ADS_SECURE_AUTHENTICATION,
            &<IDirectorySearch as Interface>::IID,
            &mut search as *mut _ as *mut *mut std::ffi::c_void,
        );

        if let Err(e) = bind_result {
            let hresult = e.code().0 as u32;
            diagnostics.ldap_bind_status = format!("FAILED - HRESULT: 0x{:08X}", hresult);
            diagnostics.error_code = Some(format!("0x{:08X}", hresult));
            diagnostics.error_message = Some(format!("ADsOpenObject failed: {}", e));
            diagnostics.steps_completed.push(format!("LDAP bind FAILED: {} (0x{:08X})", e, hresult));

            // Add helpful error interpretation
            let error_hint = match hresult {
                0x80070005 => "E_ACCESSDENIED - Check user permissions to read AD",
                0x80005000 => "E_ADS_BAD_PATHNAME - Invalid LDAP path format",
                0x8007203A => "LDAP_SERVER_DOWN - Cannot reach domain controller",
                0x80072020 => "LDAP_OPERATIONS_ERROR - Server-side error",
                0x80072030 => "LDAP_NO_SUCH_OBJECT - The DN does not exist",
                0x80072EE7 => "WININET_E_NAME_NOT_RESOLVED - DNS resolution failed",
                _ => "Unknown error - check HRESULT code",
            };
            diagnostics.steps_completed.push(format!("Error hint: {}", error_hint));
            return diagnostics;
        }

        diagnostics.ldap_bind_status = "OK".to_string();
        diagnostics.steps_completed.push("LDAP bind successful".to_string());

        let search = match search {
            Some(s) => s,
            None => {
                diagnostics.ldap_search_status = "FAILED - Search interface is null".to_string();
                diagnostics.error_message = Some("IDirectorySearch interface was null after successful bind".to_string());
                return diagnostics;
            }
        };

        // Step 3: Try a simple search
        diagnostics.steps_completed.push("Attempting LDAP search (BASE scope, limit 1)...".to_string());

        let filter = "(objectClass=domainDNS)";
        let filter_bstr = BSTR::from(filter);
        let attr_name = BSTR::from("name");
        let attrs = [PCWSTR(attr_name.as_ptr())];

        // Set search preferences for BASE scope (just the root object) with timeout and size limit
        let mut prefs = [
            ADS_SEARCHPREF_INFO {
                dwSearchPref: ADS_SEARCHPREF_SEARCH_SCOPE,
                vValue: ADSVALUE {
                    dwType: ADSTYPE_INTEGER,
                    Anonymous: ADSVALUE_0 {
                        Integer: ADS_SCOPE_BASE.0 as u32,
                    },
                },
                dwStatus: ADS_STATUS_S_OK,
            },
            ADS_SEARCHPREF_INFO {
                dwSearchPref: ADS_SEARCHPREF_SIZE_LIMIT,
                vValue: ADSVALUE {
                    dwType: ADSTYPE_INTEGER,
                    Anonymous: ADSVALUE_0 {
                        Integer: 1, // Only need 1 result
                    },
                },
                dwStatus: ADS_STATUS_S_OK,
            },
            ADS_SEARCHPREF_INFO {
                dwSearchPref: ADS_SEARCHPREF_TIMEOUT,
                vValue: ADSVALUE {
                    dwType: ADSTYPE_INTEGER,
                    Anonymous: ADSVALUE_0 {
                        Integer: 10, // 10 second timeout
                    },
                },
                dwStatus: ADS_STATUS_S_OK,
            },
        ];
        let pref_result = search.SetSearchPreference(prefs.as_mut_ptr(), prefs.len() as u32);
        if let Err(e) = pref_result {
            diagnostics.steps_completed.push(format!("Warning: SetSearchPreference failed: {}", e));
        }

        let search_result = search.ExecuteSearch(
            PCWSTR(filter_bstr.as_ptr()),
            attrs.as_ptr(),
            attrs.len() as u32,
        );

        match search_result {
            Ok(handle) => {
                diagnostics.steps_completed.push("ExecuteSearch succeeded, getting first row...".to_string());

                // Just try to get the first row with a hard limit
                let mut count = 0;
                const MAX_ROWS: usize = 5; // Hard limit to prevent infinite loop

                loop {
                    if count >= MAX_ROWS {
                        diagnostics.steps_completed.push(format!("Hit row limit ({}), stopping", MAX_ROWS));
                        break;
                    }

                    let first_row_hr = search.GetFirstRow(handle);
                    let first_row_code = first_row_hr.0 as u32;

                    // S_OK = 0, S_ADS_NOMORE_ROWS = 0x00005012
                    if first_row_hr.is_ok() {
                        count += 1;
                        // Try GetNextRow for subsequent rows
                        while count < MAX_ROWS {
                            let next_hr = search.GetNextRow(handle);
                            if next_hr.is_err() || next_hr.0 as u32 == 0x00005012 {
                                break;
                            }
                            count += 1;
                        }
                    } else if first_row_code != 0x00005012 {
                        // Not "no more rows", so it's an actual error
                        diagnostics.steps_completed.push(format!("GetFirstRow returned: 0x{:08X}", first_row_code));
                    }
                    break;
                }

                if let Err(e) = search.CloseSearchHandle(handle) {
                    tracing::warn!(error = %e, "Failed to close diagnostic search handle");
                }

                diagnostics.objects_found = count;
                diagnostics.ldap_search_status = format!("OK - found {} object(s)", count);
                diagnostics.steps_completed.push(format!("Search completed, found {} object(s)", count));
            }
            Err(e) => {
                let hresult = e.code().0 as u32;
                diagnostics.ldap_search_status = format!("FAILED - HRESULT: 0x{:08X}", hresult);
                diagnostics.error_code = Some(format!("0x{:08X}", hresult));
                diagnostics.error_message = Some(format!("ExecuteSearch failed: {}", e));
                diagnostics.steps_completed.push(format!("ExecuteSearch FAILED: {} (0x{:08X})", e, hresult));

                // Add helpful error interpretation
                let error_hint = match hresult {
                    0x80070005 => "E_ACCESSDENIED - Check user permissions",
                    0x8007200A => "LDAP_SIZELIMIT_EXCEEDED - Too many results",
                    0x8007200B => "LDAP_TIMELIMIT_EXCEEDED - Query timeout",
                    0x80072030 => "LDAP_NO_SUCH_OBJECT - Object not found",
                    _ => "Check HRESULT code for details",
                };
                diagnostics.steps_completed.push(format!("Error hint: {}", error_hint));
            }
        }
    }

    // Step 4: Test Tier OU queries
    diagnostics.steps_completed.push("Testing Tier OU queries...".to_string());

    for tier in Tier::all() {
        let ou_path = format!("{},{}", tier.ou_path(), domain_dn);
        let tier_name = format!("{:?}", tier);

        let status = match get_tier_objects(domain_dn, Some(*tier)) {
            Ok(objects) => TierOuStatus {
                tier: tier_name,
                ou_path,
                exists: true,
                object_count: objects.len(),
                error: None,
            },
            Err(e) => {
                let error_str = e.to_string();
                let exists = !error_str.contains("0x80072030"); // LDAP_NO_SUCH_OBJECT
                TierOuStatus {
                    tier: tier_name,
                    ou_path,
                    exists,
                    object_count: 0,
                    error: Some(error_str),
                }
            }
        };
        diagnostics.tier_ou_status.push(status);
    }

    // Also test "Unassigned" (entire domain search)
    let unassigned_status = match get_tier_objects(domain_dn, None) {
        Ok(objects) => TierOuStatus {
            tier: "Unassigned".to_string(),
            ou_path: domain_dn.to_string(),
            exists: true,
            object_count: objects.len(),
            error: None,
        },
        Err(e) => TierOuStatus {
            tier: "Unassigned".to_string(),
            ou_path: domain_dn.to_string(),
            exists: true,
            object_count: 0,
            error: Some(e.to_string()),
        },
    };
    diagnostics.tier_ou_status.push(unassigned_status);

    diagnostics.steps_completed.push("Tier OU tests completed".to_string());

    diagnostics
}
