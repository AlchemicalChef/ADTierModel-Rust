//! Active Directory search operations using Windows ADSI IDirectorySearch
//!
//! This module provides LDAP search functionality for querying AD objects.

use crate::domain::{ObjectType, Tier, Tier0RoleType, TierMember, Tier0Component};
use crate::error::{AppError, AppResult};
use std::collections::HashMap;
use serde::Serialize;

#[cfg(windows)]
use windows::{
    core::{BSTR, Interface, PCWSTR},
    Win32::Networking::ActiveDirectory::*,
    Win32::System::Com::*,
};

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(windows)]
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
#[cfg(windows)]
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
    unsafe {
        // Initialize COM - use MULTITHREADED for async compatibility
        // Handle the case where COM is already initialized
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        let hr_code = hr.0 as u32;
        if hr.is_ok() {
            tracing::trace!("COM initialized successfully");
        } else if hr_code == 0x00000001 {
            // S_FALSE means COM was already initialized, which is fine
            tracing::trace!("COM was already initialized");
        } else if hr_code == 0x80010106 {
            // RPC_E_CHANGED_MODE means it was initialized with different mode
            tracing::debug!("COM initialized with different threading model, continuing anyway");
        } else {
            tracing::warn!(hresult = format!("0x{:08X}", hr_code), "COM initialization returned unexpected result");
        }

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

        search.SetSearchPreference(prefs.as_mut_ptr(), prefs.len() as u32).ok();

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
        const MAX_RESULTS: usize = 10000; // Safety limit to prevent infinite loops
        const LOG_INTERVAL: usize = 500; // Log progress every N results

        // Iterate through results with safety limits
        let mut row_count = 0;
        loop {
            // Check if we've hit the safety limit
            if row_count >= MAX_RESULTS {
                tracing::warn!(
                    base_dn = base_dn,
                    limit = MAX_RESULTS,
                    "LDAP search hit result limit, stopping"
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

            // Log progress periodically
            if row_count % LOG_INTERVAL == 0 {
                tracing::info!(
                    base_dn = base_dn,
                    rows_processed = row_count,
                    "LDAP search in progress..."
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
                    search.FreeColumn(&mut column).ok();
                }
            }

            results.push(result);
        }

        search.CloseSearchHandle(search_handle).ok();
        tracing::info!(
            base_dn = base_dn,
            result_count = results.len(),
            "LDAP search completed"
        );
        Ok(results)
    }
}

/// LDAP search scope
#[derive(Debug, Clone, Copy)]
pub enum SearchScope {
    Base,
    OneLevel,
    Subtree,
}

impl SearchScope {
    #[cfg(windows)]
    fn to_ads_scope(&self) -> i32 {
        match self {
            SearchScope::Base => ADS_SCOPE_BASE.0,
            SearchScope::OneLevel => ADS_SCOPE_ONELEVEL.0,
            SearchScope::Subtree => ADS_SCOPE_SUBTREE.0,
        }
    }
}

/// Extract values from an ADS_SEARCH_COLUMN
#[cfg(windows)]
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
#[cfg(windows)]
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
                            &format!("(&(objectClass=computer)(name={}))", server_name),
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

/// Get group memberships for an AD object
#[cfg(windows)]
pub fn get_object_group_memberships(
    object_dn: &str,
) -> crate::error::AppResult<Vec<crate::commands::tier_management::GroupMembership>> {
    // TODO: Implement actual group membership lookup
    let _ = object_dn;
    Ok(vec![])
}

/// Test AD connection and return detailed diagnostics
#[cfg(windows)]
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

    unsafe {
        // Step 1: Initialize COM
        diagnostics.steps_completed.push("Attempting COM initialization...".to_string());
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
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

                let _ = search.CloseSearchHandle(handle);

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

/// Test AD connection (non-Windows stub)
#[cfg(not(windows))]
pub fn test_ad_connection(domain_dn: &str) -> AdDiagnostics {
    AdDiagnostics {
        domain_dn: domain_dn.to_string(),
        com_init_status: "N/A (not Windows)".to_string(),
        ldap_bind_status: "N/A (not Windows)".to_string(),
        ldap_search_status: "N/A (not Windows)".to_string(),
        objects_found: 0,
        error_code: None,
        error_message: Some("AD diagnostics only available on Windows".to_string()),
        steps_completed: vec!["Running on non-Windows platform".to_string()],
        tier_ou_status: Vec::new(),
    }
}
