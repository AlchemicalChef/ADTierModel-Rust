pub mod commands;
pub mod domain;
pub mod error;
pub mod infrastructure;
pub mod logging;

use commands::{
    add_to_tier_group, check_tier_initialization, create_admin_account, get_domain_info,
    get_expected_groups, get_expected_ou_structure, get_tier_counts, get_tier_members,
    get_tier0_infrastructure, initialize_ad_tier_model, move_object_to_tier, move_tier0_component,
    reconnect_ad, remove_from_tier_group, get_compliance_status, get_cross_tier_violations,
    get_object_groups, get_gpo_status, configure_tier_gpo, configure_all_gpos, delete_tier_gpo,
    bulk_disable_stale_accounts, harden_service_accounts,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize logging to ADTier.log in executable directory
    let _guard = logging::init_logging();

    tracing::info!("AD Tier Model application starting");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .invoke_handler(tauri::generate_handler![
            // Read operations
            get_domain_info,
            get_tier_counts,
            get_tier_members,
            get_tier0_infrastructure,
            get_object_groups,
            // Initialization
            check_tier_initialization,
            initialize_ad_tier_model,
            get_expected_ou_structure,
            get_expected_groups,
            // Connection management
            reconnect_ad,
            // Write operations
            move_object_to_tier,
            move_tier0_component,
            add_to_tier_group,
            remove_from_tier_group,
            // Compliance
            get_compliance_status,
            get_cross_tier_violations,
            // Account creation
            create_admin_account,
            // GPO Management
            get_gpo_status,
            configure_tier_gpo,
            configure_all_gpos,
            delete_tier_gpo,
            // Account Management
            bulk_disable_stale_accounts,
            harden_service_accounts,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
