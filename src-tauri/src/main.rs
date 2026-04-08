//! ZeroTrust Mesh - Main Entry Point

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;
use tracing::{info, error, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod commands;

fn setup_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(true))
        .with(filter)
        .init();
}

fn main() {
    setup_logging();
    info!("Starting ZeroTrust Mesh v{}", env!("CARGO_PKG_VERSION"));
    
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            // Initialize application state
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                match zerotrust_mesh_lib::init_app(None).await {
                    Ok(_) => info!("Application state initialized"),
                    Err(e) => error!("Failed to initialize application: {}", e),
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Identity commands
            commands::identity::register_service,
            commands::identity::deregister_service,
            commands::identity::list_services,
            commands::identity::get_service,
            commands::identity::issue_jwt_svid,
            commands::identity::verify_svid,
            
            // Policy commands
            commands::policy::create_policy,
            commands::policy::update_policy,
            commands::policy::delete_policy,
            commands::policy::list_policies,
            commands::policy::get_policy,
            commands::policy::evaluate_policy,
            commands::policy::toggle_policy,
            commands::policy::test_policy,
            
            // WireGuard commands
            commands::wireguard::create_tunnel,
            commands::wireguard::destroy_tunnel,
            commands::wireguard::list_tunnels,
            commands::wireguard::get_tunnel_status,
            
            // Attestation commands
            commands::attestation::get_trust_score,
            commands::attestation::list_trust_scores,
            commands::attestation::measure_binary,
            commands::attestation::get_tpm_status,
            
            // Attack detection commands
            commands::attacks::get_attack_stats,
            commands::attacks::get_recent_attacks,
            commands::attacks::blacklist_ip,
            commands::attacks::whitelist_ip,
            commands::attacks::get_blacklist,
            
            // Alert commands
            commands::alerts::get_alerts,
            commands::alerts::acknowledge_alert,
            commands::alerts::mute_alert_type,
            
            // Dashboard commands
            commands::dashboard::get_dashboard_data,
            commands::dashboard::get_service_topology,
            
            // Audit commands
            commands::audit::get_audit_logs,
            commands::audit::export_logs,
            
            // Config commands
            commands::config::get_config,
            commands::config::update_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ZeroTrust Mesh");
}
