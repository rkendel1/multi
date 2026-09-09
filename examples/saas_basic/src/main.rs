//! `saas_basic` — run the scenario, or serve the application.
//!
//! ```text
//! cargo run -p saas_basic            # both modes, side by side
//! cargo run -p saas_basic -- serve   # standalone AuthPort on a real socket
//! ```

use std::sync::Arc;

use appport_auth_mesh_server::{serve, AuthPortServer, UpstreamProxy};
use saas_basic::app::{router, Invoices};
use saas_basic::bootstrap::bootstrap_live;
use saas_basic::demo::{application_policy, PROXY_SECRET};

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => {
            let address = args.next().unwrap_or_else(|| "127.0.0.1:8787".to_string());
            if let Err(err) = run_server(&address) {
                eprintln!("saas_basic: {}", err);
                std::process::exit(1);
            }
        }
        Some("embedded") => {
            let address = args.next().unwrap_or_else(|| "127.0.0.1:8787".to_string());
            if let Err(err) = run_embedded(&address) {
                eprintln!("saas_basic: {}", err);
                std::process::exit(1);
            }
        }
        _ => match saas_basic::demo::run() {
            Ok(report) => print!("{}", report),
            Err(err) => {
                eprintln!("saas_basic: {} ({:?})", err.message, err.stage);
                std::process::exit(1);
            }
        },
    }
}

/// Standalone: AuthPort owns the socket, the application sits behind it.
fn run_server(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let deployment = bootstrap_live(appport_auth_mesh_boundary::BindingMode::Standalone)?;
    let invoices = Arc::new(Invoices::default());
    let upstream = serve(
        Arc::new(saas_basic::upstream::UpstreamApp::new(
            invoices,
            PROXY_SECRET,
        )),
        "127.0.0.1:0",
    )?;

    let proxy = UpstreamProxy::new(upstream.address(), application_policy(), PROXY_SECRET);
    let server = Arc::new(
        AuthPortServer::new(deployment.runtime.clone(), Arc::new(proxy))
            .with_tenants(&["acme", "globex"]),
    );
    let handle = serve(server, address)?;

    println!(
        "AuthPort (standalone) listening on http://{}",
        handle.address()
    );
    println!(
        "application (no auth code)  on http://{}",
        upstream.address()
    );
    println!(
        "sign in at http://{}/auth/login  (alice / alice-secret)",
        handle.address()
    );
    handle.wait();
    Ok(())
}

/// Embedded: one process, handlers bound behind the boundary.
fn run_embedded(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let deployment = bootstrap_live(appport_auth_mesh_boundary::BindingMode::Embedded)?;
    let server = Arc::new(
        AuthPortServer::new(
            deployment.runtime.clone(),
            Arc::new(router(deployment.invoices.clone())),
        )
        .with_tenants(&["acme", "globex"]),
    );
    let handle = serve(server, address)?;

    println!(
        "AuthPort (embedded) listening on http://{}",
        handle.address()
    );
    println!(
        "sign in at http://{}/auth/login  (alice / alice-secret)",
        handle.address()
    );
    handle.wait();
    Ok(())
}
