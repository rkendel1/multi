//! `authboundry` — inspect the application's authority boundary.

use std::process::ExitCode;

use appport_auth_mesh_cli::{run, Output};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(Output { text, .. }) => {
            print!("{}", text);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("authboundry: {}", err);
            ExitCode::FAILURE
        }
    }
}
