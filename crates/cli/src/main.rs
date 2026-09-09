//! `authport` — inspect what a declaration generates, without running the app.

use std::process::ExitCode;

use appport_auth_mesh_cli::{run, Output};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(Output { text, .. }) => {
            print!("{}", text);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("authport: {}", err);
            ExitCode::FAILURE
        }
    }
}
