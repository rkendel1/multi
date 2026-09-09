//! The inspection surface: the beginning of the Studio experience.
//!
//! An auth contract is inspectable as data, so what the platform generated is
//! reviewable in the same way as any other part of an application.

use std::path::PathBuf;

use appport_auth_mesh_dsl::{parse_auth_block, AuthConfig};
use appport_auth_mesh_providers::ConnectorRegistry;
use appport_auth_mesh_surface::{render_json, render_text, AuthSurface};

pub const USAGE: &str = "\
authport — inspect an AuthPort auth contract

USAGE:
    authport inspect [FILE] [--json]
    authport fingerprint [FILE]
    authport routes [FILE]
    authport providers [FILE]

FILE defaults to the first of appport.auth, appport.toml or auth.appport that
exists in the current directory.
";

/// Candidate declaration files, in the order they are tried.
pub const DEFAULT_FILES: &[&str] = &["appport.auth", "appport.toml", "auth.appport"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}

fn error(message: impl Into<String>) -> CliError {
    CliError {
        message: message.into(),
    }
}

pub fn run<I>(args: I) -> Result<Output, CliError>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    let mut command = None;
    let mut file: Option<PathBuf> = None;
    let mut json = false;

    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" | "help" => {
                return Ok(Output {
                    text: USAGE.to_string(),
                })
            }
            flag if flag.starts_with('-') => return Err(error(format!("unknown flag `{}`", flag))),
            value if command.is_none() => command = Some(value.to_string()),
            value if file.is_none() => file = Some(PathBuf::from(value)),
            value => return Err(error(format!("unexpected argument `{}`", value))),
        }
    }

    let command = command.unwrap_or_else(|| "inspect".to_string());
    let path = resolve_file(file)?;
    let source = std::fs::read_to_string(&path)
        .map_err(|err| error(format!("cannot read `{}`: {}", path.display(), err)))?;
    let config = parse_auth_block(&source)
        .map_err(|err| error(format!("{}: {}", path.display(), err.message)))?;

    let text = match command.as_str() {
        "inspect" => describe(&config, json),
        "fingerprint" => format!(
            "contract {}\nsurface  {}\n",
            config.fingerprint(),
            AuthSurface::derive(&config).fingerprint()
        ),
        "routes" => AuthSurface::derive(&config)
            .routes
            .iter()
            .map(|route| {
                let methods = route
                    .methods
                    .iter()
                    .map(|method| method.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{:<18} {}\n", methods, route.path)
            })
            .collect(),
        "providers" => describe_providers(&config)?,
        other => return Err(error(format!("unknown command `{}`\n\n{}", other, USAGE))),
    };

    Ok(Output { text })
}

fn describe(config: &AuthConfig, json: bool) -> String {
    let surface = AuthSurface::derive(config);
    if json {
        render_json(&surface)
    } else {
        render_text(&surface)
    }
}

/// Provider status comes from the connector registry the runtime would build,
/// so inspection cannot disagree with what actually happens at login.
fn describe_providers(config: &AuthConfig) -> Result<String, CliError> {
    let registry = ConnectorRegistry::from_config(config)
        .map_err(|err| error(format!("connector registry: {}", err)))?;

    Ok(registry
        .metadata()
        .iter()
        .map(|metadata| {
            format!(
                "{:<12} {:<16} {}\n",
                metadata.id,
                metadata.kind.as_str(),
                metadata.status.as_str()
            )
        })
        .collect())
}

fn resolve_file(file: Option<PathBuf>) -> Result<PathBuf, CliError> {
    if let Some(file) = file {
        return Ok(file);
    }
    for candidate in DEFAULT_FILES {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Ok(path);
        }
    }
    Err(error(format!(
        "no auth declaration found (looked for {})",
        DEFAULT_FILES.join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_declaration(dir: &std::path::Path, body: &str) -> PathBuf {
        let path = dir.join("appport.auth");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("authport-cli-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const DECLARATION: &str = r#"
use auth {
  providers = [local, google, github, email]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }
  agents = true
}
"#;

    fn run_with(args: &[&str]) -> Result<Output, CliError> {
        run(args.iter().map(|arg| arg.to_string()))
    }

    #[test]
    fn inspects_a_declaration_without_running_the_application() {
        let dir = temp_dir("inspect");
        let path = write_declaration(&dir, DECLARATION);

        let output = run_with(&["inspect", path.to_str().unwrap()]).unwrap();

        assert!(output.text.contains("Multi-tenant: yes"));
        assert!(output.text.contains("Isolation: strict"));
        assert!(output.text.contains("  ✓ local"));
        assert!(output.text.contains("  ○ google"));
        assert!(output.text.contains("  role: admin | member | owner"));
        assert!(output.text.contains("Agents:\n  enabled"));
        assert!(output.text.contains("Delegation:\n  enabled"));
        assert!(output.text.contains("/auth/delegations"));
    }

    #[test]
    fn renders_json_routes_providers_and_fingerprints() {
        let dir = temp_dir("formats");
        let path = write_declaration(&dir, DECLARATION);
        let file = path.to_str().unwrap();

        let json = run_with(&["inspect", file, "--json"]).unwrap().text;
        assert!(json.contains("\"surface_fingerprint\""));
        assert!(json.contains("\"path\": \"/auth/login\""));
        assert!(json.contains("\"agents\": true"));

        let routes = run_with(&["routes", file]).unwrap().text;
        assert!(routes.contains("POST               /auth/login"));

        let providers = run_with(&["providers", file]).unwrap().text;
        assert!(providers.contains("local        local            supported"));
        assert!(providers.contains("google       oauth            declared"));

        let fingerprint = run_with(&["fingerprint", file]).unwrap().text;
        assert!(fingerprint.starts_with("contract "));
        // Inspection is a pure function of the declaration.
        assert_eq!(fingerprint, run_with(&["fingerprint", file]).unwrap().text);
    }

    #[test]
    fn reports_problems_instead_of_guessing() {
        let dir = temp_dir("errors");
        let path = write_declaration(&dir, "use auth { providers = [pigeon] }");
        let file = path.to_str().unwrap();

        assert!(run_with(&["providers", file])
            .unwrap_err()
            .message
            .contains("unknown connector `pigeon`"));
        assert!(run_with(&["inspect", "does-not-exist.auth"])
            .unwrap_err()
            .message
            .contains("cannot read"));
        assert!(run_with(&["explode", file])
            .unwrap_err()
            .message
            .contains("unknown command"));
        assert!(run_with(&["--nope"])
            .unwrap_err()
            .message
            .contains("unknown flag"));
        assert!(run_with(&["--help"]).unwrap().text.contains("USAGE"));
    }
}
