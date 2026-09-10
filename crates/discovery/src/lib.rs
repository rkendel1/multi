//! Framework-neutral application discovery for AuthPort adoption.
//!
//! Discovery is intentionally read-only: it inspects manifests and likely
//! entrypoints, but never runs package scripts or binaries.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationCandidate {
    pub root: PathBuf,
    pub name: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub package_manager: Option<String>,
    pub entrypoints: Vec<EntrypointCandidate>,
    pub servers: Vec<ServerCandidate>,
    pub routes: Vec<RouteCandidate>,
    pub providers: Vec<ProviderCandidate>,
    pub existing_authport: ExistingAuthPort,
    pub confidence: DiscoveryConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrypointCandidate {
    pub path: PathBuf,
    pub kind: EntrypointKind,
    pub confidence: DiscoveryConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntrypointKind {
    NodeScript,
    RustBinary,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCandidate {
    pub command: String,
    pub source: String,
    pub confidence: DiscoveryConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteCandidate {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCandidate {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryConfidence {
    Low,
    Medium,
    High,
}

impl DiscoveryConfidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExistingAuthPort {
    pub dependency: bool,
    pub initialization: bool,
    pub middleware: bool,
    pub configuration: bool,
    pub manifest: bool,
}

impl ExistingAuthPort {
    pub fn detected(&self) -> bool {
        self.dependency
            || self.initialization
            || self.middleware
            || self.configuration
            || self.manifest
    }
}

pub fn discover(root: impl AsRef<Path>) -> Option<ApplicationCandidate> {
    let root = root.as_ref();
    discover_node(root).or_else(|| discover_rust(root))
}

fn discover_node(root: &Path) -> Option<ApplicationCandidate> {
    let package = root.join("package.json");
    let package_json = fs::read_to_string(&package).ok()?;
    let entrypoints = node_entrypoints(root, &package_json);
    let files = readable_sources(root, &entrypoints);
    let framework = if package_json.contains("\"express\"")
        || files.iter().any(|(_, source)| source.contains("express()"))
    {
        Some("Express".to_string())
    } else {
        None
    };
    let mut routes = files
        .iter()
        .flat_map(|(_, source)| discover_js_routes(source))
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    Some(ApplicationCandidate {
        root: root.to_path_buf(),
        name: json_string_field(&package_json, "name"),
        language: Some("Node".to_string()),
        framework,
        package_manager: node_package_manager(root),
        entrypoints,
        servers: node_servers(&package_json),
        routes,
        providers: discover_providers(root, &files),
        existing_authport: existing_authport(root, &package_json, &files),
        confidence: DiscoveryConfidence::High,
    })
}

fn discover_rust(root: &Path) -> Option<ApplicationCandidate> {
    let manifest = root.join("Cargo.toml");
    let cargo = fs::read_to_string(&manifest).ok()?;
    let entrypoint = root.join("src").join("main.rs");
    let mut entrypoints = Vec::new();
    if entrypoint.exists() {
        entrypoints.push(EntrypointCandidate {
            path: entrypoint,
            kind: EntrypointKind::RustBinary,
            confidence: DiscoveryConfidence::High,
        });
    }
    let files = readable_sources(root, &entrypoints);
    Some(ApplicationCandidate {
        root: root.to_path_buf(),
        name: toml_name(&cargo),
        language: Some("Rust".to_string()),
        framework: None,
        package_manager: Some("cargo".to_string()),
        entrypoints,
        servers: vec![ServerCandidate {
            command: "cargo run".to_string(),
            source: "Cargo.toml".to_string(),
            confidence: DiscoveryConfidence::Medium,
        }],
        routes: Vec::new(),
        providers: discover_providers(root, &files),
        existing_authport: existing_authport(root, &cargo, &files),
        confidence: DiscoveryConfidence::Medium,
    })
}

fn node_entrypoints(root: &Path, package_json: &str) -> Vec<EntrypointCandidate> {
    let mut candidates = Vec::new();
    if let Some(main) = json_string_field(package_json, "main") {
        candidates.push(entrypoint(
            root.join(main),
            EntrypointKind::NodeScript,
            DiscoveryConfidence::High,
        ));
    }
    for path in [
        "src/server.ts",
        "src/server.js",
        "server.ts",
        "server.js",
        "src/index.ts",
        "src/index.js",
        "index.ts",
        "index.js",
        "app.js",
    ] {
        let path = root.join(path);
        if path.exists() && !candidates.iter().any(|candidate| candidate.path == path) {
            candidates.push(entrypoint(
                path,
                EntrypointKind::NodeScript,
                DiscoveryConfidence::Medium,
            ));
        }
    }
    candidates
}

fn entrypoint(
    path: PathBuf,
    kind: EntrypointKind,
    confidence: DiscoveryConfidence,
) -> EntrypointCandidate {
    EntrypointCandidate {
        path,
        kind,
        confidence,
    }
}

fn readable_sources(root: &Path, entrypoints: &[EntrypointCandidate]) -> Vec<(PathBuf, String)> {
    let mut files = entrypoints
        .iter()
        .filter_map(|candidate| {
            fs::read_to_string(&candidate.path)
                .ok()
                .map(|source| (candidate.path.clone(), source))
        })
        .collect::<Vec<_>>();
    for name in [".env", ".env.local"] {
        let path = root.join(name);
        if let Ok(source) = fs::read_to_string(&path) {
            files.push((path, source));
        }
    }
    files
}

fn node_package_manager(root: &Path) -> Option<String> {
    if root.join("pnpm-lock.yaml").exists() {
        Some("pnpm".to_string())
    } else if root.join("yarn.lock").exists() {
        Some("yarn".to_string())
    } else if root.join("package-lock.json").exists() {
        Some("npm".to_string())
    } else {
        Some("npm".to_string())
    }
}

fn node_servers(package_json: &str) -> Vec<ServerCandidate> {
    json_script(package_json, "start")
        .into_iter()
        .map(|command| ServerCandidate {
            command,
            source: "package.json scripts.start".to_string(),
            confidence: DiscoveryConfidence::High,
        })
        .collect()
}

fn existing_authport(root: &Path, manifest: &str, files: &[(PathBuf, String)]) -> ExistingAuthPort {
    ExistingAuthPort {
        dependency: manifest.contains("\"authport\"") || manifest.contains("appport-auth-mesh"),
        initialization: files.iter().any(|(_, source)| {
            source.contains("createAuthPort(") || source.contains("AuthPortRuntime::new")
        }),
        middleware: files.iter().any(|(_, source)| {
            source.contains("authport()")
                || source.contains("app.use(authport")
                || source.contains("AuthPortServer::new")
        }),
        configuration: [
            "authport.toml",
            "appport.auth",
            "appport.toml",
            "auth.appport",
        ]
        .iter()
        .any(|name| root.join(name).exists()),
        manifest: root.join(".authport").join("adoption.json").exists(),
    }
}

fn discover_providers(root: &Path, files: &[(PathBuf, String)]) -> Vec<ProviderCandidate> {
    let mut haystack = String::new();
    for (_, source) in files {
        haystack.push_str(source);
        haystack.push('\n');
    }
    for name in [".env", ".env.local"] {
        if let Ok(source) = fs::read_to_string(root.join(name)) {
            haystack.push_str(&source);
            haystack.push('\n');
        }
    }
    let mut providers = Vec::new();
    if haystack.contains("GOOGLE_CLIENT_ID") || haystack.contains("GOOGLE_CLIENT_SECRET") {
        providers.push(ProviderCandidate {
            id: "google".to_string(),
            display_name: "Google OAuth configuration".to_string(),
        });
    }
    if haystack.contains("GITHUB_CLIENT_ID") || haystack.contains("GITHUB_CLIENT_SECRET") {
        providers.push(ProviderCandidate {
            id: "github".to_string(),
            display_name: "GitHub OAuth configuration".to_string(),
        });
    }
    providers
}

fn discover_js_routes(source: &str) -> Vec<RouteCandidate> {
    let mut routes = Vec::new();
    for method in ["get", "post", "put", "patch", "delete"] {
        for needle in [format!(".{}('", method), format!(".{}(\"", method)] {
            let quote = needle.chars().last().unwrap();
            let mut rest = source;
            while let Some(index) = rest.find(&needle) {
                let after = &rest[index + needle.len()..];
                if let Some(end) = after.find(quote) {
                    let path = &after[..end];
                    if path.starts_with('/') {
                        routes.push(RouteCandidate {
                            method: method.to_ascii_uppercase(),
                            path: path.to_string(),
                        });
                    }
                    rest = &after[end + 1..];
                } else {
                    break;
                }
            }
        }
    }
    routes
}

fn json_string_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let after = json[json.find(&needle)? + needle.len()..].trim_start();
    let after = after.strip_prefix(':')?.trim_start();
    let after = after.strip_prefix('"')?;
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn json_script(json: &str, script: &str) -> Option<String> {
    let scripts = json.split("\"scripts\"").nth(1)?;
    json_string_field(scripts, script)
}

fn toml_name(toml: &str) -> Option<String> {
    toml.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("name")
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .map(str::trim)
            .and_then(|value| value.strip_prefix('"'))
            .and_then(|value| value.split('"').next())
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("authport-discovery-{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn discovers_express_without_running_scripts_or_exposing_secrets() {
        let dir = temp_dir("express");
        fs::write(
            dir.join("package.json"),
            r#"{"name":"shop","scripts":{"start":"node src/server.js"},"dependencies":{"express":"latest"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/server.js"),
            "const express = require('express');\nconst app = express();\napp.get('/health', handler);\napp.post(\"/invoices\", handler);\n",
        )
        .unwrap();
        fs::write(
            dir.join(".env"),
            "GOOGLE_CLIENT_ID=public\nGOOGLE_CLIENT_SECRET=super-secret\n",
        )
        .unwrap();

        let app = discover(&dir).expect("node app discovered");

        assert_eq!(app.name.as_deref(), Some("shop"));
        assert_eq!(app.framework.as_deref(), Some("Express"));
        assert_eq!(app.servers[0].command, "node src/server.js");
        assert!(app.routes.contains(&RouteCandidate {
            method: "GET".to_string(),
            path: "/health".to_string()
        }));
        assert_eq!(app.providers[0].id, "google");
        assert!(!app.providers[0].display_name.contains("super-secret"));
    }
}
