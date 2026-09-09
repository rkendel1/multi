use appport_auth_mesh_dsl::UiScreen;

use crate::surface::{AuthSurface, PrincipalSurfaceKind};

/// Render the derived surface for a developer.
///
/// This is the inspection view: it answers "what did my declaration actually
/// generate?" without running the application.
pub fn render_text(surface: &AuthSurface) -> String {
    let mut out = String::new();
    out.push_str("AuthPort · Auth\n");
    out.push_str("────────────────────────\n\n");

    out.push_str(&format!("Multi-tenant: {}\n", yes_no(surface.multi_tenant)));
    out.push_str(&format!("Isolation: {}\n", surface.isolation.as_str()));
    out.push_str(&format!("Contract: {}\n", surface.contract_fingerprint));
    out.push_str(&format!("Surface: {}\n", surface.fingerprint()));

    out.push_str("\nProviders:\n");
    for provider in &surface.providers {
        out.push_str(&format!("  {} {}\n", provider.marker(), provider.id));
    }

    out.push_str("\nClaims:\n");
    if surface.claims.is_empty() {
        out.push_str("  (none)\n");
    }
    for claim in &surface.claims {
        out.push_str(&format!("  {}: {}\n", claim.name, claim.kind.describe()));
    }

    out.push_str("\nPrincipals:\n");
    for principal in &surface.principals {
        out.push_str(&format!("  {}\n", principal.as_str()));
    }

    out.push_str("\nAgents:\n");
    out.push_str(&format!("  {}\n", enabled(surface.features.agents)));

    out.push_str("\nDelegation:\n");
    out.push_str(&format!("  {}\n", enabled(surface.features.delegation)));

    if let Some(agents) = &surface.agents {
        out.push_str("\nAgent operations:\n");
        for operation in &agents.operations {
            out.push_str(&format!("  {}\n", operation.as_str()));
        }
    }

    out.push_str("\nUI:\n");
    out.push_str(&format!("  mode: {}\n", surface.ui.mode.as_str()));
    out.push_str(&format!("  theme: {}\n", surface.ui.theme));
    for screen in &surface.ui.screens {
        let providers = if screen.providers.is_empty() {
            String::new()
        } else {
            format!(" [{}]", screen.providers.join(", "))
        };
        out.push_str(&format!(
            "  {}: {}{}\n",
            screen_label(&screen.screen),
            screen.mode.as_str(),
            providers
        ));
    }

    out.push_str("\nGenerated surfaces:\n");
    for route in &surface.routes {
        out.push_str(&format!("  {}\n", route.path));
    }

    out
}

fn screen_label(screen: &UiScreen) -> &'static str {
    screen.as_str()
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn enabled(value: bool) -> &'static str {
    if value {
        "enabled"
    } else {
        "disabled"
    }
}

/// A deterministic JSON rendering, for tooling that wants the surface as data.
pub fn render_json(surface: &AuthSurface) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!(
        "  \"contract_fingerprint\": \"{}\",\n",
        surface.contract_fingerprint
    ));
    out.push_str(&format!(
        "  \"surface_fingerprint\": \"{}\",\n",
        surface.fingerprint()
    ));
    out.push_str(&format!("  \"multi_tenant\": {},\n", surface.multi_tenant));
    out.push_str(&format!(
        "  \"isolation\": \"{}\",\n",
        surface.isolation.as_str()
    ));

    out.push_str("  \"features\": {\n");
    let features = crate::surface::AuthFeatures::all();
    for (index, feature) in features.iter().enumerate() {
        out.push_str(&format!(
            "    \"{}\": {}{}\n",
            feature.as_str(),
            surface.features.enabled(*feature),
            comma(index, features.len())
        ));
    }
    out.push_str("  },\n");

    out.push_str("  \"providers\": [\n");
    for (index, provider) in surface.providers.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"id\": \"{}\", \"display_name\": \"{}\", \"kind\": \"{}\", \"status\": \"{}\"}}{}\n",
            escape(&provider.id),
            escape(&provider.display_name),
            provider.kind.as_str(),
            provider.status.as_str(),
            comma(index, surface.providers.len())
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"claims\": [\n");
    for (index, claim) in surface.claims.iter().enumerate() {
        out.push_str(&format!(
            "    {{\"name\": \"{}\", \"kind\": \"{}\"}}{}\n",
            escape(&claim.name),
            escape(&claim.kind.describe()),
            comma(index, surface.claims.len())
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"principals\": [");
    out.push_str(
        &surface
            .principals
            .iter()
            .map(|principal: &PrincipalSurfaceKind| format!("\"{}\"", principal.as_str()))
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push_str("],\n");

    out.push_str("  \"routes\": [\n");
    for (index, route) in surface.routes.iter().enumerate() {
        let methods = route
            .methods
            .iter()
            .map(|method| format!("\"{}\"", method.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "    {{\"path\": \"{}\", \"methods\": [{}], \"operation\": \"{}\", \"requires_session\": {}, \"feature\": \"{}\"}}{}\n",
            escape(&route.path),
            methods,
            route.operation.as_str(),
            route.requires_session,
            route.feature.as_str(),
            comma(index, surface.routes.len())
        ));
    }
    out.push_str("  ],\n");

    out.push_str("  \"ui\": {\n");
    out.push_str(&format!(
        "    \"mode\": \"{}\",\n    \"theme\": \"{}\",\n    \"screens\": [\n",
        surface.ui.mode.as_str(),
        escape(&surface.ui.theme)
    ));
    for (index, screen) in surface.ui.screens.iter().enumerate() {
        let providers = screen
            .providers
            .iter()
            .map(|provider| format!("\"{}\"", escape(provider)))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "      {{\"screen\": \"{}\", \"mode\": \"{}\", \"providers\": [{}]}}{}\n",
            screen.screen.as_str(),
            screen.mode.as_str(),
            providers,
            comma(index, surface.ui.screens.len())
        ));
    }
    out.push_str("    ]\n  }");

    if let Some(agents) = &surface.agents {
        let operations = agents
            .operations
            .iter()
            .map(|operation| format!("\"{}\"", operation.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(",\n  \"agent_operations\": [{}]", operations));
    }

    out.push_str("\n}\n");
    out
}

fn comma(index: usize, len: usize) -> &'static str {
    if index + 1 == len {
        ""
    } else {
        ","
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
