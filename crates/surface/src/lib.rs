//! The generated auth surface.
//!
//! ```text
//! use auth { ... }  ->  AuthConfig  ->  AuthSurface  ->  routes | providers | UI
//! ```
//!
//! The application declares auth; the platform derives the standard surface.

pub mod inspect;
pub mod surface;

pub use inspect::{render_json, render_json_with, render_text};
pub use surface::{
    AgentOperation, AgentSurface, AuthFeature, AuthFeatures, AuthMethod, AuthOperation, AuthRoute,
    AuthSurface, AuthUiSurface, BindingModeSurface, BoundarySurface, ClaimSurface,
    ExperienceSurface, PrincipalSurfaceKind, ProviderSurface, UiScreenSurface,
};

#[cfg(test)]
mod tests {
    use appport_auth_mesh_dsl::{
        parse_auth_block, AuthExperienceCapability, AuthUiMode, AuthenticationAssurance,
        AuthenticationMethod, ExperienceRenderer, ExperienceState, UiScreen,
    };
    use appport_auth_mesh_providers::ConnectorStatus;

    use super::*;

    fn surface(src: &str) -> AuthSurface {
        AuthSurface::derive(&parse_auth_block(src).expect("valid declaration"))
    }

    #[test]
    fn derives_the_canonical_surface() {
        let surface = surface(
            r#"
use auth {
  providers = [google, github, email]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }
  agents = true
}
"#,
        );

        for path in [
            "/auth/login",
            "/auth/signup",
            "/auth/logout",
            "/auth/session",
            "/auth/providers",
            "/auth/tenant",
            "/auth/tenants",
            "/auth/agents",
            "/auth/delegations",
        ] {
            assert!(surface.exposes(path), "expected {path} in the surface");
        }

        assert!(!surface.route("/auth/login").unwrap().requires_session);
        assert!(surface.route("/auth/session").unwrap().requires_session);
        assert_eq!(
            surface
                .providers
                .iter()
                .map(|provider| provider.id.as_str())
                .collect::<Vec<_>>(),
            vec!["email", "github", "google"]
        );
        assert_eq!(
            surface
                .claims
                .iter()
                .map(|claim| claim.name.as_str())
                .collect::<Vec<_>>(),
            vec!["plan", "role"]
        );
        assert_eq!(
            surface
                .principals
                .iter()
                .map(|principal| principal.as_str())
                .collect::<Vec<_>>(),
            vec!["human", "agent", "service"]
        );
    }

    #[test]
    fn agent_surfaces_require_agents_to_be_declared() {
        let without = surface("use auth { providers = [local] tenant = true }");

        assert!(!without.features.agents);
        assert!(!without.features.delegation);
        assert!(!without.exposes("/auth/agents"));
        assert!(!without.exposes("/auth/delegations"));
        assert!(without.agents.is_none());
        assert!(without.ui.screen(UiScreen::Agents).is_none());
        assert_eq!(
            without
                .principals
                .iter()
                .map(|principal| principal.as_str())
                .collect::<Vec<_>>(),
            vec!["human", "service"]
        );

        let with = surface("use auth { providers = [local] tenant = true agents = true }");
        assert!(with.exposes("/auth/agents"));
        assert!(with.exposes("/auth/delegations"));
        assert!(with.agents.is_some());
        assert!(with.ui.screen(UiScreen::Agents).is_some());
    }

    #[test]
    fn tenant_surfaces_require_tenancy_to_be_declared() {
        let single = surface("use auth { providers = [local] }");
        assert!(!single.exposes("/auth/tenant"));
        assert!(!single.exposes("/auth/tenants"));
        assert!(single.ui.screen(UiScreen::Tenant).is_none());
        // A single connector cannot link accounts to itself.
        assert!(!single.features.account_linking);
        assert!(!single.exposes("/auth/account/links"));

        let linked = surface("use auth { providers = [local, google] }");
        assert!(linked.features.account_linking);
        assert!(linked.exposes("/auth/account/links"));
    }

    #[test]
    fn provider_surface_reports_real_support() {
        let surface = surface("use auth { providers = [local, google, github, email] }");

        assert_eq!(
            surface.provider("local").unwrap().status,
            ConnectorStatus::Supported
        );
        assert!(surface.provider("local").unwrap().is_actionable());
        for declared in ["google", "github", "email"] {
            assert_eq!(
                surface.provider(declared).unwrap().status,
                ConnectorStatus::Declared
            );
            assert!(!surface.provider(declared).unwrap().is_actionable());
        }

        // The default UI offers only connectors that can actually authenticate.
        assert_eq!(
            surface.ui.screen(UiScreen::Login).unwrap().providers,
            vec!["local".to_string()]
        );
    }

    #[test]
    fn ui_is_derived_from_the_same_contract() {
        let surface = surface(
            r#"
use auth {
  providers = [local]
  agents = true
  ui = {
    login = "custom"
    theme = "midnight"
  }
}
"#,
        );

        assert_eq!(surface.ui.mode, AuthUiMode::Custom);
        assert_eq!(surface.ui.theme, "midnight");
        assert_eq!(surface.ui.renderer, ExperienceRenderer::Generated);
        assert_eq!(
            surface.ui.screen(UiScreen::Login).unwrap().mode,
            AuthUiMode::Custom
        );
        assert_eq!(
            surface.ui.screen(UiScreen::Signup).unwrap().mode,
            AuthUiMode::Default
        );
    }

    #[test]
    fn experience_registry_separates_capability_method_and_renderer() {
        let surface = surface(
            r#"
use auth {
  providers = [local, google]
  tenant = true
  experience = {
    mfa = required
    passkeys = enabled
    devices = enabled
    profile = enabled
  }
  ui = {
    mode = "embedded"
  }
}
"#,
        );

        assert_eq!(surface.ui.renderer, ExperienceRenderer::Embedded);
        let mfa = surface
            .experiences
            .iter()
            .find(|experience| experience.id == AuthExperienceCapability::Mfa)
            .expect("mfa registry entry");
        assert_eq!(mfa.state, ExperienceState::Required);
        assert_eq!(mfa.authentication_methods, vec![AuthenticationMethod::Mfa]);
        assert_eq!(mfa.required_assurance, AuthenticationAssurance::Strong);
        assert!(surface.exposes("/auth/mfa"));
        assert!(surface.exposes("/auth/passkeys"));
        assert!(surface.exposes("/auth/devices"));
        assert!(surface.exposes("/auth/profile"));

        let sign_in = surface
            .experiences
            .iter()
            .find(|experience| experience.id == AuthExperienceCapability::SignIn)
            .unwrap();
        assert_eq!(
            sign_in.authentication_methods,
            vec![
                AuthenticationMethod::Password,
                AuthenticationMethod::ExternalIdentity
            ]
        );
        assert!(surface.provider("google").is_some());
    }

    #[test]
    fn disabled_experience_is_removed_from_the_protocol_surface() {
        let surface = surface(
            r#"
use auth {
  providers = [local]
  experience = {
    sign_in = disabled
    sign_up = enabled
    password_reset = disabled
  }
}
"#,
        );

        assert!(!surface.exposes("/auth/sign-in"));
        assert!(surface.exposes("/auth/signup"));
        assert!(!surface.exposes("/auth/password/reset"));
        let reset = surface
            .experiences
            .iter()
            .find(|experience| experience.id == AuthExperienceCapability::PasswordReset)
            .unwrap();
        assert_eq!(reset.state, ExperienceState::Disabled);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = surface(
            r#"
use auth {
  multi_tenant: true
  providers: [github, local]
  claims: {
    role: enum["admin","owner"]
  }
  isolation: "strict"
  agents: true
}
"#,
        );
        let b = surface(
            r#"
use auth {
  tenant = true
  providers = [local, github]
  claims = {
    role = enum["owner", "admin"]
  }
  agents = true
}
"#,
        );

        assert_eq!(a, b);
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(render_text(&a), render_text(&b));
        assert_eq!(render_json(&a), render_json(&b));

        let different = surface("use auth { tenant = true providers = [local, github] }");
        assert_ne!(a.fingerprint(), different.fingerprint());
    }

    #[test]
    fn inspection_shows_the_generated_contract() {
        let text = render_text(&surface(
            r#"
use auth {
  providers = [local, google, github, email]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }
  agents = true
}
"#,
        ));

        assert!(text.contains("Multi-tenant: yes"));
        assert!(text.contains("Isolation: strict"));
        assert!(text.contains("  ✓ local"));
        assert!(text.contains("  ○ google"));
        assert!(text.contains("  ○ github"));
        assert!(text.contains("  ○ email"));
        assert!(text.contains("  role: admin | member | owner"));
        assert!(text.contains("  plan: free | pro"));
        assert!(text.contains("Agents:\n  enabled"));
        assert!(text.contains("Delegation:\n  enabled"));
        for path in [
            "/auth/login",
            "/auth/signup",
            "/auth/logout",
            "/auth/session",
            "/auth/providers",
            "/auth/tenants",
            "/auth/agents",
            "/auth/delegations",
        ] {
            assert!(text.contains(path), "inspection should list {path}");
        }
    }
}
