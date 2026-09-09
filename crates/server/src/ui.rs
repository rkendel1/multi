use appport_auth_mesh_dsl::{AuthUiMode, UiScreen};
use appport_auth_mesh_surface::AuthSurface;

/// The client library, served to the browser. It is the same file the JS
/// package ships, so there is one client implementation.
pub const CLIENT_JS: &str = include_str!("../../../clients/js/authport.js");

/// The default sign-in page, generated from the auth contract.
///
/// The provider buttons come from the same `AuthSurface` the runtime
/// authenticates against: there is one provider declaration, and this reads it
/// rather than repeating it.
pub fn render_sign_in(surface: &AuthSurface, tenants: &[String]) -> String {
    let providers = surface
        .ui
        .screen(UiScreen::Login)
        .map(|screen| screen.providers.clone())
        .unwrap_or_default();

    let provider_options = providers
        .iter()
        .map(|id| {
            let label = surface
                .provider(id)
                .map(|provider| provider.display_name.clone())
                .unwrap_or_else(|| id.clone());
            format!(
                "<option value=\"{}\">{}</option>",
                html_escape(id),
                html_escape(&label)
            )
        })
        .collect::<Vec<_>>()
        .join("\n        ");

    let unavailable = surface
        .providers
        .iter()
        .filter(|provider| !provider.is_actionable())
        .map(|provider| {
            format!(
                "<li class=\"muted\">{} — declared, not configured</li>",
                html_escape(&provider.display_name)
            )
        })
        .collect::<Vec<_>>()
        .join("\n      ");

    let tenant_options = tenants
        .iter()
        .map(|tenant| {
            format!(
                "<option value=\"{}\">{}</option>",
                html_escape(tenant),
                html_escape(tenant)
            )
        })
        .collect::<Vec<_>>()
        .join("\n        ");

    let tenant_field = if surface.multi_tenant {
        format!(
            "<label>Tenant\n        <select name=\"tenant\" id=\"tenant\">\n        {}\n        </select>\n      </label>",
            tenant_options
        )
    } else {
        format!(
            "<input type=\"hidden\" name=\"tenant\" id=\"tenant\" value=\"{}\">",
            html_escape(tenants.first().map(String::as_str).unwrap_or("default"))
        )
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in · AuthPort</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{ font: 15px/1.5 system-ui, sans-serif; margin: 0; display: grid; place-items: center; min-height: 100vh; }}
    main {{ width: min(26rem, 92vw); padding: 2rem; }}
    h1 {{ font-size: 1.25rem; margin: 0 0 0.25rem; }}
    p.sub {{ margin: 0 0 1.5rem; opacity: 0.7; }}
    label {{ display: block; margin-bottom: 0.75rem; font-weight: 600; }}
    input, select, button {{ width: 100%; padding: 0.6rem; margin-top: 0.25rem; font: inherit; box-sizing: border-box; }}
    button {{ margin-top: 1rem; cursor: pointer; font-weight: 600; }}
    ul {{ padding-left: 1.1rem; }}
    .muted {{ opacity: 0.6; }}
    #status {{ margin-top: 1rem; white-space: pre-wrap; }}
  </style>
</head>
<body>
  <main>
    <h1>Sign in</h1>
    <p class="sub">AuthPort · contract {fingerprint}</p>
    <form id="signin">
      {tenant_field}
      <label>Provider
        <select name="connector" id="connector">
        {provider_options}
        </select>
      </label>
      <label>Username
        <input name="username" id="username" autocomplete="username" required>
      </label>
      <label>Password
        <input name="password" id="password" type="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Sign in</button>
    </form>
    <ul>
      {unavailable}
    </ul>
    <pre id="status"></pre>
  </main>
  <script src="/authport/client.js"></script>
  <script>
    const auth = AuthPort.createAuthPort({{}});
    const status = document.getElementById("status");

    auth.subscribe((state) => {{
      if (state.auth.authenticated) {{
        status.textContent = JSON.stringify(state.auth, null, 2);
      }}
    }});
    auth.session().catch(() => {{}});

    document.getElementById("signin").addEventListener("submit", async (event) => {{
      event.preventDefault();
      const form = new FormData(event.target);
      try {{
        await auth.signIn(Object.fromEntries(form.entries()));
        status.textContent = JSON.stringify(auth.auth, null, 2);
      }} catch (error) {{
        status.textContent = "denied: " + (error.reason || error.message);
      }}
    }});
  </script>
</body>
</html>
"#,
        fingerprint = html_escape(&surface.contract_fingerprint),
        tenant_field = tenant_field,
        provider_options = provider_options,
        unavailable = unavailable,
    )
}

/// Whether the deployment serves the generated screen, or the application owns
/// it. Customization is a contract setting, not a fork of the runtime.
pub fn serves_default_screen(surface: &AuthSurface, screen: UiScreen) -> bool {
    surface
        .ui
        .screen(screen)
        .map(|entry| entry.mode == AuthUiMode::Default)
        .unwrap_or(false)
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
