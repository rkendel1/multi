use crate::{send_upstream, ApplicationUpstream, ClientRequest};
use appport_auth_mesh_boundary::{MailMessage, MailPort};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const PASSWORD_RESET_HTML: &str = include_str!("../../../templates/password-reset.html");
const PASSWORD_RESET_TEXT: &str = include_str!("../../../templates/password-reset.txt");
const EMAIL_VERIFICATION_HTML: &str = include_str!("../../../templates/email-verification.html");
const EMAIL_VERIFICATION_TEXT: &str = include_str!("../../../templates/email-verification.txt");

/// Zero-configuration development transport. Messages are captured under the
/// application's runtime-owned `.authboundry/mail` directory.
pub struct DevelopmentMailPort {
    directory: PathBuf,
    sequence: AtomicU64,
}

impl DevelopmentMailPort {
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            directory: directory.as_ref().to_path_buf(),
            sequence: AtomicU64::new(0),
        }
    }
}

impl MailPort for DevelopmentMailPort {
    fn send(&self, message: MailMessage) -> Result<(), String> {
        std::fs::create_dir_all(&self.directory).map_err(|error| error.to_string())?;
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_millis())
            .unwrap_or_default();
        let variables = message
            .variables
            .iter()
            .map(|(key, value)| format!("\"{}\":\"{}\"", escape(key), escape(value)))
            .collect::<Vec<_>>()
            .join(",");
        let contents = format!(
            "{{\"template\":\"{}\",\"identity\":\"{}\",\"to\":\"{}\",\"tenant\":\"{}\",\"variables\":{{{}}},\"idempotency_key\":\"{}\"}}\n",
            escape(&message.template), escape(&message.identity), escape(&message.to),
            escape(&message.tenant), variables, escape(&message.idempotency_key)
        );
        let stem = format!("{timestamp}-{sequence}-{}", message.template);
        std::fs::write(self.directory.join(format!("{stem}.json")), contents)
            .map_err(|error| error.to_string())?;
        let application_root = self.directory.parent().and_then(Path::parent);
        let file_stem = message.template.replace('_', "-");
        let bundled = match message.template.as_str() {
            "password_reset" => (PASSWORD_RESET_HTML, PASSWORD_RESET_TEXT),
            "email_verification" => (EMAIL_VERIFICATION_HTML, EMAIL_VERIFICATION_TEXT),
            _ => return Ok(()),
        };
        let load = |extension: &str, fallback: &str| {
            application_root
                .and_then(|root| {
                    std::fs::read_to_string(
                        root.join("emails").join(format!("{file_stem}.{extension}")),
                    )
                    .ok()
                })
                .unwrap_or_else(|| fallback.to_string())
        };
        let html = render_template(&load("html", bundled.0), &message.variables);
        let text = render_template(&load("txt", bundled.1), &message.variables);
        std::fs::write(self.directory.join(format!("{stem}.html")), html)
            .and_then(|_| std::fs::write(self.directory.join(format!("{stem}.txt")), text))
            .map_err(|error| error.to_string())
    }
}

fn render_template(
    template: &str,
    variables: &std::collections::HashMap<String, String>,
) -> String {
    let mut rendered = template.to_string();
    while let Some(start) = rendered.find("{{#if support_url}}") {
        let Some(relative_end) = rendered[start..].find("{{/if}}") else {
            break;
        };
        let end = start + relative_end + "{{/if}}".len();
        let inner_start = start + "{{#if support_url}}".len();
        let replacement = if variables
            .get("support_url")
            .is_some_and(|value| !value.is_empty())
        {
            rendered[inner_start..start + relative_end].to_string()
        } else {
            String::new()
        };
        rendered.replace_range(start..end, &replacement);
    }
    for (key, value) in variables {
        rendered = rendered.replace(&format!("{{{{ {key} }}}}"), value);
        rendered = rendered.replace(&format!("{{{{{key}}}}}"), value);
    }
    rendered
}

/// Adapter for MailPort's documented remote capability protocol.
pub struct RemoteMailPort {
    upstream: ApplicationUpstream,
    api_key: Option<String>,
}

impl RemoteMailPort {
    pub fn new(base_url: &str, api_key: Option<String>) -> Result<Self, String> {
        let trimmed = base_url.trim_end_matches('/');
        let normalized = if let Some(authority) = trimmed.strip_prefix("https://") {
            if authority.rsplit_once(':').is_none() {
                format!("https://{authority}:443")
            } else {
                trimmed.to_string()
            }
        } else if let Some(authority) = trimmed.strip_prefix("http://") {
            if authority.rsplit_once(':').is_none() {
                format!("http://{authority}:80")
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };
        Ok(Self {
            upstream: ApplicationUpstream::parse(&normalized)?,
            api_key,
        })
    }
}

impl MailPort for RemoteMailPort {
    fn send(&self, message: MailMessage) -> Result<(), String> {
        let request = self.request(message);
        let response = send_upstream(&self.upstream, &request).map_err(|error| error.message)?;
        if (200..300).contains(&response.status) {
            Ok(())
        } else {
            Err(format!(
                "MailPort rejected message with status {}",
                response.status
            ))
        }
    }
}

impl RemoteMailPort {
    fn request(&self, message: MailMessage) -> ClientRequest {
        let variables = message
            .variables
            .iter()
            .map(|(key, value)| format!("\"{}\":\"{}\"", escape(key), escape(value)))
            .collect::<Vec<_>>()
            .join(",");
        let body = format!("{{\"template\":\"{}\",\"payload\":{{\"identity\":\"{}\",\"to\":\"{}\",\"tenantId\":\"{}\",\"variables\":{{{}}},\"idempotencyKey\":\"{}\"}}}}", escape(&message.template), escape(&message.identity), escape(&message.to), escape(&message.tenant), variables, escape(&message.idempotency_key));
        let mut request = ClientRequest::post_json("/v1/messages", body);
        if let Some(key) = &self.api_key {
            request = request.with_header("authorization", format!("Bearer {key}"));
        }
        request
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn request_matches_mailports_remote_template_contract() {
        let port =
            RemoteMailPort::new("http://127.0.0.1:7798", Some("secret".to_string())).unwrap();
        let request = port.request(MailMessage {
            template: "password_reset".to_string(),
            identity: "auth".to_string(),
            to: "alice@example.com".to_string(),
            tenant: "acme".to_string(),
            variables: HashMap::from([("token".to_string(), "opaque".to_string())]),
            idempotency_key: "reset:one".to_string(),
        });
        assert_eq!(request.path, "/v1/messages");
        assert!(request
            .headers
            .contains(&("authorization".to_string(), "Bearer secret".to_string())));
        let body = String::from_utf8(request.body).unwrap();
        for expected in [
            "\"template\":\"password_reset\"",
            "\"identity\":\"auth\"",
            "\"to\":\"alice@example.com\"",
            "\"tenantId\":\"acme\"",
            "\"token\":\"opaque\"",
            "\"idempotencyKey\":\"reset:one\"",
        ] {
            assert!(body.contains(expected), "missing {expected} in {body}");
        }
    }

    #[test]
    fn development_mail_renders_bundled_html_and_text() {
        let root = std::env::temp_dir().join(format!("authboundry-mail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let port = DevelopmentMailPort::new(root.join(".authboundry/mail"));
        port.send(MailMessage {
            template: "email_verification".to_string(),
            identity: "auth".to_string(),
            to: "alice@example.com".to_string(),
            tenant: "development".to_string(),
            variables: HashMap::from([
                ("user.name".to_string(), "Alice".to_string()),
                (
                    "verification_url".to_string(),
                    "/verify?token=opaque".to_string(),
                ),
                ("expires_at".to_string(), "tomorrow".to_string()),
                ("support_url".to_string(), String::new()),
            ]),
            idempotency_key: "verification:test".to_string(),
        })
        .unwrap();
        let files = std::fs::read_dir(root.join(".authboundry/mail"))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        assert!(files
            .iter()
            .any(|path| path.extension().is_some_and(|value| value == "html")));
        assert!(files
            .iter()
            .any(|path| path.extension().is_some_and(|value| value == "txt")));
        let html = files
            .iter()
            .find(|path| path.extension().is_some_and(|value| value == "html"))
            .and_then(|path| std::fs::read_to_string(path).ok())
            .unwrap();
        assert!(html.contains("Hello Alice"));
        assert!(html.contains("/verify?token=opaque"));
        assert!(!html.contains("{{"));
        let _ = std::fs::remove_dir_all(root);
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
