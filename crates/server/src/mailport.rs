use crate::{send_upstream, ApplicationUpstream, ClientRequest};
use appport_auth_mesh_boundary::{MailMessage, MailPort};

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
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
