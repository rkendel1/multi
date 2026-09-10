use std::collections::HashSet;

use crate::model::{
    AuthConfig, AuthUiConfig, AuthUiMode, ClaimDef, ClaimKind, IsolationMode, PolicyClaimCondition,
    PasswordPolicy, PolicyDef, UiScreen, UiScreenOverride, UiTheme,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDslError {
    pub message: String,
}

impl AuthDslError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AuthDslError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for AuthDslError {}

/// A parsed value inside an auth block.
///
/// Both the `key: value` and the `key = value` spellings parse into the same
/// shape, so the original MVP syntax and the capability syntax coexist.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Scalar(String),
    List(Vec<String>),
    Enum(Vec<String>),
    Block(Vec<(String, Value)>),
}

impl Value {
    fn kind(&self) -> &'static str {
        match self {
            Self::Scalar(_) => "scalar",
            Self::List(_) => "list",
            Self::Enum(_) => "enum",
            Self::Block(_) => "block",
        }
    }
}

pub fn parse_auth_block(src: &str) -> Result<AuthConfig, AuthDslError> {
    if src.trim() == "use auth" {
        let mut config = AuthConfig::default();
        config.providers.push("local".to_string());
        return Ok(config);
    }
    if src.matches("use auth").count() > 1 {
        return Err(AuthDslError::new("multiple auth blocks are not allowed"));
    }

    let body = extract_auth_block(src)?;
    let entries = Parser::new(&body).parse_entries(false)?;

    let mut config = AuthConfig::default();
    let mut seen: HashSet<String> = HashSet::new();
    let mut tenant_declaration: Option<bool> = None;

    for (key, value) in entries {
        if !seen.insert(key.clone()) {
            return Err(AuthDslError::new(format!("duplicate auth field `{}`", key)));
        }

        match key.as_str() {
            // `multi_tenant` is the original spelling, `tenant` the capability
            // spelling. They declare the same thing.
            "multi_tenant" | "tenant" => {
                let declared = expect_bool(&key, &value)?;
                if let Some(previous) = tenant_declaration {
                    if previous != declared {
                        return Err(AuthDslError::new("conflicting tenant declaration"));
                    }
                }
                tenant_declaration = Some(declared);
                config.multi_tenant = declared;
            }
            "providers" => config.providers = expect_providers(&value)?,
            "isolation" => config.isolation = parse_isolation(expect_scalar(&key, &value)?)?,
            "claims" => config.claims = parse_claims(&value)?,
            "policy" => config.policies = parse_policies(&value)?,
            "password" | "password_policy" => config.password_policy = parse_password(&value)?,
            "agents" => config.agents = expect_bool(&key, &value)?,
            "ui" => config.ui = parse_ui(&value)?,
            _ => return Err(AuthDslError::new(format!("unknown auth field `{}`", key))),
        }
    }

    if config.providers.is_empty() {
        config.providers.push("local".to_string());
    }

    config
        .validate()
        .map_err(|err| AuthDslError::new(err.message))?;

    Ok(config)
}

fn extract_auth_block(src: &str) -> Result<String, AuthDslError> {
    let start = src
        .find("use auth")
        .ok_or_else(|| AuthDslError::new("missing `use auth` block"))?;
    let open = src[start..]
        .find('{')
        .ok_or_else(|| AuthDslError::new("missing `{` in auth block"))?
        + start;

    let mut depth = 0usize;
    let mut close = None;
    for (idx, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + idx);
                    break;
                }
            }
            _ => {}
        }
    }

    let close = close.ok_or_else(|| AuthDslError::new("missing closing `}` in auth block"))?;

    Ok(src[open + 1..close].to_string())
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn new(src: &str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
        }
    }

    fn parse_entries(&mut self, nested: bool) -> Result<Vec<(String, Value)>, AuthDslError> {
        let mut entries = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                None => {
                    if nested {
                        return Err(AuthDslError::new("missing closing `}`"));
                    }
                    return Ok(entries);
                }
                Some('}') => {
                    if !nested {
                        return Err(AuthDslError::new("unexpected `}`"));
                    }
                    self.pos += 1;
                    return Ok(entries);
                }
                Some(_) => {}
            }

            let key = self.parse_ident()?;
            self.skip_trivia();
            let value = match self.peek() {
                Some(':') | Some('=') => {
                    self.pos += 1;
                    self.parse_value()?
                }
                Some('{') => self.parse_value()?,
                _ => {
                    return Err(AuthDslError::new(format!(
                        "expected `:`, `=` or `{{` after `{}`",
                        key
                    )))
                }
            };
            entries.push((key, value));
        }
    }

    fn parse_value(&mut self) -> Result<Value, AuthDslError> {
        self.skip_trivia();
        match self.peek() {
            Some('{') => {
                self.pos += 1;
                Ok(Value::Block(self.parse_entries(true)?))
            }
            Some('[') => Ok(Value::List(self.parse_list()?)),
            Some('"') => Ok(Value::Scalar(self.parse_quoted()?)),
            Some(ch) if is_ident_char(ch) => {
                let ident = self.parse_ident()?;
                if ident == "enum" && self.peek() == Some('[') {
                    return Ok(Value::Enum(self.parse_list()?));
                }
                Ok(Value::Scalar(ident))
            }
            Some(ch) => Err(AuthDslError::new(format!("unexpected character `{}`", ch))),
            None => Err(AuthDslError::new("unexpected end of auth block")),
        }
    }

    fn parse_list(&mut self) -> Result<Vec<String>, AuthDslError> {
        if self.peek() != Some('[') {
            return Err(AuthDslError::new("expected `[`"));
        }
        self.pos += 1;

        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                Some(']') => {
                    self.pos += 1;
                    return Ok(items);
                }
                Some('"') => items.push(self.parse_quoted()?),
                Some(ch) if is_ident_char(ch) => items.push(self.parse_ident()?),
                Some(ch) => {
                    return Err(AuthDslError::new(format!(
                        "unexpected character `{}` in list",
                        ch
                    )))
                }
                None => return Err(AuthDslError::new("missing closing `]`")),
            }
        }
    }

    fn parse_ident(&mut self) -> Result<String, AuthDslError> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if is_ident_char(ch) {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            let ch = self.peek().unwrap_or(' ');
            return Err(AuthDslError::new(format!(
                "expected an identifier, found `{}`",
                ch
            )));
        }
        Ok(self.chars[start..self.pos].iter().collect())
    }

    fn parse_quoted(&mut self) -> Result<String, AuthDslError> {
        self.pos += 1;
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == '"' {
                let value = self.chars[start..self.pos].iter().collect();
                self.pos += 1;
                return Ok(value);
            }
            self.pos += 1;
        }
        Err(AuthDslError::new("unterminated string"))
    }

    /// Whitespace, separators (`,`) and `#` / `//` comments carry no meaning.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(ch) if ch.is_whitespace() || ch == ',' => self.pos += 1,
                Some('#') => self.skip_line(),
                Some('/') if self.peek_at(1) == Some('/') => self.skip_line(),
                _ => return,
            }
        }
    }

    fn skip_line(&mut self) {
        while let Some(ch) = self.peek() {
            self.pos += 1;
            if ch == '\n' {
                return;
            }
        }
    }

    fn peek(&self) -> Option<char> {
        self.peek_at(0)
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos + offset).copied()
    }
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.'
}

fn expect_scalar<'a>(key: &str, value: &'a Value) -> Result<&'a str, AuthDslError> {
    match value {
        Value::Scalar(scalar) => Ok(scalar),
        other => Err(AuthDslError::new(format!(
            "`{}` expects a value, found {}",
            key,
            other.kind()
        ))),
    }
}

fn expect_bool(key: &str, value: &Value) -> Result<bool, AuthDslError> {
    match expect_scalar(key, value)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(AuthDslError::new(format!("{} must be true or false", key))),
    }
}

fn expect_providers(value: &Value) -> Result<Vec<String>, AuthDslError> {
    let items = match value {
        Value::List(items) => items.clone(),
        _ => return Err(AuthDslError::new("providers must be in []")),
    };

    let items = items
        .into_iter()
        .filter(|item| !item.trim().is_empty())
        .collect::<Vec<_>>();

    if items.is_empty() {
        return Err(AuthDslError::new("providers cannot be empty"));
    }

    Ok(items)
}

fn parse_isolation(input: &str) -> Result<IsolationMode, AuthDslError> {
    match input.to_ascii_lowercase().as_str() {
        "strict" => Ok(IsolationMode::Strict),
        "shared_storage_with_policy" => Ok(IsolationMode::SharedStorageWithPolicy),
        _ => Err(AuthDslError::new(format!(
            "unknown isolation mode `{}`",
            input
        ))),
    }
}

fn parse_claims(value: &Value) -> Result<Vec<ClaimDef>, AuthDslError> {
    let entries = match value {
        Value::Block(entries) => entries,
        _ => return Err(AuthDslError::new("claims must be a `{ ... }` block")),
    };

    let mut claims = Vec::new();
    for (name, kind) in entries {
        claims.push(ClaimDef {
            name: name.clone(),
            kind: parse_claim_kind(name, kind)?,
        });
    }
    Ok(claims)
}

fn parse_claim_kind(name: &str, value: &Value) -> Result<ClaimKind, AuthDslError> {
    match value {
        Value::Enum(variants) => {
            let variants = variants
                .iter()
                .filter(|variant| !variant.trim().is_empty())
                .cloned()
                .collect::<Vec<_>>();
            if variants.is_empty() {
                return Err(AuthDslError::new("enum claim must have values"));
            }
            let mut seen = HashSet::new();
            for variant in &variants {
                if !seen.insert(variant) {
                    return Err(AuthDslError::new(format!(
                        "duplicate enum value `{}`",
                        variant
                    )));
                }
            }
            Ok(ClaimKind::Enum(variants))
        }
        Value::Scalar(scalar) => match scalar.as_str() {
            "string" => Ok(ClaimKind::String),
            "integer" => Ok(ClaimKind::Integer),
            "boolean" => Ok(ClaimKind::Boolean),
            _ => Err(AuthDslError::new(format!(
                "unsupported claim kind `{}`",
                scalar
            ))),
        },
        other => Err(AuthDslError::new(format!(
            "claim `{}` has an unsupported {} definition",
            name,
            other.kind()
        ))),
    }
}

fn parse_policies(value: &Value) -> Result<Vec<PolicyDef>, AuthDslError> {
    let entries = match value {
        Value::Block(entries) => entries,
        _ => return Err(AuthDslError::new("policy must be a `{ ... }` block")),
    };
    let mut policies = Vec::new();
    for (capability, value) in entries {
        let Value::Block(fields) = value else {
            return Err(AuthDslError::new(format!(
                "policy `{}` must be a block",
                capability
            )));
        };
        let mut policy = PolicyDef {
            capability: capability.clone(),
            tenant_current: false,
            resource: None,
            action: capability
                .split_once('.')
                .map(|(_, action)| action.to_string()),
            claims: Vec::new(),
        };
        for (key, value) in fields {
            match key.as_str() {
                "tenant" => {
                    let tenant = expect_scalar(key, value)?;
                    if tenant != "current" {
                        return Err(AuthDslError::new("policy tenant must be `current`"));
                    }

                    policy.tenant_current = true;
                }
                "resource" => policy.resource = Some(expect_scalar(key, value)?.to_string()),
                "action" => policy.action = Some(expect_scalar(key, value)?.to_string()),
                claim => {
                    let values = match value {
                        Value::List(values) | Value::Enum(values) => values.clone(),
                        Value::Scalar(value) => vec![value.clone()],
                        Value::Block(_) => {
                            return Err(AuthDslError::new(format!(
                                "policy claim `{}` cannot be a block",
                                claim
                            )))
                        }
                    };
                    policy.claims.push(PolicyClaimCondition {
                        claim: claim.to_string(),
                        values,
                    });
                }
            }
        }
        policy.claims.sort();
        policies.push(policy);
    }
    Ok(policies)
}

fn parse_password(value: &Value) -> Result<PasswordPolicy, AuthDslError> {
    let entries = match value {
        Value::Block(entries) => entries,
        _ => return Err(AuthDslError::new("password must be a `{ ... }` block")),
    };
    let mut policy = PasswordPolicy::default();
    let mut seen = HashSet::new();
    for (key, value) in entries {
        if !seen.insert(key.clone()) {
            return Err(AuthDslError::new(format!(
                "duplicate password field `{}`",
                key
            )));
        }
        match key.as_str() {
            "min_length" => policy.min_length = expect_usize(key, value)?,
            "max_length" => policy.max_length = expect_usize(key, value)?,
            "require_uppercase" => policy.require_uppercase = expect_bool(key, value)?,
            "require_lowercase" => policy.require_lowercase = expect_bool(key, value)?,
            "require_number" => policy.require_number = expect_bool(key, value)?,
            "require_special_character" => policy.require_special_character = expect_bool(key, value)?,
            "expiration_days" | "password_expiration_days" => {
                policy.password_expiration_days = expect_optional_u32(key, value)?
            }
            "history_count" | "password_history_count" => {
                policy.password_history_count = expect_usize(key, value)?
            }
            "allow_password_change" => policy.allow_password_change = expect_bool(key, value)?,
            "allow_password_reset" => policy.allow_password_reset = expect_bool(key, value)?,
            _ => return Err(AuthDslError::new(format!("unknown password field `{}`", key))),
        }
    }
    policy
        .validate()
        .map_err(|err| AuthDslError::new(err.message))?;
    Ok(policy)
}

fn expect_usize(key: &str, value: &Value) -> Result<usize, AuthDslError> {
    expect_scalar(key, value)?
        .parse()
        .map_err(|_| AuthDslError::new(format!("{} must be a non-negative integer", key)))
}

fn expect_optional_u32(key: &str, value: &Value) -> Result<Option<u32>, AuthDslError> {
    let scalar = expect_scalar(key, value)?;
    if scalar == "null" {
        return Ok(None);
    }
    scalar
        .parse()
        .map(Some)
        .map_err(|_| AuthDslError::new(format!("{} must be an integer or null", key)))
}

fn parse_ui(value: &Value) -> Result<AuthUiConfig, AuthDslError> {
    let entries = match value {
        Value::Block(entries) => entries,
        _ => return Err(AuthDslError::new("ui must be a `{ ... }` block")),
    };

    let mut ui = AuthUiConfig::default();
    let mut seen = HashSet::new();
    for (key, entry) in entries {
        if !seen.insert(key.clone()) {
            return Err(AuthDslError::new(format!("duplicate ui field `{}`", key)));
        }
        if key == "theme" {
            ui.theme = UiTheme {
                name: expect_scalar(key, entry)?.to_string(),
            };
            continue;
        }

        let screen = UiScreen::parse(key)
            .ok_or_else(|| AuthDslError::new(format!("unknown ui surface `{}`", key)))?;
        let mode = match expect_scalar(key, entry)? {
            "default" => AuthUiMode::Default,
            "custom" => AuthUiMode::Custom,
            other => {
                return Err(AuthDslError::new(format!(
                    "ui surface `{}` must be \"default\" or \"custom\", found `{}`",
                    key, other
                )))
            }
        };
        ui.screens.push(UiScreenOverride { screen, mode });
    }

    ui.validate()
        .map_err(|err| AuthDslError::new(err.message))?;
    Ok(ui.canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mvp_auth_block() {
        let src = r#"
use auth {
  multi_tenant: true
  providers: [local, google, microsoft]
  claims: {
    role: enum["admin","user"]
    plan: enum["free","pro"]
  }
  isolation: "strict"
}
"#;

        let parsed = parse_auth_block(src).expect("parser should parse valid DSL");
        assert!(parsed.multi_tenant);
        assert_eq!(parsed.providers, vec!["local", "google", "microsoft"]);
        assert_eq!(parsed.claims.len(), 2);
        assert_eq!(parsed.isolation, IsolationMode::Strict);
        assert!(!parsed.agents);
        assert_eq!(parsed.ui, AuthUiConfig::default());
    }

    #[test]
    fn parses_resource_aware_policy_block() {
        let parsed = parse_auth_block(
            r#"
use auth {
  providers = [local]
  tenant = true
  claims = {
    role = enum["owner", "admin", "member"]
  }
  policy {
    invoice.read {
      tenant = current
      resource = invoice
    }
    invoice.update {
      tenant = current
      resource = invoice
      role = ["owner", "admin"]
    }
  }
}
"#,
        )
        .expect("policy DSL should parse");

        assert_eq!(parsed.policies.len(), 2);
        let update = parsed
            .policies
            .iter()
            .find(|policy| policy.capability == "invoice.update")
            .unwrap();
        assert!(update.tenant_current);
        assert_eq!(update.resource.as_deref(), Some("invoice"));
        assert_eq!(update.action.as_deref(), Some("update"));
        assert_eq!(update.claims[0].claim, "role");
        assert_eq!(update.claims[0].values, vec!["owner", "admin"]);
    }

    #[test]
    fn parses_password_policy_with_modern_defaults() {
        let defaulted = parse_auth_block("use auth { providers = [local] }").unwrap();
        assert_eq!(defaulted.password_policy, PasswordPolicy::default());

        let parsed = parse_auth_block(
            r#"
use auth {
  providers = [local]
  password {
    min_length = 16
    max_length = 128
    require_number = true
    require_special_character = true
    expiration_days = 90
    history_count = 7
  }
}
"#,
        )
        .unwrap();

        assert_eq!(parsed.password_policy.min_length, 16);
        assert!(parsed.password_policy.require_number);
        assert!(parsed.password_policy.require_special_character);
        assert_eq!(parsed.password_policy.password_expiration_days, Some(90));
        assert_eq!(parsed.password_policy.password_history_count, 7);
        assert!(parsed.password_policy.allow_password_change);
    }

    #[test]
    fn parses_capability_declaration_syntax() {
        let src = r#"
use auth {
  providers = [google, github, email]

  tenant = true

  claims = {
    role = enum["owner", "admin", "member"]
    plan = enum["free", "pro"]
  }

  agents = true
}
"#;

        let parsed = parse_auth_block(src).expect("capability syntax should parse");
        assert!(parsed.multi_tenant);
        assert!(parsed.agents);
        assert_eq!(parsed.providers, vec!["google", "github", "email"]);
        assert_eq!(
            parsed.claim("role").map(|claim| claim.kind.clone()),
            Some(ClaimKind::Enum(vec![
                "owner".to_string(),
                "admin".to_string(),
                "member".to_string()
            ]))
        );
        // Isolation is an implementation detail the application need not declare.
        assert_eq!(parsed.isolation, IsolationMode::Strict);
    }

    #[test]
    fn both_syntaxes_produce_the_same_contract() {
        let colon = parse_auth_block(
            r#"
use auth {
  multi_tenant: true
  providers: [local, google]
  claims: {
    role: enum["admin","user"]
  }
  isolation: "strict"
  agents: true
}
"#,
        )
        .unwrap();
        let equals = parse_auth_block(
            r#"
use auth {
  tenant = true
  providers = [google, local]
  claims = {
    role = enum["user", "admin"]
  }
  isolation = "strict"
  agents = true
}
"#,
        )
        .unwrap();

        assert_eq!(colon.fingerprint(), equals.fingerprint());
        assert_eq!(colon.canonical(), equals.canonical());
    }

    #[test]
    fn parses_ui_customization() {
        let parsed = parse_auth_block(
            r#"
use auth {
  providers = [local]
  ui = {
    login = "custom"
    account = "custom"
    theme = "midnight"
  }
}
"#,
        )
        .expect("ui block should parse");

        assert_eq!(parsed.ui.mode, AuthUiMode::Custom);
        assert_eq!(parsed.ui.theme.name, "midnight");
        assert_eq!(parsed.ui.mode_for(UiScreen::Login), AuthUiMode::Custom);
        assert_eq!(parsed.ui.mode_for(UiScreen::Signup), AuthUiMode::Default);
    }

    #[test]
    fn canonical_fingerprint_is_deterministic_for_equivalent_config() {
        let a = parse_auth_block(
            r#"
use auth {
  multi_tenant: true
  providers: [local, agent]
  claims: {
    role: enum["admin","user"]
    plan: enum["free","pro"]
  }
  isolation: "strict"
}
"#,
        )
        .unwrap();
        let b = parse_auth_block(
            r#"
use auth {
  multi_tenant: true
  providers: [agent, local]
  claims: {
    plan: enum["pro","free"]
    role: enum["user","admin"]
  }
  isolation: "strict"
}
"#,
        )
        .unwrap();

        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn agents_and_ui_participate_in_the_fingerprint() {
        let base = parse_auth_block(
            r#"
use auth {
  providers = [local]
}
"#,
        )
        .unwrap();
        let with_agents = parse_auth_block(
            r#"
use auth {
  providers = [local]
  agents = true
}
"#,
        )
        .unwrap();
        let with_ui = parse_auth_block(
            r#"
use auth {
  providers = [local]
  ui = { login = "custom" }
}
"#,
        )
        .unwrap();

        assert_ne!(base.fingerprint(), with_agents.fingerprint());
        assert_ne!(base.fingerprint(), with_ui.fingerprint());
        assert_ne!(with_agents.fingerprint(), with_ui.fingerprint());
    }

    #[test]
    fn rejects_duplicate_claims_and_unknown_fields() {
        let duplicate_claim = r#"
use auth {
  multi_tenant: true
  providers: [local]
  claims: {
    role: enum["admin","user"]
    role: enum["admin","user"]
  }
  isolation: "strict"
}
"#;
        assert_eq!(
            parse_auth_block(duplicate_claim).unwrap_err().message,
            "duplicate claim `role`"
        );

        let unknown_field = r#"
use auth {
  multi_tenant: true
  providers: [local]
  claims: {
    role: enum["admin","user"]
  }
  isolation: "strict"
  secret_backdoor: true
}
"#;
        assert!(parse_auth_block(unknown_field)
            .unwrap_err()
            .message
            .starts_with("unknown auth field"));
    }

    #[test]
    fn rejects_duplicate_providers_duplicate_enum_values_and_multiple_blocks() {
        assert_eq!(
            parse_auth_block(
                r#"
use auth {
  multi_tenant: true
  providers: [local, local]
  claims: {
    role: enum["admin","user"]
  }
  isolation: "strict"
}
"#
            )
            .unwrap_err()
            .message,
            "duplicate provider `local`"
        );

        assert_eq!(
            parse_auth_block(
                r#"
use auth {
  multi_tenant: true
  providers: [local]
  claims: {
    role: enum["admin","admin"]
  }
  isolation: "strict"
}
"#
            )
            .unwrap_err()
            .message,
            "duplicate enum value `admin`"
        );

        assert_eq!(
            parse_auth_block(
                r#"
use auth {
  multi_tenant: true
  providers: [local]
  claims: {}
  isolation: "strict"
}
use auth {
  multi_tenant: true
  providers: [local]
  claims: {}
  isolation: "strict"
}
"#
            )
            .unwrap_err()
            .message,
            "multiple auth blocks are not allowed"
        );
    }

    #[test]
    fn rejects_conflicting_and_repeated_declarations() {
        assert_eq!(
            parse_auth_block(
                r#"
use auth {
  tenant = true
  multi_tenant = false
  providers = [local]
}
"#
            )
            .unwrap_err()
            .message,
            "conflicting tenant declaration"
        );

        assert_eq!(
            parse_auth_block(
                r#"
use auth {
  providers = [local]
  providers = [google]
}
"#
            )
            .unwrap_err()
            .message,
            "duplicate auth field `providers`"
        );

        assert_eq!(
            parse_auth_block("use auth {\n  tenant = true\n}\n")
                .unwrap()
                .providers,
            vec!["local"]
        );

        assert_eq!(
            parse_auth_block("use auth").unwrap().providers,
            vec!["local"]
        );

        assert_eq!(
            parse_auth_block(
                "use auth {\n  providers = [local]\n  ui = { login = \"fancy\" }\n}\n"
            )
            .unwrap_err()
            .message,
            "ui surface `login` must be \"default\" or \"custom\", found `fancy`"
        );
    }
}
