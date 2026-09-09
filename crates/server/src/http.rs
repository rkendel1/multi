use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use appport_auth_mesh_boundary::{BoundaryRequest, Method};
use appport_auth_mesh_surface::BoundarySurface;

/// A parsed HTTP request. Deliberately small: the boundary does the thinking,
/// this only gets bytes into a shape it understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: Method,
    pub target: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub cookies: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

const MAX_BODY_BYTES: usize = 1 << 20;

impl HttpRequest {
    pub fn read_from(stream: &mut BufReader<TcpStream>) -> Result<Self, HttpError> {
        let mut request_line = String::new();
        if stream.read_line(&mut request_line).map_err(HttpError::io)? == 0 {
            return Err(HttpError::new("empty request"));
        }

        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .and_then(Method::parse)
            .ok_or_else(|| HttpError::new("unsupported method"))?;
        let target = parts
            .next()
            .ok_or_else(|| HttpError::new("missing request target"))?
            .to_string();

        let mut headers = BTreeMap::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).map_err(HttpError::io)? == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let length = headers
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0)
            .min(MAX_BODY_BYTES);
        let mut body = vec![0u8; length];
        if length > 0 {
            stream.read_exact(&mut body).map_err(HttpError::io)?;
        }

        Ok(Self::assemble(method, target, headers, body))
    }

    pub fn assemble(
        method: Method,
        target: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        let (path, query) = split_target(&target);
        let cookies = headers
            .get("cookie")
            .map(|value| parse_cookies(value))
            .unwrap_or_default();

        Self {
            method,
            target,
            path,
            query,
            headers,
            cookies,
            body,
        }
    }

    /// Translate into the framework-neutral request the boundary consumes.
    ///
    /// Reserved headers are dropped here, so nothing a client sends can
    /// impersonate the context AuthPort injects downstream.
    pub fn to_boundary(&self) -> BoundaryRequest {
        BoundaryRequest {
            method: self.method,
            path: self.path.clone(),
            headers: self.headers.clone(),
            cookies: self.cookies.clone(),
            query: self.query.clone(),
            body: self.parsed_body(),
        }
        .sanitized()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    fn parsed_body(&self) -> BTreeMap<String, String> {
        let content_type = self.header("content-type").unwrap_or("");
        let body = String::from_utf8_lossy(&self.body);
        if content_type.contains("json") {
            parse_flat_json(&body)
        } else if content_type.contains("form-urlencoded") {
            parse_form(&body)
        } else if body.trim_start().starts_with('{') {
            parse_flat_json(&body)
        } else {
            parse_form(&body)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: body.into(),
        }
    }

    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "application/json", body.into().into_bytes())
    }

    pub fn html(status: u16, body: impl Into<String>) -> Self {
        Self::new(status, "text/html; charset=utf-8", body.into().into_bytes())
    }

    pub fn text(status: u16, body: impl Into<String>) -> Self {
        Self::new(
            status,
            "text/plain; charset=utf-8",
            body.into().into_bytes(),
        )
    }

    /// A refusal, in the same shape everywhere: a reason, never a fallback.
    pub fn denied(status: u16, reason: &str, message: &str) -> Self {
        Self::json(
            status,
            format!(
                "{{\"error\": \"{}\", \"reason\": \"{}\", \"message\": \"{}\"}}",
                if status == 401 {
                    "unauthenticated"
                } else {
                    "denied"
                },
                escape(reason),
                escape(message)
            ),
        )
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn with_session_cookie(self, value: &str) -> Self {
        self.with_header(
            "set-cookie",
            format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax",
                BoundarySurface::SESSION_COOKIE,
                value
            ),
        )
    }

    pub fn clearing_session_cookie(self) -> Self {
        self.with_header(
            "set-cookie",
            format!(
                "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
                BoundarySurface::SESSION_COOKIE
            ),
        )
    }

    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn write_to(&self, stream: &mut impl Write) -> std::io::Result<()> {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason_phrase(self.status)
        );
        for (name, value) in &self.headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        head.push_str(&format!("content-length: {}\r\n", self.body.len()));
        head.push_str("connection: close\r\n\r\n");

        stream.write_all(head.as_bytes())?;
        stream.write_all(&self.body)?;
        stream.flush()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    pub message: String,
}

impl HttpError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn io(err: std::io::Error) -> Self {
        Self::new(err.to_string())
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HttpError {}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Unknown",
    }
}

fn split_target(target: &str) -> (String, BTreeMap<String, String>) {
    match target.split_once('?') {
        Some((path, query)) => (path.to_string(), parse_form(query)),
        None => (target.to_string(), BTreeMap::new()),
    }
}

fn parse_cookies(value: &str) -> BTreeMap<String, String> {
    value
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

pub fn parse_form(input: &str) -> BTreeMap<String, String> {
    input
        .split('&')
        .filter(|pair| !pair.trim().is_empty())
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| (percent_decode(name), percent_decode(value)))
        .collect()
}

/// A flat JSON object reader.
///
/// Sign-in payloads are flat by construction; anything nested is ignored rather
/// than half-understood.
pub fn parse_flat_json(input: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let chars: Vec<char> = input.chars().collect();
    let mut index = 0usize;
    let mut depth = 0usize;

    while index < chars.len() {
        match chars[index] {
            '{' | '[' => {
                depth += 1;
                index += 1;
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                index += 1;
            }
            '"' if depth == 1 => {
                let (key, next) = read_json_string(&chars, index);
                index = next;
                while index < chars.len() && chars[index].is_whitespace() {
                    index += 1;
                }
                if index >= chars.len() || chars[index] != ':' {
                    continue;
                }
                index += 1;
                while index < chars.len() && chars[index].is_whitespace() {
                    index += 1;
                }
                if index >= chars.len() {
                    break;
                }
                match chars[index] {
                    '"' => {
                        let (value, next) = read_json_string(&chars, index);
                        out.insert(key, value);
                        index = next;
                    }
                    '{' | '[' => {
                        // Nested values are not part of the flat contract.
                        let mut nested = 0usize;
                        while index < chars.len() {
                            match chars[index] {
                                '{' | '[' => nested += 1,
                                '}' | ']' => {
                                    nested -= 1;
                                    if nested == 0 {
                                        index += 1;
                                        break;
                                    }
                                }
                                _ => {}
                            }
                            index += 1;
                        }
                    }
                    _ => {
                        let start = index;
                        while index < chars.len() && !matches!(chars[index], ',' | '}' | ']') {
                            index += 1;
                        }
                        let value: String = chars[start..index].iter().collect();
                        out.insert(key, value.trim().to_string());
                    }
                }
            }
            _ => index += 1,
        }
    }

    out
}

fn read_json_string(chars: &[char], start: usize) -> (String, usize) {
    let mut index = start + 1;
    let mut value = String::new();
    while index < chars.len() {
        match chars[index] {
            '\\' if index + 1 < chars.len() => {
                value.push(match chars[index + 1] {
                    'n' => '\n',
                    't' => '\t',
                    other => other,
                });
                index += 2;
            }
            '"' => {
                index += 1;
                break;
            }
            other => {
                value.push(other);
                index += 1;
            }
        }
    }
    (value, index)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            match u8::from_str_radix(hex, 16) {
                Ok(byte) => {
                    out.push(byte);
                    index += 3;
                }
                Err(_) => {
                    out.push(bytes[index]);
                    index += 1;
                }
            }
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
