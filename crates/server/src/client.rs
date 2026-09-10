use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use appport_auth_mesh_boundary::Method;

use crate::http::{HttpError, HttpResponse};
use crate::upstream::{ApplicationUpstream, UpstreamScheme};

/// A minimal HTTP client.
///
/// It exists for two reasons: forwarding a request to the upstream application
/// in standalone mode, and letting tests speak to the server over a real
/// socket rather than through an in-process shortcut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRequest {
    pub method: Method,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ClientRequest {
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn get(path: impl Into<String>) -> Self {
        Self::new(Method::Get, path)
    }

    pub fn post_json(path: impl Into<String>, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        Self {
            method: Method::Post,
            path: path.into(),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    pub fn with_cookie(self, name: &str, value: &str) -> Self {
        self.with_header("cookie", format!("{}={}", name, value))
    }
}

pub fn send(address: SocketAddr, request: &ClientRequest) -> Result<HttpResponse, HttpError> {
    let mut stream = TcpStream::connect(address).map_err(|err| HttpError::new(err.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| HttpError::new(err.to_string()))?;

    let mut head = format!("{} {} HTTP/1.1\r\n", request.method.as_str(), request.path);
    head.push_str(&format!("host: {}\r\n", address));
    for (name, value) in &request.headers {
        head.push_str(&format!("{}: {}\r\n", name, value));
    }
    head.push_str(&format!("content-length: {}\r\n", request.body.len()));
    head.push_str("connection: close\r\n\r\n");

    stream
        .write_all(head.as_bytes())
        .map_err(|err| HttpError::new(err.to_string()))?;
    stream
        .write_all(&request.body)
        .map_err(|err| HttpError::new(err.to_string()))?;
    stream
        .flush()
        .map_err(|err| HttpError::new(err.to_string()))?;

    read_response(stream)
}

pub fn send_upstream(
    upstream: &ApplicationUpstream,
    request: &ClientRequest,
) -> Result<HttpResponse, HttpError> {
    let stream = upstream
        .connect(Duration::from_secs(3))
        .map_err(HttpError::new)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| HttpError::new(err.to_string()))?;
    match upstream.scheme {
        UpstreamScheme::Http => exchange(stream, &upstream.authority(), request),
        UpstreamScheme::Https => {
            let connector = native_tls::TlsConnector::new()
                .map_err(|err| HttpError::new(format!("TLS setup failed: {}", err)))?;
            let stream = connector
                .connect(&upstream.host, stream)
                .map_err(|err| HttpError::new(format!("TLS connection failed: {}", err)))?;
            exchange(stream, &upstream.authority(), request)
        }
    }
}

fn exchange<S: Read + Write>(
    mut stream: S,
    authority: &str,
    request: &ClientRequest,
) -> Result<HttpResponse, HttpError> {
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method.as_str(), request.path);
    head.push_str(&format!("host: {}\r\n", authority));
    for (name, value) in &request.headers {
        head.push_str(&format!("{}: {}\r\n", name, value));
    }
    head.push_str(&format!("content-length: {}\r\n", request.body.len()));
    head.push_str("connection: close\r\n\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(&request.body))
        .and_then(|_| stream.flush())
        .map_err(|err| HttpError::new(err.to_string()))?;
    read_response(stream)
}

fn read_response(stream: impl Read) -> Result<HttpResponse, HttpError> {
    let mut reader = BufReader::new(stream);

    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|err| HttpError::new(err.to_string()))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| HttpError::new("malformed status line"))?;

    let mut headers = Vec::new();
    let mut header_map = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .map_err(|err| HttpError::new(err.to_string()))?
            == 0
        {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            header_map.insert(name.clone(), value.clone());
            headers.push((name, value));
        }
    }

    let mut body = Vec::new();
    if header_map
        .get("transfer-encoding")
        .map(|value| value.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        read_chunked(&mut reader, &mut body)?;
        headers.retain(|(name, _)| name != "transfer-encoding");
    } else {
        match header_map
            .get("content-length")
            .and_then(|value| value.parse::<usize>().ok())
        {
            Some(length) => {
                body.resize(length, 0);
                if length > 0 {
                    reader
                        .read_exact(&mut body)
                        .map_err(|err| HttpError::new(err.to_string()))?;
                }
            }
            None => loop {
                let mut chunk = [0u8; 8192];
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(length) => body.extend_from_slice(&chunk[..length]),
                    Err(err)
                        if matches!(
                            err.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break
                    }
                    Err(err) => return Err(HttpError::new(err.to_string())),
                }
            },
        }
    }

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn read_chunked(reader: &mut impl BufRead, body: &mut Vec<u8>) -> Result<(), HttpError> {
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| HttpError::new(err.to_string()))?;
        let size = line
            .trim()
            .split(';')
            .next()
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or_else(|| HttpError::new("malformed chunked response"))?;
        if size == 0 {
            loop {
                line.clear();
                reader
                    .read_line(&mut line)
                    .map_err(|err| HttpError::new(err.to_string()))?;
                if line == "\r\n" || line == "\n" || line.is_empty() {
                    return Ok(());
                }
            }
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .map_err(|err| HttpError::new(err.to_string()))?;
        let mut ending = [0u8; 2];
        reader
            .read_exact(&mut ending)
            .map_err(|err| HttpError::new(err.to_string()))?;
        if ending != *b"\r\n" {
            return Err(HttpError::new("malformed chunk boundary"));
        }
    }
}

/// Read a cookie value out of a response's `set-cookie` headers.
pub fn cookie_value(response: &HttpResponse, name: &str) -> Option<String> {
    response
        .headers
        .iter()
        .filter(|(header, _)| header == "set-cookie")
        .find_map(|(_, value)| {
            let (pair, _) = value.split_once(';').unwrap_or((value.as_str(), ""));
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name.trim() == name).then(|| cookie_value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_chunked_development_server_responses() {
        let wire = b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-type: text/html\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let response = read_response(std::io::Cursor::new(wire)).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello world");
        assert!(!response
            .headers
            .iter()
            .any(|(name, _)| name == "transfer-encoding"));
    }
}
