use std::fmt;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationUpstream {
    pub scheme: UpstreamScheme,
    pub host: String,
    pub port: u16,
}

impl ApplicationUpstream {
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.strip_suffix('/').unwrap_or(value);
        let (scheme, authority) = if let Some(value) = value.strip_prefix("http://") {
            (UpstreamScheme::Http, value)
        } else if let Some(value) = value.strip_prefix("https://") {
            (UpstreamScheme::Https, value)
        } else {
            return Err("application upstream must use http:// or https://".to_string());
        };
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
        {
            return Err("application upstream must be an origin without a path".to_string());
        }
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or_else(|| "IPv6 upstreams must use [host]:port".to_string())?;
            (host, port)
        } else {
            let pair = authority
                .rsplit_once(':')
                .ok_or_else(|| "application upstream must include an explicit port".to_string())?;
            if pair.0.contains(':') {
                return Err("IPv6 upstreams must use [host]:port".to_string());
            }
            pair
        };
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err("application upstream host is invalid".to_string());
        }
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| "application upstream port is invalid".to_string())?;
        Ok(Self {
            scheme,
            host: host.to_string(),
            port,
        })
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn resolve(&self) -> Result<Vec<SocketAddr>, String> {
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect())
            .map_err(|err| format!("cannot resolve `{}`: {}", self.host, err))
            .and_then(|addresses: Vec<_>| {
                if addresses.is_empty() {
                    Err(format!("`{}` resolved to no addresses", self.host))
                } else {
                    Ok(addresses)
                }
            })
    }

    pub fn connect(&self, timeout: Duration) -> Result<TcpStream, String> {
        let mut last = None;
        for address in self.resolve()? {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => return Ok(stream),
                Err(err) => last = Some(err),
            }
        }
        Err(format!(
            "cannot connect to `{}`: {}",
            self,
            last.map(|err| err.to_string())
                .unwrap_or_else(|| "no resolved address accepted the connection".to_string())
        ))
    }
}

impl fmt::Display for ApplicationUpstream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.scheme {
            UpstreamScheme::Http => "http",
            UpstreamScheme::Https => "https",
        };
        write!(formatter, "{}://{}", scheme, self.authority())
    }
}

impl From<SocketAddr> for ApplicationUpstream {
    fn from(value: SocketAddr) -> Self {
        Self {
            scheme: UpstreamScheme::Http,
            host: value.ip().to_string(),
            port: value.port(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicit_http_origins_and_preserves_them() {
        for origin in [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
            "https://localhost:3000",
            "https://127.0.0.1:8443",
            "http://127.0.0.1:5173/",
        ] {
            assert_eq!(
                ApplicationUpstream::parse(origin).unwrap().to_string(),
                origin.trim_end_matches('/')
            );
        }
        for invalid in [
            "localhost:3000",
            "127.0.0.1:3000",
            "http://localhost",
            "http://localhost/path",
            "http://localhost:3000/api",
            "ftp://localhost:3000",
            "http://localhost:abc",
        ] {
            assert!(ApplicationUpstream::parse(invalid).is_err(), "{invalid}");
        }
    }
}
