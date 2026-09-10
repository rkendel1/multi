use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

use crate::{error, CliError, Output};

const DEFAULT_SERVER: &str = "http://localhost:8080";

pub fn run(args: &[String]) -> Result<Output, CliError> {
    match args.first().map(String::as_str) {
        Some("connect") => connect(&args[1..]),
        Some("propose") => propose(&args[1..]),
        Some("approve") => approve(&args[1..]),
        Some("apply") => apply(&args[1..]),
        Some("reject") => reject(&args[1..]),
        Some("agents") => agents(&args[1..]),
        Some("agent") => agent(&args[1..]),
        Some("policies") => policies(&args[1..]),
        Some("policy") => policy(&args[1..]),
        Some("explain") => explain(&args[1..]),
        _ => Err(error("unknown control command")),
    }
}

fn connect(args: &[String]) -> Result<Output, CliError> {
    let (server, output_token, _) = common_options(args)?;
    let response = http_get(&server, "/_authport/overview")?;
    if output_token {
        if let Some(token) = extract_quoted_field(&response, "token") {
            write_token(&token)?;
        }
    }
    Ok(Output {
        text: format!("connected to {}\n{}\n", server, response),
    })
}

fn propose(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, dry_run) = common_options(args)?;
    let filtered = strip_common_options(args);
    let change_type = filtered
        .first()
        .ok_or_else(|| error("propose needs a change type"))?;
    let body = proposal_body(change_type, &filtered[1..])?;

    if dry_run {
        return Ok(Output {
            text: format!("dry-run proposal for {}\n{}\n", server, body),
        });
    }

    let response = http_post(&server, "/_authport/propose", &body)?;
    if let Some(proposal_id) = extract_quoted_field(&response, "proposal_id") {
        cache_proposal(&proposal_id, &server, &response)?;
    }
    Ok(Output {
        text: format!("proposal response from {}\n{}\n", server, response),
    })
}

fn apply(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let mut proposal_id = None;
    let mut all = false;
    let mut yes = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--proposal-id" => {
                index += 1;
                proposal_id = args.get(index).cloned();
            }
            "--all" => all = true,
            "--yes" => yes = true,
            "--server" => index += 1,
            _ => {}
        }
        index += 1;
    }
    if !yes {
        return Err(error(
            "apply needs --yes to confirm in non-interactive mode",
        ));
    }

    if all {
        let proposal_ids = inferred_proposal_ids(&server)?;
        let body = proposal_ids_body(&proposal_ids);
        let response = http_post(&server, "/_authport/authority-proposals/apply", &body)?;
        return Ok(Output {
            text: format!("apply response from {}\n{}\n", server, response),
        });
    }

    let proposal_id = match proposal_id {
        Some(id) => id,
        None => latest_proposal_id()?,
    };
    let cached = read_cached_proposal(&proposal_id).unwrap_or_default();
    let approval_token = extract_quoted_field(&cached, "approval_token").unwrap_or_default();
    let body = if approval_token.is_empty() {
        format!("{{\"proposal_id\": \"{}\"}}", escape(&proposal_id))
    } else {
        format!(
            "{{\"proposal_id\": \"{}\", \"approval_token\": \"{}\"}}",
            escape(&proposal_id),
            escape(&approval_token)
        )
    };
    let response = http_post(&server, "/_authport/apply", &body)?;
    Ok(Output {
        text: format!("apply response from {}\n{}\n", server, response),
    })
}

fn approve(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let mut proposal_id = None;
    let mut all = false;
    let mut yes = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--proposal-id" => {
                index += 1;
                proposal_id = args.get(index).cloned();
            }
            "--all" => all = true,
            "--yes" => yes = true,
            "--server" => index += 1,
            _ => {}
        }
        index += 1;
    }
    if !yes {
        return Err(error(
            "approve needs --yes to confirm in non-interactive mode",
        ));
    }
    let (path, body) = if all {
        let proposal_ids = inferred_proposal_ids(&server)?;
        (
            "/_authport/authority-proposals/approve".to_string(),
            proposal_ids_body(&proposal_ids),
        )
    } else {
        let proposal_id = match proposal_id {
            Some(id) => id,
            None => latest_proposal_id()?,
        };
        (
            "/_authport/approve".to_string(),
            format!("{{\"proposal_id\": \"{}\"}}", escape(&proposal_id)),
        )
    };
    let response = http_post(&server, &path, &body)?;
    Ok(Output {
        text: format!("approve response from {}\n{}\n", server, response),
    })
}

fn reject(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let mut proposal_id = None;
    let mut reason = "rejected".to_string();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--proposal-id" => {
                index += 1;
                proposal_id = args.get(index).cloned();
            }

            "--reason" => {
                index += 1;
                reason = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| error("--reason needs a value"))?;
            }
            "--server" => index += 1,
            _ => {}
        }
        index += 1;
    }
    let proposal_id = match proposal_id {
        Some(id) => id,
        None => latest_proposal_id()?,
    };
    let body = format!(
        "{{\"proposal_id\": \"{}\", \"reason\": \"{}\"}}",
        escape(&proposal_id),
        escape(&reason)
    );
    let response = http_post(&server, "/_authport/reject", &body)?;
    Ok(Output {
        text: format!("reject response from {}\n{}\n", server, response),
    })
}

fn agents(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let tenant =
        option_value(args, "--tenant").ok_or_else(|| error("agents needs --tenant TENANT"))?;
    let response = http_get(
        &server,
        &format!("/_authport/agents?tenant={}", escape_path(&tenant)),
    )?;
    Ok(Output {
        text: format!("agents from {}\n{}\n", server, response),
    })
}

fn agent(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let filtered = strip_common_options(args);
    match filtered.first().map(String::as_str) {
        Some("create") => {
            let tenant = option_value(&filtered, "--tenant")
                .ok_or_else(|| error("agent create needs --tenant TENANT"))?;
            let name = option_value(&filtered, "--name")
                .ok_or_else(|| error("agent create needs --name NAME"))?;
            let id = option_value(&filtered, "--id")
                .map(|id| format!(", \"id\": \"{}\"", escape(&id)))
                .unwrap_or_default();
            let body = format!(
                "{{\"tenant\": \"{}\", \"name\": \"{}\"{}}}",
                escape(&tenant),
                escape(&name),
                id
            );
            let response = http_post(&server, "/_authport/agents", &body)?;
            Ok(Output {
                text: format!("agent create response from {}\n{}\n", server, response),
            })
        }
        Some("show") => {
            let id = filtered
                .get(1)
                .ok_or_else(|| error("agent show needs an id"))?;
            let tenant = option_value(&filtered, "--tenant")
                .ok_or_else(|| error("agent show needs --tenant TENANT"))?;
            let response = http_get(
                &server,
                &format!(
                    "/_authport/agents/{}?tenant={}",
                    escape_path(id),
                    escape_path(&tenant)
                ),
            )?;
            Ok(Output {
                text: format!("agent {} from {}\n{}\n", id, server, response),
            })
        }
        _ => Err(error("agent command supports `create` and `show ID`")),
    }
}

fn policies(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let response = http_get(&server, "/_authport/policies")?;
    Ok(Output {
        text: format!("policies from {}\n{}\n", server, response),
    })
}

fn policy(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let filtered = strip_common_options(args);
    if filtered.first().map(String::as_str) != Some("show") {
        return Err(error("policy command supports `show ID`"));
    }

    let id = filtered
        .get(1)
        .ok_or_else(|| error("policy show needs an id"))?;
    let response = http_get(&server, &format!("/_authport/policies/{}", id))?;
    Ok(Output {
        text: format!("policy {} from {}\n{}\n", id, server, response),
    })
}

fn explain(args: &[String]) -> Result<Output, CliError> {
    let (server, _output_token, _) = common_options(args)?;
    let filtered = strip_common_options(args);
    let path = explain_path(&filtered);
    let response = http_get(&server, &path)?;
    Ok(Output {
        text: format!("authorization explanation from {}\n{}\n", server, response),
    })
}

fn explain_path(args: &[String]) -> String {
    match args.first() {
        Some(id) => format!("/_authport/authorization/decisions/{}/explain", id),
        None => "/_authport/authorization/explain".to_string(),
    }
}

fn common_options(args: &[String]) -> Result<(String, bool, bool), CliError> {
    let mut server = load_server_url();
    let mut output_token = false;
    let mut dry_run = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--server" => {
                index += 1;
                server = args
                    .get(index)
                    .cloned()
                    .ok_or_else(|| error("--server needs a value"))?;
            }
            "--output-token" => output_token = true,
            "--dry-run" => dry_run = true,
            _ => {}
        }
        index += 1;
    }
    Ok((server, output_token, dry_run))
}

fn strip_common_options(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--server" => index += 2,
            "--output-token" | "--dry-run" => index += 1,
            _ => {
                out.push(args[index].clone());
                index += 1;
            }
        }
    }
    out
}

fn proposal_body(change_type: &str, args: &[String]) -> Result<String, CliError> {
    let get = |name: &str| -> Result<String, CliError> {
        option_value(args, name).ok_or_else(|| error(format!("{} needs a value", name)))
    };

    match change_type {
        "protect-route" => Ok(format!(
            "{{\"type\": \"protect_route\", \"method\": \"{}\", \"path\": \"{}\", \"capability\": \"{}\"}}",
            escape(&get("--method")?),
            escape(&get("--path")?),
            escape(&get("--capability")?)
        )),
        "unprotect-route" => Ok(format!(
            "{{\"type\": \"unprotect_route\", \"method\": \"{}\", \"path\": \"{}\"}}",
            escape(&get("--method")?),
            escape(&get("--path")?)
        )),
        "set-policy" => Ok(format!(
            "{{\"type\": \"set_policy\", \"capability\": \"{}\", \"policy\": \"{}\"}}",
            escape(&get("--capability")?),
            escape(&get("--policy")?)
        )),
        "enable-provider" => Ok(format!(
            "{{\"type\": \"enable_provider\", \"provider\": \"{}\", \"enabled\": true}}",
            escape(&get("--provider")?)
        )),
        "disable-provider" => Ok(format!(
            "{{\"type\": \"disable_provider\", \"provider\": \"{}\", \"enabled\": false}}",
            escape(&get("--provider")?)
        )),
        other => Err(error(format!("unknown proposal change type `{}`", other))),
    }
}

fn option_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == name).then(|| pair[1].clone()))
}

fn load_server_url() -> String {
    std::env::var("AUTHPORT_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string())
}

fn http_get(server: &str, path: &str) -> Result<String, CliError> {
    http_request(server, "GET", path, "")
}

fn inferred_proposal_ids(server: &str) -> Result<Vec<String>, CliError> {
    let _ = http_get(server, "/_authport/authority-proposal")?;
    let proposals = http_get(server, "/_authport/proposals?source=inferred")?;
    let ids = extract_all_quoted_fields(&proposals, "id");
    if ids.is_empty() {
        return Err(error("no inferred proposals to approve or apply"));
    }
    Ok(ids)
}

fn proposal_ids_body(proposal_ids: &[String]) -> String {
    format!(
        "{{\"proposal_ids\": \"{}\"}}",
        escape(&proposal_ids.join(","))
    )
}

fn http_post(server: &str, path: &str, body: &str) -> Result<String, CliError> {
    http_request(server, "POST", path, body)
}

fn http_request(server: &str, method: &str, path: &str, body: &str) -> Result<String, CliError> {
    let (host, port) = parse_http_url(server)?;
    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|err| error(format!("could not connect to AuthPort server: {}", err)))?;
    let request = format!(
        "{} {} HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        method,
        path,
        host,
        body.len(),
        body
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| error(format!("request failed: {}", err)))?;
    stream
        .flush()
        .map_err(|err| error(format!("request failed: {}", err)))?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|err| error(format!("response failed: {}", err)))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| error("malformed response from AuthPort server"))?;
    let mut content_length = None;
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| error(format!("response failed: {}", err)))?;
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().ok();
            }
        }
    }
    let mut body_bytes = Vec::new();
    match content_length {
        Some(length) => {
            body_bytes.resize(length, 0);
            reader
                .read_exact(&mut body_bytes)
                .map_err(|err| error(format!("response failed: {}", err)))?;
        }
        None => {
            reader
                .read_to_end(&mut body_bytes)
                .map_err(|err| error(format!("response failed: {}", err)))?;
        }
    }
    let body = String::from_utf8_lossy(&body_bytes).to_string();
    if !(200..300).contains(&status) {
        return Err(error(format!("AuthPort returned {}: {}", status, body)));
    }
    Ok(body)
}

fn parse_http_url(server: &str) -> Result<(String, u16), CliError> {
    let rest = server
        .strip_prefix("http://")
        .ok_or_else(|| error("--server must be an http:// URL"))?;
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match host_port.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|_| error("--server has an invalid port"))?,
        ),
        None => (host_port.to_string(), 80),
    };
    if host.is_empty() {
        return Err(error("--server needs a host"));
    }
    Ok((host, port))
}

fn cache_proposal(proposal_id: &str, server: &str, response: &str) -> Result<(), CliError> {
    let dir = proposals_dir()?;
    fs::create_dir_all(&dir).map_err(|err| error(format!("cannot create cache: {}", err)))?;
    let path = dir.join(format!("{}.json", proposal_id));
    fs::write(
        &path,
        format!(
            "{{\"server_url\": \"{}\", \"response\": {}}}",
            escape(server),
            response
        ),
    )
    .map_err(|err| error(format!("cannot write proposal cache: {}", err)))?;
    fs::write(dir.join("latest"), proposal_id)
        .map_err(|err| error(format!("cannot update proposal cache: {}", err)))?;
    Ok(())
}

fn read_cached_proposal(proposal_id: &str) -> Result<String, CliError> {
    fs::read_to_string(proposals_dir()?.join(format!("{}.json", proposal_id)))
        .map_err(|err| error(format!("cannot read proposal cache: {}", err)))
}

fn latest_proposal_id() -> Result<String, CliError> {
    fs::read_to_string(proposals_dir()?.join("latest"))
        .map(|value| value.trim().to_string())
        .map_err(|_| error("no cached proposal; pass --proposal-id"))
}

fn write_token(token: &str) -> Result<(), CliError> {
    let dir = authport_dir()?;
    fs::create_dir_all(&dir).map_err(|err| error(format!("cannot create token cache: {}", err)))?;
    fs::write(
        dir.join("token.json"),
        format!("{{\"token\": \"{}\"}}\n", escape(token)),
    )
    .map_err(|err| error(format!("cannot write token cache: {}", err)))
}

fn proposals_dir() -> Result<PathBuf, CliError> {
    Ok(authport_dir()?.join("proposals"))
}

fn authport_dir() -> Result<PathBuf, CliError> {
    let home = std::env::var("HOME").map_err(|_| error("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".authport"))
}

fn extract_quoted_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\":", field);
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let value = rest.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

fn extract_all_quoted_fields(json: &str, field: &str) -> Vec<String> {
    let pattern = format!("\"{}\":", field);
    let mut rest = json;
    let mut values = Vec::new();
    while let Some(start) = rest.find(&pattern) {
        rest = &rest[start + pattern.len()..];
        let value = match rest.trim_start().strip_prefix('"') {
            Some(value) => value,
            None => continue,
        };
        if let Some(end) = value.find('"') {
            values.push(value[..end].to_string());
            rest = &value[end + 1..];
        } else {
            break;
        }
    }
    values
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn escape_path(value: &str) -> String {
    value.replace(' ', "%20")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| arg.to_string()).collect()
    }

    #[test]
    fn builds_supported_proposal_bodies() {
        let body = proposal_body(
            "protect-route",
            &strings(&[
                "--method",
                "POST",
                "--path",
                "/invoices",
                "--capability",
                "invoice.create",
            ]),
        )
        .unwrap();
        assert!(body.contains("\"type\": \"protect_route\""));
        assert!(body.contains("\"method\": \"POST\""));

        let body = proposal_body("disable-provider", &strings(&["--provider", "github"])).unwrap();
        assert!(body.contains("\"enabled\": false"));
    }

    #[test]
    fn parses_http_urls_for_the_embedded_client() {
        assert_eq!(
            parse_http_url("http://localhost:8787").unwrap(),
            ("localhost".to_string(), 8787)
        );
        assert!(parse_http_url("https://localhost:8787").is_err());
    }

    #[test]
    fn explain_uses_latest_or_specific_decision_endpoint() {
        assert_eq!(
            explain_path(&[]),
            "/_authport/authorization/explain".to_string()
        );
        assert_eq!(
            explain_path(&strings(&["evt_1"])),
            "/_authport/authorization/decisions/evt_1/explain".to_string()
        );
    }

    #[test]
    fn agent_commands_validate_required_arguments_before_network_io() {
        assert!(agent(&strings(&["create", "--tenant", "acme"]))
            .unwrap_err()
            .message
            .contains("--name"));
        assert!(agent(&strings(&["show", "agent:invoice"]))
            .unwrap_err()
            .message
            .contains("--tenant"));
        assert_eq!(escape_path("invoice agent"), "invoice%20agent");
    }
}
