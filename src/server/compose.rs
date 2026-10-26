//! Turns the compose file of an app into what actually runs: no published ports, no builds, no host paths,
//! one isolated network per app with static addresses, secrets as an env file.
use anyhow::{anyhow, bail, Context, Result};
use serde_yaml_ng::{Mapping, Value};

use crate::firewall;

pub struct Rendered {
    pub yaml: String,
    /// service name -> static address in the app network
    pub services: Vec<(String, String)>,
    #[allow(dead_code)]
    pub images: Vec<String>,
}

const FORBIDDEN_SERVICE_KEYS: &[&str] = &[
    "build",
    "cap_add",
    "devices",
    "pid",
    "network_mode",
    "ipc",
    "userns_mode",
    "cgroup_parent",
    "cgroup",
    "sysctls",
    "privileged",
    "secrets",
    "runtime",
    "platform",
    "external_links",
    "links",
];

fn key(s: &str) -> Value {
    Value::String(s.to_string())
}

fn app_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

pub fn validate_app_name(name: &str) -> Result<()> {
    if !app_name_ok(name) {
        bail!("app name must be 1-32 characters of a-z, 0-9 and dashes");
    }
    Ok(())
}

/// Parse and check a compose file without rendering, for the editor.
/// What the interface shows about a compose file without rendering it.
pub struct ServiceInfo {
    pub name: String,
    /// container port from `ports` or `expose`, a hint for a route
    pub port: Option<u16>,
    /// `environment` entries as written
    pub env: Vec<(String, String)>,
    /// hardening hints: what the service does not do that it could
    pub hints: Vec<String>,
}

pub struct Inspection {
    pub services: Vec<ServiceInfo>,
    /// `${NAME}` placeholders without a default, in order of appearance
    pub placeholders: Vec<String>,
}

pub fn inspect(compose: &str) -> Result<Inspection> {
    let doc: Value = serde_yaml_ng::from_str(compose).context("compose file is not valid YAML")?;
    let services = doc.get("services").and_then(|s| s.as_mapping()).ok_or_else(|| anyhow!("compose file has no services"))?;
    let mut out = Vec::new();
    for (name, svc) in services {
        let name = name.as_str().unwrap_or_default().to_string();
        let port = svc
            .get("ports")
            .and_then(|p| p.as_sequence())
            .and_then(|p| p.iter().find_map(container_port))
            .or_else(|| svc.get("expose").and_then(|e| e.as_sequence()).and_then(|e| e.iter().find_map(container_port)));
        let env = environment_entries(svc.get("environment"));
        let hints = hardening_hints(svc);
        out.push(ServiceInfo { name, port, env, hints });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Inspection { services: out, placeholders: placeholders(compose) })
}

fn hardening_hints(svc: &Value) -> Vec<String> {
    let mut h = Vec::new();
    let image = svc.get("image").and_then(|i| i.as_str()).unwrap_or("");
    if !image.contains("@sha256:") {
        let tag = image.rsplit('/').next().unwrap_or(image).split_once(':').map(|(_, t)| t);
        match tag {
            None => h.push("image has no tag, so `latest` is pulled; pin a version".into()),
            Some("latest") => h.push("image tag `latest` changes under you; pin a version".into()),
            _ => {}
        }
    }
    if svc.get("user").is_none() {
        h.push("no `user`: runs as root unless the image switches user itself".into());
    }
    if svc.get("read_only").and_then(|v| v.as_bool()) != Some(true) {
        h.push("not `read_only`: a writable root filesystem; add `tmpfs` for paths that need writes".into());
    }
    let drops_all = svc.get("cap_drop").and_then(|v| v.as_sequence()).map(|s| s.iter().any(|c| c.as_str().map(|c| c.eq_ignore_ascii_case("all")).unwrap_or(false))).unwrap_or(false);
    if !drops_all {
        h.push("no `cap_drop: [ALL]`: keeps the default capabilities".into());
    }
    if svc.get("healthcheck").is_none() {
        h.push("no `healthcheck`: deploys cannot wait for it to be healthy".into());
    }
    h
}

/// The container side of a `ports`/`expose` entry: "127.0.0.1:3000:3000", "8080:80/tcp", "80", or a mapping with `target`.
fn container_port(v: &Value) -> Option<u16> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Mapping(m) => return m.get("target").and_then(|t| t.as_u64()).and_then(|t| u16::try_from(t).ok()),
        _ => return None,
    };
    let s = s.split('/').next().unwrap_or("");
    let last = s.rsplit(':').next().unwrap_or("");
    last.split('-').next().unwrap_or("").parse().ok()
}

fn environment_entries(env: Option<&Value>) -> Vec<(String, String)> {
    match env {
        Some(Value::Mapping(m)) => m.iter().map(|(k, v)| (k.as_str().unwrap_or_default().to_string(), scalar_string(v))).collect(),
        Some(Value::Sequence(l)) => l
            .iter()
            .filter_map(|e| e.as_str())
            .map(|e| match e.split_once('=') {
                Some((k, v)) => (k.to_string(), v.to_string()),
                None => (e.to_string(), String::new()),
            })
            .collect(),
        _ => vec![],
    }
}

fn scalar_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => serde_yaml_ng::to_string(other).unwrap_or_default().trim().to_string(),
    }
}

/// `${NAME}` and `${NAME:?msg}` need a value; `${NAME:-x}` and `${NAME-x}` have one. `$$` is an escape.
fn placeholders(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find('$') {
        rest = &rest[i + 1..];
        if rest.starts_with('$') {
            rest = &rest[1..];
            continue;
        }
        let Some(inner) = rest.strip_prefix('{') else { continue };
        let Some(end) = inner.find('}') else { break };
        let body = &inner[..end];
        let name_end = body.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(body.len());
        let (name, tail) = body.split_at(name_end);
        let has_default = tail.starts_with(":-") || (tail.starts_with('-') && !tail.starts_with("-?"));
        if !name.is_empty() && !has_default && !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    }
    out
}

/// Set or remove (`value: None`) one `environment` entry of a service and return the rewritten file.
/// Round-trips through the YAML model, so comments and formatting are not kept.
pub fn set_environment(compose: &str, service: &str, name: &str, value: Option<&str>) -> Result<String> {
    let mut doc: Value = serde_yaml_ng::from_str(compose).context("compose file is not valid YAML")?;
    let svc = doc
        .get_mut("services")
        .and_then(|s| s.as_mapping_mut())
        .and_then(|s| s.get_mut(key(service)))
        .and_then(|s| s.as_mapping_mut())
        .ok_or_else(|| anyhow!("no service `{service}`"))?;
    match svc.get_mut(key("environment")) {
        Some(Value::Sequence(list)) => {
            list.retain(|e| e.as_str().map(|e| e.split_once('=').map(|(k, _)| k).unwrap_or(e) != name).unwrap_or(true));
            if let Some(v) = value {
                list.push(key(&format!("{name}={v}")));
            }
        }
        Some(Value::Mapping(m)) => match value {
            Some(v) => {
                m.insert(key(name), key(v));
            }
            None => {
                m.remove(key(name));
            }
        },
        _ => {
            if let Some(v) = value {
                let mut m = Mapping::new();
                m.insert(key(name), key(v));
                svc.insert(key("environment"), Value::Mapping(m));
            }
        }
    }
    Ok(serde_yaml_ng::to_string(&doc)?)
}

pub fn check(compose: &str) -> Result<Vec<String>> {
    let r = render(compose, "check", 1, "/run/pocketcloud/env")?;
    Ok(r.services.into_iter().map(|(n, _)| n).collect())
}

/// `env_dir` holds the secrets: `<app>.<service>.env` per service, written by deploy.
pub fn render(compose: &str, app: &str, net_index: u32, env_dir: &str) -> Result<Rendered> {
    let mut doc: Value = serde_yaml_ng::from_str(compose).context("compose file is not valid YAML")?;
    let root = doc.as_mapping_mut().ok_or_else(|| anyhow!("compose file must be a mapping"))?;
    root.remove(key("name"));
    root.remove(key("version"));
    if root.contains_key(key("secrets")) {
        bail!("top-level `secrets` is not supported; use the app's secrets, they arrive as environment variables");
    }
    if let Some(nets) = root.get(key("networks")) {
        let m = nets.as_mapping().ok_or_else(|| anyhow!("`networks` must be a mapping"))?;
        for (k, _) in m {
            if k.as_str() != Some("default") {
                bail!("only the `default` network is supported; every service of an app shares one isolated network");
            }
        }
    }
    if let Some(cfgs) = root.get(key("configs")).and_then(|c| c.as_mapping()) {
        for (name, cfg) in cfgs {
            if let Some(file) = cfg.get(key("file")).and_then(|f| f.as_str()) {
                check_relative_path(file).with_context(|| format!("config {}", name.as_str().unwrap_or("?")))?;
            }
        }
    }

    let services = root
        .get_mut(key("services"))
        .and_then(|s| s.as_mapping_mut())
        .ok_or_else(|| anyhow!("compose file needs a `services` mapping"))?;
    if services.is_empty() {
        bail!("compose file has no services");
    }
    let mut names: Vec<String> = services
        .keys()
        .map(|k| k.as_str().map(|s| s.to_string()).ok_or_else(|| anyhow!("service names must be strings")))
        .collect::<Result<_>>()?;
    names.sort();
    if names.len() > 200 {
        bail!("too many services for one app network");
    }

    let mut out_services = Vec::new();
    let mut images = Vec::new();
    for (i, name) in names.iter().enumerate() {
        if !app_name_ok(name) && !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("service name `{name}` must be alphanumeric with dashes or underscores");
        }
        let svc = services
            .get_mut(key(name))
            .and_then(|s| s.as_mapping_mut())
            .ok_or_else(|| anyhow!("service `{name}` must be a mapping"))?;
        for k in FORBIDDEN_SERVICE_KEYS {
            if svc.contains_key(key(k)) {
                bail!("service `{name}`: `{k}` is not allowed");
            }
        }
        let image = svc
            .get(key("image"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("service `{name}` needs an `image`; builds are not supported"))?;
        images.push(image.to_string());
        svc.remove(key("ports"));
        svc.remove(key("container_name"));
        if let Some(vols) = svc.get(key("volumes")).and_then(|v| v.as_sequence()) {
            for v in vols {
                check_volume(v).with_context(|| format!("service `{name}` volumes"))?;
            }
        }
        if !svc.contains_key(key("restart")) {
            svc.insert(key("restart"), key("unless-stopped"));
        }
        // no-new-privileges on top of whatever the user set
        let mut sec: Vec<Value> = svc
            .get(key("security_opt"))
            .and_then(|v| v.as_sequence())
            .cloned()
            .unwrap_or_default();
        if !sec.iter().any(|v| v.as_str().map(|s| s.starts_with("no-new-privileges")).unwrap_or(false)) {
            sec.push(key("no-new-privileges:true"));
        }
        svc.insert(key("security_opt"), Value::Sequence(sec));
        // secrets as env file, appended after the user's own
        let mut envs: Vec<Value> = match svc.get(key("env_file")) {
            Some(Value::String(s)) => vec![Value::String(s.clone())],
            Some(Value::Sequence(s)) => s.clone(),
            Some(_) => bail!("service `{name}`: `env_file` must be a string or list"),
            None => vec![],
        };
        for e in &envs {
            if let Some(p) = e.as_str() {
                check_relative_path(p).with_context(|| format!("service `{name}` env_file"))?;
            }
        }
        envs.push(key(&format!("{env_dir}/{app}.{name}.env")));
        svc.insert(key("env_file"), Value::Sequence(envs));
        // static address in the app network
        let ip = firewall::service_ip(net_index, i as u32);
        let mut net_entry = Mapping::new();
        net_entry.insert(key("ipv4_address"), key(&ip));
        let mut nets = Mapping::new();
        if let Some(existing) = svc.get(key("networks")) {
            match existing {
                Value::Sequence(s) => {
                    for n in s {
                        if n.as_str() != Some("default") {
                            bail!("service `{name}`: only the `default` network is supported");
                        }
                    }
                }
                Value::Mapping(m) => {
                    for (k, v) in m {
                        if k.as_str() != Some("default") {
                            bail!("service `{name}`: only the `default` network is supported");
                        }
                        if let Some(vm) = v.as_mapping() {
                            for (ek, ev) in vm {
                                if ek.as_str() != Some("ipv4_address") {
                                    net_entry.insert(ek.clone(), ev.clone());
                                }
                            }
                        }
                    }
                }
                _ => bail!("service `{name}`: `networks` must be a list or mapping"),
            }
        }
        nets.insert(key("default"), Value::Mapping(net_entry));
        svc.insert(key("networks"), Value::Mapping(nets));
        out_services.push((name.clone(), ip));
    }

    // the app network: one bridge named pc-<app>, 172.30.<n>.0/24
    let mut ipam_cfg = Mapping::new();
    ipam_cfg.insert(key("subnet"), key(&firewall::app_subnet(net_index)));
    ipam_cfg.insert(key("gateway"), key(&firewall::app_gateway(net_index)));
    let mut ipam = Mapping::new();
    ipam.insert(key("config"), Value::Sequence(vec![Value::Mapping(ipam_cfg)]));
    let mut opts = Mapping::new();
    opts.insert(key("com.docker.network.bridge.name"), key(&firewall::bridge_name(app)));
    let mut default = Mapping::new();
    default.insert(key("driver"), key("bridge"));
    default.insert(key("enable_ipv6"), Value::Bool(false));
    default.insert(key("driver_opts"), Value::Mapping(opts));
    default.insert(key("ipam"), Value::Mapping(ipam));
    let mut networks = Mapping::new();
    networks.insert(key("default"), Value::Mapping(default));
    root.insert(key("networks"), Value::Mapping(networks));

    let yaml = serde_yaml_ng::to_string(&doc)?;
    Ok(Rendered { yaml, services: out_services, images })
}

fn check_relative_path(p: &str) -> Result<()> {
    if p.starts_with("./") && !p.contains("..") {
        return Ok(());
    }
    bail!("path `{p}` must be relative to the app directory (start with ./); host paths are not allowed")
}

fn check_volume(v: &Value) -> Result<()> {
    match v {
        Value::String(s) => {
            let src = s.split(':').next().unwrap_or("");
            if s.contains(':') && (src.starts_with('/') || src.starts_with('~') || src.starts_with("..")) {
                bail!("bind mount of host path `{src}` is not allowed; use a named volume or ./files");
            }
            if src.starts_with('.') {
                check_relative_path(src)?;
            }
            Ok(())
        }
        Value::Mapping(m) => {
            let t = m.get(key("type")).and_then(|t| t.as_str()).unwrap_or("volume");
            match t {
                "volume" => Ok(()),
                "tmpfs" => Ok(()),
                "bind" => {
                    let src = m.get(key("source")).and_then(|s| s.as_str()).unwrap_or("");
                    check_relative_path(src)
                }
                other => bail!("volume type `{other}` is not allowed"),
            }
        }
        _ => bail!("volume entries must be strings or mappings"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspects() {
        let c = "services:\n  web:\n    image: x\n    ports: ['127.0.0.1:3000:3000']\n    environment:\n      A: '1'\n      B: ${SECRET}\n      C: ${OPT:-x}\n  db:\n    image: y\n    expose: [5432]\n    environment: ['PGUSER=app', 'PGPASSWORD=${PG}']\n";
        let i = inspect(c).unwrap();
        assert_eq!(i.services[0].name, "db");
        assert_eq!(i.services[0].port, Some(5432));
        assert_eq!(i.services[0].env, vec![("PGUSER".to_string(), "app".to_string()), ("PGPASSWORD".to_string(), "${PG}".to_string())]);
        assert_eq!(i.services[1].port, Some(3000));
        assert_eq!(i.placeholders, vec!["SECRET", "PG"]);
        assert!(i.services[1].hints.iter().any(|h| h.contains("no tag")));
        assert!(i.services[1].hints.iter().any(|h| h.contains("read_only")));
        let c2 = set_environment(c, "web", "A", Some("2")).unwrap();
        let c2 = set_environment(&c2, "db", "PGUSER", None).unwrap();
        let i2 = inspect(&c2).unwrap();
        assert_eq!(i2.services[1].env[0], ("A".to_string(), "2".to_string()));
        assert_eq!(i2.services[0].env, vec![("PGPASSWORD".to_string(), "${PG}".to_string())]);
        assert!(set_environment(c, "nope", "A", Some("2")).is_err());
    }

    const SAMPLE: &str = r#"
services:
  web:
    image: ghcr.io/me/web:1.2
    ports: ["8080:80"]
    environment:
      DB: ${DB_URL}
  db:
    image: postgres:17
    volumes:
      - data:/var/lib/postgresql/data
volumes:
  data: {}
"#;

    #[test]
    fn renders_sample() {
        let r = render(SAMPLE, "shop", 3, "/run/pocketcloud/env/shop.env").unwrap();
        assert_eq!(r.services, vec![("db".to_string(), "172.30.3.10".into()), ("web".to_string(), "172.30.3.11".into())]);
        assert!(!r.yaml.contains("ports"));
        assert!(r.yaml.contains("pc-shop"));
        assert!(r.yaml.contains("172.30.3.0/24"));
        assert!(r.yaml.contains("no-new-privileges:true"));
        assert!(r.yaml.contains("/run/pocketcloud/env/shop.env"));
        assert_eq!(r.images, vec!["postgres:17", "ghcr.io/me/web:1.2"]);
    }

    #[test]
    fn rejects_dangerous() {
        assert!(render("services:\n  a:\n    build: .\n", "a", 1, "/e").is_err());
        assert!(render("services:\n  a:\n    image: x\n    privileged: true\n", "a", 1, "/e").is_err());
        assert!(render("services:\n  a:\n    image: x\n    volumes: [\"/etc:/etc\"]\n", "a", 1, "/e").is_err());
        assert!(render("services:\n  a:\n    image: x\n    volumes: [\"/var/run/docker.sock:/s\"]\n", "a", 1, "/e").is_err());
        assert!(render("services:\n  a:\n    image: x\n    networks: [other]\n", "a", 1, "/e").is_err());
        assert!(render("services:\n  a:\n    image: x\n    volumes: [\"./files/x:/x\"]\n", "a", 1, "/e").is_ok());
    }

    #[test]
    fn names() {
        assert!(validate_app_name("my-app").is_ok());
        assert!(validate_app_name("My_App").is_err());
        assert!(validate_app_name("-a").is_err());
    }
}
