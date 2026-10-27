//! Caddy configuration: a public listener on the public addresses, an internal one on the WireGuard address.
//! Certificates come from files the daemon obtained; Caddy's own ACME is off.
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::Path;

use crate::wireguard::HUB_IP;

pub const ADMIN: &str = "http://127.0.0.1:2019";

pub struct RouteSpec {
    pub host: String,
    pub upstream: String,
    pub public: bool,
    pub waf: bool,
    pub headers: bool,
}

/// Coraza with the OWASP Core Rule Set, compiled into the Caddy build. Request bodies are inspected (up to the
/// CRS default of 13 MB, bigger ones are rejected), response bodies are not.
/// The CRS allows only GET, HEAD, POST and OPTIONS by default (rule 911100), which blocks every PUT, PATCH and DELETE
/// of a REST API; 900200 widens that before the rules load.
pub const WAF_DIRECTIVES: &str = "Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecAction \"id:900200,phase:1,pass,nolog,t:none,setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'\"
Include @owasp_crs/*.conf
SecRuleEngine On
SecResponseBodyAccess Off
";

pub struct CaddySpec<'a> {
    pub public_ips: &'a [String],
    /// configured domains; names below them without a route redirect to the domain itself
    pub domains: &'a [String],
    pub routes: &'a [RouteSpec],
    pub interface_host: &'a str,
    pub interface_upstream: &'a str,
    /// the Caddy binary has the Coraza module; without it the WAF route would make Caddy reject the whole config
    pub waf_available: bool,
    /// (fullchain.pem, key.pem) pairs that exist on disk
    pub certificates: &'a [(String, String)],
}

fn listen(ips: &[String], port: u16) -> Vec<String> {
    ips.iter()
        .map(|ip| if ip.contains(':') { format!("[{ip}]:{port}") } else { format!("{ip}:{port}") })
        .collect()
}

fn proxy_route(host: &str, upstream: &str) -> Value {
    json!({
        "match": [{"host": [host]}],
        "handle": [{
            "handler": "reverse_proxy",
            "upstreams": [{"dial": upstream}],
            "headers": {"request": {"set": {"X-Forwarded-Proto": ["https"]}}}
        }],
        "terminal": true
    })
}

/// Anything under the domain that has no route goes to the domain itself. Temporary redirect: the name may get
/// an app later and browsers cache permanent ones.
fn fallback_route(domain: &str) -> Value {
    json!({
        "match": [{"host": [format!("*.{domain}")]}],
        "handle": [{
            "handler": "static_response",
            "status_code": 302,
            "headers": {"Location": [format!("https://{domain}/")]}
        }],
        "terminal": true
    })
}

/// One WAF in front of all protected hosts; not terminal, so the matching proxy route runs after it.
fn waf_route(hosts: Vec<String>) -> Value {
    json!({
        "match": [{"host": hosts}],
        "handle": [{
            "handler": "waf",
            "load_owasp_crs": true,
            "directives": WAF_DIRECTIVES
        }]
    })
}

/// Default security headers, set on the proxied response (deferred) so the app cannot lose them by accident.
fn headers_route(hosts: Vec<String>) -> Value {
    json!({
        "match": [{"host": hosts}],
        "handle": [{
            "handler": "headers",
            "response": {
                "deferred": true,
                "set": {
                    "Strict-Transport-Security": ["max-age=31536000; includeSubDomains"],
                    "X-Content-Type-Options": ["nosniff"],
                    "Referrer-Policy": ["strict-origin-when-cross-origin"],
                    "X-Frame-Options": ["SAMEORIGIN"]
                }
            }
        }]
    })
}

pub fn render(s: &CaddySpec) -> Value {
    let mut public_routes: Vec<Value> = Vec::new();
    let waf_hosts: Vec<String> = s.routes.iter().filter(|r| r.public && r.waf).map(|r| r.host.clone()).collect();
    if s.waf_available && !waf_hosts.is_empty() {
        public_routes.push(waf_route(waf_hosts));
    }
    let header_hosts: Vec<String> = s.routes.iter().filter(|r| r.public && r.headers).map(|r| r.host.clone()).collect();
    if !header_hosts.is_empty() {
        public_routes.push(headers_route(header_hosts));
    }
    public_routes.extend(s.routes.iter().filter(|r| r.public).map(|r| proxy_route(&r.host, &r.upstream)));
    public_routes.extend(s.domains.iter().map(|d| fallback_route(d)));
    let mut internal_routes: Vec<Value> = vec![proxy_route(s.interface_host, s.interface_upstream)];
    internal_routes.extend(s.routes.iter().filter(|r| !r.public).map(|r| proxy_route(&r.host, &r.upstream)));
    let certs: Vec<Value> = s.certificates.iter().map(|(c, k)| json!({"certificate": c, "key": k})).collect();
    json!({
        "admin": {"listen": "127.0.0.1:2019", "config": {"persist": true}},
        "logging": {"logs": {
            "default": {"writer": {"output": "stderr"}, "level": "WARN", "exclude": ["http.log.access.public"]},
            "access": {"writer": {"output": "stderr"}, "level": "INFO", "include": ["http.log.access.public"], "encoder": {"format": "json"}}
        }},
        "apps": {
            "http": {
                "servers": {
                    "public": {
                        "listen": listen(s.public_ips, 443),
                        "routes": public_routes,
                        "logs": {"default_logger_name": "public"},
                        "automatic_https": {"disable": true},
                        "tls_connection_policies": [{}],
                        // Off: every name shares one address and the wildcard certificate, so HTTP/2 clients reuse a
                        // connection opened for one app for another (RFC 7540 9.1.1). With it on, Caddy answers those
                        // with 421, and iOS (CFNetwork) does not retry: images from a second host never load. Routing
                        // is by Host either way; names without a public route still get no app.
                        "strict_sni_host": false
                    },
                    "public_http": {
                        "listen": listen(s.public_ips, 80),
                        "routes": [{
                            "handle": [{
                                "handler": "static_response",
                                "status_code": 308,
                                "headers": {"Location": ["https://{http.request.host}{http.request.uri}"]}
                            }]
                        }],
                        "automatic_https": {"disable": true}
                    },
                    "internal": {
                        "listen": [format!("{HUB_IP}:443")],
                        "routes": internal_routes,
                        "automatic_https": {"disable": true},
                        "tls_connection_policies": [{}],
                        "strict_sni_host": true
                    }
                }
            },
            "tls": {
                "certificates": {"load_files": certs}
            }
        }
    })
}

pub async fn push(config: &Value) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client.post(format!("{ADMIN}/load")).json(config).send().await.context("caddy admin api")?;
    if !resp.status().is_success() {
        let t = resp.text().await.unwrap_or_default();
        anyhow::bail!("caddy rejected the config: {t}");
    }
    Ok(())
}

pub fn cert_files(certs_dir: &Path, domains: &[String]) -> Vec<(String, String)> {
    domains
        .iter()
        .filter_map(|d| {
            let c = certs_dir.join(d).join("fullchain.pem");
            let k = certs_dir.join(d).join("key.pem");
            (c.exists() && k.exists()).then(|| (c.display().to_string(), k.display().to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders() {
        let routes = vec![
            RouteSpec { host: "shop.example.com".into(), upstream: "172.30.1.10:80".into(), public: true, waf: true, headers: true },
            RouteSpec { host: "tools.example.com".into(), upstream: "172.30.2.10:3000".into(), public: false, waf: true, headers: true },
        ];
        let ips = vec!["1.2.3.4".to_string(), "2a01::1".to_string()];
        let certs = vec![("/c/fullchain.pem".to_string(), "/c/key.pem".to_string())];
        let domains = vec!["example.com".to_string()];
        let v = render(&CaddySpec {
            public_ips: &ips,
            domains: &domains,
            routes: &routes,
            interface_host: "pocketcloud.example.com",
            interface_upstream: "127.0.0.1:7788",
            waf_available: true,
            certificates: &certs,
        });
        let s = v.to_string();
        assert!(s.contains("[2a01::1]:443"));
        assert!(s.contains("10.8.0.1:443"));
        let public = v["apps"]["http"]["servers"]["public"]["routes"].as_array().unwrap();
        assert_eq!(public.len(), 4);
        assert_eq!(public[0]["handle"][0]["handler"], "waf");
        assert_eq!(public[0]["match"][0]["host"][0], "shop.example.com");
        assert!(public[0].get("terminal").is_none());
        assert_eq!(public[1]["handle"][0]["handler"], "headers");
        assert_eq!(public[1]["handle"][0]["response"]["deferred"], true);
        assert_eq!(public[2]["handle"][0]["handler"], "reverse_proxy");
        assert_eq!(public[3]["match"][0]["host"][0], "*.example.com");
        assert_eq!(public[3]["handle"][0]["headers"]["Location"][0], "https://example.com/");
        assert_eq!(v["apps"]["http"]["servers"]["public"]["logs"]["default_logger_name"], "public");
        assert_eq!(v["apps"]["http"]["servers"]["internal"]["routes"].as_array().unwrap().len(), 2);
    }
}
