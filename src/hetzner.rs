//! Minimal Hetzner Cloud API client: servers, firewalls, ssh keys, actions, DNS zones and record sets.
#![allow(dead_code)] // API models carry fields we do not read yet
use anyhow::{anyhow, bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::Duration;

const BASE: &str = "https://api.hetzner.cloud/v1";

#[derive(Clone)]
pub struct Hetzner {
    http: reqwest::Client,
    token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub status: String,
    pub public_net: PublicNet,
    pub server_type: Named,
    /// Newer API responses carry `location`, older ones `datacenter.location`
    #[serde(default)]
    pub location: Option<Named>,
    #[serde(default)]
    pub datacenter: Option<Datacenter>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Server {
    pub fn location_name(&self) -> String {
        self.location
            .as_ref()
            .map(|l| l.name.clone())
            .or_else(|| self.datacenter.as_ref().map(|d| d.location.name.clone()))
            .unwrap_or_default()
    }

    pub fn ipv4(&self) -> Option<String> {
        self.public_net.ipv4.as_ref().map(|i| i.ip.clone())
    }
    /// Hetzner assigns a /64; the host uses ::1 of it.
    pub fn ipv6(&self) -> Option<String> {
        self.public_net.ipv6.as_ref().map(|i| i.ip.trim_end_matches("::/64").to_string() + "::1")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicNet {
    pub ipv4: Option<IpInfo>,
    pub ipv6: Option<IpInfo>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IpInfo {
    pub ip: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Named {
    pub id: i64,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Datacenter {
    pub location: Named,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerType {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub cores: u32,
    pub memory: f64,
    pub disk: u32,
    pub architecture: String,
    #[serde(default)]
    pub deprecated: Option<bool>,
    #[serde(default)]
    pub prices: Vec<Price>,
}

impl ServerType {
    pub fn monthly_gross(&self, location: &str) -> Option<f64> {
        self.prices
            .iter()
            .find(|p| p.location == location)
            .and_then(|p| p.price_monthly.gross.parse().ok())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Price {
    pub location: String,
    pub price_monthly: Amount,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Amount {
    pub gross: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Location {
    pub id: i64,
    pub name: String,
    pub city: String,
    pub country: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshKey {
    pub id: i64,
    pub name: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Firewall {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallRule {
    pub direction: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[serde(default)]
    pub source_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl FirewallRule {
    pub fn inbound(protocol: &str, port: Option<&str>, sources: &[&str], description: &str) -> Self {
        FirewallRule {
            direction: "in".into(),
            protocol: protocol.into(),
            port: port.map(|p| p.to_string()),
            source_ips: sources.iter().map(|s| s.to_string()).collect(),
            destination_ips: vec![],
            description: Some(description.into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Action {
    pub id: i64,
    pub status: String,
    pub command: String,
    pub error: Option<ActionError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Zone {
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub authoritative_nameservers: Option<AuthoritativeNameservers>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthoritativeNameservers {
    #[serde(default)]
    pub assigned: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RRSet {
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    pub ttl: Option<u32>,
    #[serde(default)]
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub value: String,
}

#[derive(Deserialize)]
struct ApiError {
    error: ApiErrorBody,
}

#[derive(Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
}

#[derive(Deserialize)]
struct Page<T> {
    #[serde(flatten)]
    items: BTreeMap<String, Vec<T>>,
    meta: Option<Meta>,
}

#[derive(Deserialize)]
struct Meta {
    pagination: Pagination,
}

#[derive(Deserialize)]
struct Pagination {
    next_page: Option<u32>,
}

impl Hetzner {
    pub fn new(token: &str) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("pocketcloud/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("http client");
        Hetzner { http, token: token.trim().to_string() }
    }

    async fn request<T: DeserializeOwned>(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<T> {
        let mut req = self.http.request(method.clone(), format!("{BASE}{path}")).bearer_auth(&self.token);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.with_context(|| format!("{method} {path}"))?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            if let Ok(e) = serde_json::from_str::<ApiError>(&text) {
                bail!("hetzner {method} {path}: {} ({})", e.error.message, e.error.code);
            }
            bail!("hetzner {method} {path}: http {status}: {text}");
        }
        if text.is_empty() {
            return serde_json::from_str("null").context("empty response");
        }
        serde_json::from_str(&text).with_context(|| format!("decode response of {method} {path}: {text}"))
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request(reqwest::Method::GET, path, None).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: Value) -> Result<T> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    async fn list<T: DeserializeOwned>(&self, path: &str, key: &str) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut page = 1;
        loop {
            let sep = if path.contains('?') { '&' } else { '?' };
            let p: Page<T> = self.get(&format!("{path}{sep}per_page=50&page={page}")).await?;
            let items = p.items.into_iter().find(|(k, _)| k == key).map(|(_, v)| v).unwrap_or_default();
            out.extend(items);
            match p.meta.and_then(|m| m.pagination.next_page) {
                Some(n) => page = n,
                None => return Ok(out),
            }
        }
    }

    pub async fn check_token(&self) -> Result<()> {
        let _: Value = self.get("/locations?per_page=1").await.context("token check")?;
        Ok(())
    }

    // ---- catalog ----

    pub async fn locations(&self) -> Result<Vec<Location>> {
        self.list("/locations", "locations").await
    }

    pub async fn server_types(&self) -> Result<Vec<ServerType>> {
        let all: Vec<ServerType> = self.list("/server_types", "server_types").await?;
        Ok(all.into_iter().filter(|t| t.deprecated != Some(true)).collect())
    }

    // ---- ssh keys ----

    pub async fn ssh_key_by_name(&self, name: &str) -> Result<Option<SshKey>> {
        let keys: Vec<SshKey> = self.list(&format!("/ssh_keys?name={name}"), "ssh_keys").await?;
        Ok(keys.into_iter().next())
    }

    pub async fn create_ssh_key(&self, name: &str, public_key: &str, labels: &BTreeMap<String, String>) -> Result<SshKey> {
        #[derive(Deserialize)]
        struct R {
            ssh_key: SshKey,
        }
        let r: R = self.post("/ssh_keys", json!({"name": name, "public_key": public_key.trim(), "labels": labels})).await?;
        Ok(r.ssh_key)
    }

    // ---- firewalls ----

    pub async fn firewall(&self, id: i64) -> Result<Firewall> {
        #[derive(Deserialize)]
        struct R {
            firewall: Firewall,
        }
        let r: R = self.get(&format!("/firewalls/{id}")).await?;
        Ok(r.firewall)
    }

    pub async fn firewall_by_name(&self, name: &str) -> Result<Option<Firewall>> {
        let f: Vec<Firewall> = self.list(&format!("/firewalls?name={name}"), "firewalls").await?;
        Ok(f.into_iter().next())
    }

    pub async fn create_firewall(&self, name: &str, rules: &[FirewallRule], labels: &BTreeMap<String, String>) -> Result<Firewall> {
        #[derive(Deserialize)]
        struct R {
            firewall: Firewall,
        }
        let r: R = self.post("/firewalls", json!({"name": name, "rules": rules, "labels": labels})).await?;
        Ok(r.firewall)
    }

    pub async fn set_firewall_rules(&self, id: i64, rules: &[FirewallRule]) -> Result<()> {
        #[derive(Deserialize)]
        struct R {
            actions: Vec<Action>,
        }
        let r: R = self.post(&format!("/firewalls/{id}/actions/set_rules"), json!({"rules": rules})).await?;
        for a in r.actions {
            self.wait_action(a.id).await?;
        }
        Ok(())
    }

    // ---- servers ----

    pub async fn server(&self, id: i64) -> Result<Server> {
        #[derive(Deserialize)]
        struct R {
            server: Server,
        }
        let r: R = self.get(&format!("/servers/{id}")).await?;
        Ok(r.server)
    }

    pub async fn server_by_name(&self, name: &str) -> Result<Option<Server>> {
        let s: Vec<Server> = self.list(&format!("/servers?name={name}"), "servers").await?;
        Ok(s.into_iter().next())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_server(
        &self,
        name: &str,
        server_type: &str,
        image: &str,
        location: &str,
        ssh_key_id: i64,
        firewall_id: i64,
        user_data: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<Server> {
        #[derive(Deserialize)]
        struct R {
            server: Server,
            action: Action,
        }
        let body = json!({
            "name": name,
            "server_type": server_type,
            "image": image,
            "location": location,
            "ssh_keys": [ssh_key_id],
            "firewalls": [{"firewall": firewall_id}],
            "user_data": user_data,
            "labels": labels,
            "start_after_create": true,
            "public_net": {"enable_ipv4": true, "enable_ipv6": true},
        });
        let r: R = self.post("/servers", body).await?;
        self.wait_action(r.action.id).await?;
        self.server(r.server.id).await
    }

    pub async fn server_action(&self, id: i64, action: &str) -> Result<()> {
        #[derive(Deserialize)]
        struct R {
            action: Action,
        }
        let r: R = self.post(&format!("/servers/{id}/actions/{action}"), json!({})).await?;
        self.wait_action(r.action.id).await
    }

    pub async fn wait_action(&self, id: i64) -> Result<()> {
        #[derive(Deserialize)]
        struct R {
            action: Action,
        }
        for _ in 0..240 {
            let r: R = self.get(&format!("/actions/{id}")).await?;
            match r.action.status.as_str() {
                "success" => return Ok(()),
                "error" => {
                    let e = r.action.error.map(|e| format!("{} ({})", e.message, e.code)).unwrap_or_default();
                    bail!("hetzner action {} failed: {e}", r.action.command);
                }
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }
        bail!("hetzner action {id} did not finish in time")
    }

    // ---- dns ----

    pub async fn zones(&self) -> Result<Vec<Zone>> {
        self.list("/zones", "zones").await
    }

    /// The zone that holds `host`: the longest zone name that is a suffix of it.
    pub async fn zone_for(&self, host: &str) -> Result<Zone> {
        let host = host.trim_end_matches('.');
        let mut best: Option<Zone> = None;
        for z in self.zones().await? {
            if (host == z.name || host.ends_with(&format!(".{}", z.name)))
                && best.as_ref().map(|b| z.name.len() > b.name.len()).unwrap_or(true) {
                    best = Some(z);
                }
        }
        best.ok_or_else(|| anyhow!("no DNS zone for {host} in this Hetzner project"))
    }

    pub async fn rrset(&self, zone: &str, name: &str, rtype: &str) -> Result<Option<RRSet>> {
        #[derive(Deserialize)]
        struct R {
            rrset: RRSet,
        }
        let path = format!("/zones/{zone}/rrsets/{name}/{rtype}");
        match self.get::<R>(&path).await {
            Ok(r) => Ok(Some(r.rrset)),
            Err(e) if e.to_string().contains("not_found") => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Create the record set or replace its records.
    pub async fn rrset_set(&self, zone: &str, name: &str, rtype: &str, ttl: u32, values: &[String]) -> Result<()> {
        let records: Vec<Record> = values.iter().map(|v| Record { value: v.clone() }).collect();
        if let Some(existing) = self.rrset(zone, name, rtype).await? {
            let same = existing.records.len() == records.len()
                && existing.records.iter().all(|r| values.contains(&r.value));
            if same {
                return Ok(());
            }
            #[derive(Deserialize)]
            struct R {
                action: Action,
            }
            let r: R = self
                .post(&format!("/zones/{zone}/rrsets/{name}/{rtype}/actions/set_records"), json!({"records": records}))
                .await?;
            self.wait_action(r.action.id).await
        } else {
            #[derive(Deserialize)]
            struct R {
                action: Action,
            }
            let r: R = self
                .post(
                    &format!("/zones/{zone}/rrsets"),
                    json!({"name": name, "type": rtype, "ttl": ttl, "records": records, "labels": {"pocketcloud": "true"}}),
                )
                .await?;
            self.wait_action(r.action.id).await
        }
    }

    pub async fn rrset_delete(&self, zone: &str, name: &str, rtype: &str) -> Result<()> {
        if self.rrset(zone, name, rtype).await?.is_none() {
            return Ok(());
        }
        let _: Value = self.request(reqwest::Method::DELETE, &format!("/zones/{zone}/rrsets/{name}/{rtype}"), None).await?;
        Ok(())
    }

    // ---- teardown ----

    /// Detach the firewall from a server; needed before the firewall can be deleted.
    pub async fn firewall_remove_from_server(&self, firewall: i64, server: i64) -> Result<()> {
        let _: Value = self
            .post(&format!("/firewalls/{firewall}/actions/remove_from_resources"), json!({"remove_from": [{"type": "server", "server": {"id": server}}]}))
            .await?;
        Ok(())
    }

    pub async fn delete_firewall(&self, id: i64) -> Result<()> {
        let _: Value = self.request(reqwest::Method::DELETE, &format!("/firewalls/{id}"), None).await?;
        Ok(())
    }

    pub async fn delete_ssh_key(&self, id: i64) -> Result<()> {
        let _: Value = self.request(reqwest::Method::DELETE, &format!("/ssh_keys/{id}"), None).await?;
        Ok(())
    }

    pub async fn delete_server(&self, id: i64) -> Result<()> {
        let _: Value = self.request(reqwest::Method::DELETE, &format!("/servers/{id}"), None).await?;
        Ok(())
    }
}

/// Record set name relative to the zone: "@" for the zone itself, "*" for its wildcard, "api.staging" for deeper names.
pub fn relative_name(host: &str, zone: &str) -> String {
    let host = host.trim_end_matches('.');
    if host == zone {
        return "@".into();
    }
    host.strip_suffix(&format!(".{zone}")).unwrap_or(host).to_string()
}

/// Hetzner stores TXT values quoted.
pub fn txt_value(v: &str) -> String {
    format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative() {
        assert_eq!(relative_name("example.com", "example.com"), "@");
        assert_eq!(relative_name("*.example.com", "example.com"), "*");
        assert_eq!(relative_name("_acme-challenge.staging.example.com", "example.com"), "_acme-challenge.staging");
    }
}
