//! The public records of an installation: the domain and its wildcard point at the server, `acme-ns` names the
//! server as a nameserver, `_acme-challenge` is delegated to it (NS acme-ns.<domain>, so no DNS token ever lives
//! on the server) and CAA limits issuance to Let's Encrypt. Setup writes them through the provider's API when
//! there is one (Hetzner DNS) or prints them for any other provider and then asks the zone's own nameservers
//! whether they exist.
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};

use crate::hetzner::{relative_name, Hetzner};
use crate::server::dns::query;

/// One record set as the zone should hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub host: String,
    pub rtype: &'static str,
    pub ttl: u32,
    pub values: Vec<String>,
    /// Only written when the name has no such record yet (CAA: the owner may have a policy of their own)
    pub keep_existing: bool,
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.host, self.rtype, self.values.join(", "))
    }
}

/// The records of one domain, in the order they are written.
pub fn plan_domain(d: &str, ipv4: Option<&str>, ipv6: Option<&str>) -> Vec<Record> {
    let mut out = Vec::new();
    let rec = |host: String, rtype: &'static str, ttl: u32, values: Vec<String>| Record { host, rtype, ttl, values, keep_existing: false };
    for host in [d.to_string(), format!("*.{d}"), format!("acme-ns.{d}")] {
        if let Some(v4) = ipv4 {
            out.push(rec(host.clone(), "A", 300, vec![v4.to_string()]));
        }
        if let Some(v6) = ipv6 {
            out.push(rec(host.clone(), "AAAA", 300, vec![v6.to_string()]));
        }
    }
    // the challenge name is a zone of its own, served by the server
    out.push(rec(format!("_acme-challenge.{d}"), "NS", 300, vec![format!("acme-ns.{d}.")]));
    out.push(Record { host: d.to_string(), rtype: "CAA", ttl: 3600, values: vec!["0 issue \"letsencrypt.org\"".into()], keep_existing: true });
    out
}

/// The records of every domain.
pub fn plan(domains: &[String], ipv4: Option<&str>, ipv6: Option<&str>) -> Result<Vec<Record>> {
    if ipv4.is_none() && ipv6.is_none() {
        bail!("the server has no address yet");
    }
    Ok(domains.iter().flat_map(|d| plan_domain(d, ipv4, ipv6)).collect())
}

/// What a DNS provider's API has to offer. Hosts are full names without a trailing dot; the implementation turns
/// them into whatever the provider wants. A second provider (Cloudflare, …) is one more `impl` of this.
pub trait DnsApi {
    /// The name of the zone that holds `host`
    async fn zone_for(&self, host: &str) -> Result<String>;
    /// Values of the record set, None when there is none
    async fn get(&self, zone: &str, host: &str, rtype: &str) -> Result<Option<Vec<String>>>;
    /// Create or replace the record set
    async fn set(&self, zone: &str, host: &str, rtype: &str, ttl: u32, values: &[String]) -> Result<()>;
    /// Delete the record set; not an error when there is none
    async fn delete(&self, zone: &str, host: &str, rtype: &str) -> Result<()>;
}

impl DnsApi for Hetzner {
    async fn zone_for(&self, host: &str) -> Result<String> {
        Ok(Hetzner::zone_for(self, host).await?.name)
    }

    async fn get(&self, zone: &str, host: &str, rtype: &str) -> Result<Option<Vec<String>>> {
        Ok(self.rrset(zone, &relative_name(host, zone), rtype).await?.map(|s| s.records.into_iter().map(|r| r.value).collect()))
    }

    async fn set(&self, zone: &str, host: &str, rtype: &str, ttl: u32, values: &[String]) -> Result<()> {
        self.rrset_set(zone, &relative_name(host, zone), rtype, ttl, values).await
    }

    async fn delete(&self, zone: &str, host: &str, rtype: &str) -> Result<()> {
        self.rrset_delete(zone, &relative_name(host, zone), rtype).await
    }
}

/// Write every record of every domain through the provider's API; returns one line per record for the console.
pub async fn apply<P: DnsApi>(dns: &P, domains: &[String], ipv4: Option<&str>, ipv6: Option<&str>) -> Result<Vec<String>> {
    plan(domains, ipv4, ipv6)?;
    let mut lines = Vec::new();
    for d in domains {
        let zone = dns.zone_for(d).await.with_context(|| format!("no zone for {d} at the DNS provider"))?;
        for r in plan_domain(d, ipv4, ipv6) {
            if r.keep_existing && dns.get(&zone, &r.host, r.rtype).await?.is_some() {
                continue;
            }
            if r.rtype == "NS" {
                // a TXT record at the challenge name (left by a setup that still used a token) would shadow the delegation
                let _ = dns.delete(&zone, &r.host, "TXT").await;
            }
            dns.set(&zone, &r.host, r.rtype, r.ttl, &r.values).await?;
            lines.push(r.to_string());
        }
    }
    Ok(lines)
}

/// Delete the records setup wrote, as far as they still point at this server (`ips`); one line per step. A
/// domain whose zone the provider does not hold gets its records listed so the owner can delete them elsewhere.
pub async fn remove<P: DnsApi>(dns: &P, domains: &[String], ips: &[String]) -> Vec<String> {
    let (v4, v6) = split_ips(ips);
    let mut lines = Vec::new();
    for d in domains {
        let zone = match dns.zone_for(d).await {
            Ok(z) => z,
            Err(e) => {
                lines.push(format!("{d}: {e:#}; delete these records yourself:"));
                lines.extend(plan_domain(d, v4.as_deref(), v6.as_deref()).iter().map(|r| format!("  {r}")));
                continue;
            }
        };
        for r in plan_domain(d, v4.as_deref(), v6.as_deref()) {
            let what = format!("{} {}", r.host, r.rtype);
            let current = match dns.get(&zone, &r.host, r.rtype).await {
                Ok(Some(c)) => c,
                Ok(None) => continue,
                Err(e) => {
                    lines.push(format!("{what}: {e:#}"));
                    continue;
                }
            };
            let ours = match r.rtype {
                "A" | "AAAA" => current.iter().all(|v| ips.contains(v)),
                "CAA" => current.len() == 1 && current[0].contains("letsencrypt.org"),
                _ => true,
            };
            if !ours {
                lines.push(format!("{what} points elsewhere, left alone"));
                continue;
            }
            match dns.delete(&zone, &r.host, r.rtype).await {
                Ok(()) => lines.push(format!("removed {what}")),
                Err(e) => lines.push(format!("{what}: {e:#}")),
            }
        }
    }
    lines
}

fn split_ips(ips: &[String]) -> (Option<String>, Option<String>) {
    let v4 = ips.iter().find(|ip| ip.parse::<IpAddr>().map(|a| a.is_ipv4()).unwrap_or(false)).cloned();
    let v6 = ips.iter().find(|ip| ip.parse::<IpAddr>().map(|a| a.is_ipv6()).unwrap_or(false)).cloned();
    (v4, v6)
}

/// The records as a table for someone who creates them by hand.
pub fn table(records: &[Record]) -> String {
    let w = records.iter().map(|r| r.host.len()).max().unwrap_or(0);
    let mut s = String::new();
    s.push_str(&format!("  {:<w$}  {:<5} {:>5}  value\n", "name", "type", "ttl"));
    for r in records {
        s.push_str(&format!("  {:<w$}  {:<5} {:>5}  {}\n", r.host, r.rtype, r.ttl, r.values.join(" ")));
    }
    s
}

/// Public resolvers used to find a zone's nameservers; the records themselves are asked from those, so normally no
/// cache sits between the provider and the check.
const RESOLVERS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];

/// Ask the zone's own nameservers for the planned records of `domains`; returns what is missing or different,
/// empty when everything is in place.
pub async fn check(domains: &[String], records: &[Record]) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for d in domains {
        let (zone, servers) = authoritative_servers(d).await?;
        for r in records.iter().filter(|r| r.host == *d || r.host.ends_with(&format!(".{d}"))) {
            if let Some(p) = check_record(r, &servers).await {
                problems.push(format!("{p} (zone {zone})"));
            }
        }
    }
    Ok(problems)
}

/// The zone that holds `host` as seen from the outside, with the addresses of its nameservers: walks up the
/// name until a recursive resolver reports an NS set.
async fn authoritative_servers(host: &str) -> Result<(String, Vec<SocketAddr>)> {
    let labels: Vec<&str> = host.split('.').collect();
    for i in 0..labels.len().saturating_sub(1) {
        let candidate = labels[i..].join(".");
        let names = recursive(&candidate, RecordType::NS).await?;
        let ns: Vec<String> = names
            .iter()
            .filter_map(|r| match &r.data {
                RData::NS(n) => Some(n.0.to_utf8().trim_end_matches('.').to_string()),
                _ => None,
            })
            .collect();
        if ns.is_empty() {
            continue;
        }
        let mut servers = Vec::new();
        for n in &ns {
            if let Ok(addrs) = tokio::net::lookup_host((n.as_str(), 53)).await {
                servers.extend(addrs.filter(|a| a.is_ipv4()));
            }
        }
        if servers.is_empty() {
            bail!("the nameservers of {candidate} ({}) have no address", ns.join(", "));
        }
        return Ok((candidate, servers));
    }
    bail!("no nameservers found for {host}; is the domain registered and its zone created?")
}

/// Answers of the first public resolver that replies.
async fn recursive(name: &str, rt: RecordType) -> Result<Vec<hickory_proto::rr::Record>> {
    let mut last = anyhow!("no resolver answered");
    for r in RESOLVERS {
        match query(r.parse()?, name, rt, true).await {
            Ok(m) => return Ok(m.answers),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// One record against the zone's nameservers; None when it is in place.
async fn check_record(r: &Record, servers: &[SocketAddr]) -> Option<String> {
    // the wildcard is asked for as a name nobody has, which only the wildcard can answer
    let name = match r.host.strip_prefix("*.") {
        Some(rest) => format!("pocketcloud-probe-{:08x}.{rest}", rand::random::<u32>()),
        None => r.host.clone(),
    };
    let rt = match r.rtype {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "NS" => RecordType::NS,
        "CAA" => RecordType::CAA,
        _ => return None,
    };
    // the first nameserver that gives a real answer; one that refuses or fails is skipped. Recursion is asked for
    // although these servers are authoritative: some networks intercept port 53 and refuse queries without it.
    let mut resp = None;
    let mut last = String::from("no answer");
    for s in servers {
        match query(*s, &name, rt, true).await {
            Ok(m) if matches!(m.metadata.response_code, ResponseCode::NoError | ResponseCode::NXDomain) => {
                resp = Some(m);
                break;
            }
            Ok(m) => last = format!("{s} answered {}", m.metadata.response_code),
            Err(e) => last = format!("{e:#}"),
        }
    }
    let Some(resp) = resp else { return Some(format!("{} {}: the zone's nameservers gave no usable answer ({last})", r.host, r.rtype)) };
    // a delegation comes back as a referral: the NS records sit in the authority section
    let found: Vec<String> = resp
        .answers
        .iter()
        .chain(resp.authorities.iter())
        .filter(|a| a.record_type() == rt && a.name.to_utf8().trim_end_matches('.').eq_ignore_ascii_case(&name))
        .map(|a| a.data.to_string())
        .collect();
    match r.rtype {
        "CAA" => {
            // optional: the record only matters when the owner has one that leaves Let's Encrypt out
            if !found.is_empty() && !found.iter().any(|v| v.contains("letsencrypt.org")) {
                return Some(format!("{} CAA does not allow letsencrypt.org: {}", r.host, found.join(", ")));
            }
            None
        }
        "NS" => {
            let want = r.values[0].trim_end_matches('.').to_lowercase();
            if found.iter().any(|v| v.trim_end_matches('.').eq_ignore_ascii_case(&want)) {
                None
            } else if found.is_empty() {
                Some(format!("{} NS missing: no delegation to {want}", r.host))
            } else {
                Some(format!("{} NS points to {} instead of {want}", r.host, found.join(", ")))
            }
        }
        _ => {
            let want = &r.values[0];
            if found.iter().any(|v| v == want) {
                None
            } else if found.is_empty() {
                Some(format!("{} {} missing", r.host, r.rtype))
            } else {
                Some(format!("{} {} is {} instead of {want}", r.host, r.rtype, found.join(", ")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_lists_every_record_once() {
        let p = plan(&["example.com".into(), "staging.example.com".into()], Some("1.2.3.4"), Some("2001:db8::1")).unwrap();
        // per domain: three names × two address families, the delegation and CAA
        assert_eq!(p.len(), 16);
        let ns = p.iter().find(|r| r.rtype == "NS").unwrap();
        assert_eq!(ns.host, "_acme-challenge.example.com");
        assert_eq!(ns.values, vec!["acme-ns.example.com."]);
        assert!(p.iter().filter(|r| r.rtype == "CAA").all(|r| r.keep_existing));
        assert_eq!(plan(&["example.com".into()], Some("1.2.3.4"), None).unwrap().len(), 5);
        assert!(plan(&["example.com".into()], None, None).is_err());
    }

    #[test]
    fn table_is_readable() {
        let t = table(&plan(&["example.com".into()], Some("1.2.3.4"), None).unwrap());
        assert!(t.contains("*.example.com"));
        assert!(t.contains("_acme-challenge.example.com  NS"));
        assert!(t.contains("0 issue \"letsencrypt.org\""));
    }

    #[test]
    fn ips_split_by_family() {
        let (v4, v6) = split_ips(&["2001:db8::1".into(), "1.2.3.4".into()]);
        assert_eq!(v4.as_deref(), Some("1.2.3.4"));
        assert_eq!(v6.as_deref(), Some("2001:db8::1"));
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Needs the network: the check must find the zone's nameservers and report our records as missing, not
    /// fail. (example.com is no good here: its nameservers refuse direct queries.) `cargo test live -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn check_against_a_real_zone() {
        for d in ["cloudflare.com", "www.cloudflare.com"] {
            let domains = vec![d.to_string()];
            let records = plan(&domains, Some("203.0.113.1"), None).unwrap();
            let problems = check(&domains, &records).await.unwrap();
            for p in &problems {
                println!("{d}: {p}");
            }
            assert!(problems.iter().any(|p| p.starts_with(&format!("{d} A is ")) || p.starts_with(&format!("{d} A missing"))));
            assert!(problems.iter().any(|p| p.contains("_acme-challenge") && p.contains("missing")));
            assert!(problems.iter().any(|p| p.starts_with("acme-ns.") && p.contains("missing")));
        }
    }
}
