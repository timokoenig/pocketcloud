//! The public records of an installation, written from the laptop with the DNS token: the domain and its wildcard
//! point at the server, CAA limits issuance to Let's Encrypt, and `_acme-challenge` is delegated to the server
//! itself (NS acme-ns.<domain> with glue), so no DNS token ever lives on the server.
use anyhow::{bail, Context, Result};

use crate::cli::DnsArgs;
use crate::hetzner::{relative_name, Hetzner};
use crate::install::Installation;

/// Write every record of every domain; returns one line per record for the console.
pub async fn apply(dns: &Hetzner, domains: &[String], ipv4: Option<&str>, ipv6: Option<&str>) -> Result<Vec<String>> {
    let mut lines = Vec::new();
    let v4: Vec<String> = ipv4.into_iter().map(str::to_string).collect();
    let v6: Vec<String> = ipv6.into_iter().map(str::to_string).collect();
    if v4.is_empty() && v6.is_empty() {
        bail!("the server has no address yet");
    }
    for d in domains {
        let zone = dns.zone_for(d).await.with_context(|| format!("no zone for {d} in the DNS project"))?;
        let rel = |host: &str| relative_name(host, &zone.name);
        for host in [d.clone(), format!("*.{d}"), format!("acme-ns.{d}")] {
            if !v4.is_empty() {
                dns.rrset_set(&zone.name, &rel(&host), "A", 300, &v4).await?;
            }
            if !v6.is_empty() {
                dns.rrset_set(&zone.name, &rel(&host), "AAAA", 300, &v6).await?;
            }
            lines.push(format!("{host} → {}", v4.iter().chain(v6.iter()).cloned().collect::<Vec<_>>().join(", ")));
        }
        // the challenge name is a zone of its own, served by the server
        let challenge = format!("_acme-challenge.{d}");
        let _ = dns.rrset_delete(&zone.name, &rel(&challenge), "TXT").await;
        dns.rrset_set(&zone.name, &rel(&challenge), "NS", 300, &[format!("acme-ns.{d}.")]).await?;
        lines.push(format!("{challenge} NS acme-ns.{d}"));
        if dns.rrset(&zone.name, &rel(d), "CAA").await?.is_none() {
            dns.rrset_set(&zone.name, &rel(d), "CAA", 3600, &["0 issue \"letsencrypt.org\"".to_string()]).await?;
            lines.push(format!("{d} CAA 0 issue letsencrypt.org"));
        }
    }
    Ok(lines)
}

/// `pocketcloud dns <name>`: (re)write the records, for example after a rebuild changed the address.
pub async fn run(args: DnsArgs) -> Result<()> {
    let inst = Installation::load(&args.name)?;
    let token = std::fs::read_to_string(inst.dir()?.join("hetzner-dns.token")).context("hetzner-dns.token")?.trim().to_string();
    let dns = Hetzner::new(&token);
    let lines = apply(&dns, &inst.domains, inst.server.ipv4.as_deref(), inst.server.ipv6.as_deref()).await?;
    for l in lines {
        println!("  {l}");
    }
    println!("records written; the server answers _acme-challenge itself, certificates need no token on it");
    Ok(())
}
