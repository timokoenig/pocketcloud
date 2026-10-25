//! Wildcard certificates from Let's Encrypt with the DNS-01 challenge in Hetzner DNS.
use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::path::Path;
use std::time::Duration;

use crate::hetzner::{relative_name, txt_value, Hetzner};
use crate::server::dns;

pub struct Issued {
    pub not_after: chrono::DateTime<chrono::Utc>,
}

async fn account(acme_dir: &Path, email: &str, directory: &str) -> Result<Account> {
    let creds_path = acme_dir.join("account.json");
    if creds_path.exists() {
        let s = std::fs::read_to_string(&creds_path)?;
        let creds: AccountCredentials = serde_json::from_str(&s).context("acme account credentials")?;
        return Ok(Account::builder()?.from_credentials(creds).await?);
    }
    let contact = format!("mailto:{email}");
    let contacts: Vec<&str> = if email.is_empty() { vec![] } else { vec![&contact] };
    let (account, creds) = Account::builder()?
        .create(
            &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
            directory.to_string(),
            None,
        )
        .await
        .context("create acme account")?;
    std::fs::create_dir_all(acme_dir)?;
    crate::install::write_private(&creds_path, &serde_json::to_string(&creds)?)?;
    Ok(account)
}

/// Obtain `domain` + `*.domain`, write fullchain.pem and key.pem into certs_dir/<domain>/.
pub async fn issue(domain: &str, acme_dir: &Path, certs_dir: &Path, email: &str, directory: &str, dns_api: &Hetzner) -> Result<Issued> {
    let account = account(acme_dir, email, directory).await?;
    let identifiers = [Identifier::Dns(domain.to_string()), Identifier::Dns(format!("*.{domain}"))];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await.context("new order")?;

    let zone = dns_api.zone_for(domain).await?;
    let record_name = relative_name(&format!("_acme-challenge.{domain}"), &zone.name);

    // both identifiers (domain and *.domain) challenge the same TXT name, so all values go into one record set
    let mut values = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(a) = authorizations.next().await {
            let mut a = a.context("authorization")?;
            match a.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                s => bail!("authorization in unexpected state {s:?}"),
            }
            let challenge = a.challenge(ChallengeType::Dns01).ok_or_else(|| anyhow!("no dns-01 challenge offered"))?;
            values.push(challenge.key_authorization().dns_value());
        }
    }

    if !values.is_empty() {
        let txt: Vec<String> = values.iter().map(|v| txt_value(v)).collect();
        dns_api.rrset_set(&zone.name, &record_name, "TXT", 60, &txt).await.context("set challenge record")?;
        tracing::info!("acme: challenge record set for {domain}, waiting for the nameservers");
        wait_for_txt(&zone, &format!("_acme-challenge.{domain}"), &values).await?;
        {
            let mut authorizations = order.authorizations();
            while let Some(a) = authorizations.next().await {
                let mut a = a.context("authorization")?;
                if a.status != AuthorizationStatus::Pending {
                    continue;
                }
                if let Some(mut challenge) = a.challenge(ChallengeType::Dns01) {
                    challenge.set_ready().await.context("challenge ready")?;
                }
            }
        }
        let status = order.poll_ready(&RetryPolicy::default()).await;
        let _ = dns_api.rrset_delete(&zone.name, &record_name, "TXT").await;
        match status.context("waiting for the order")? {
            OrderStatus::Ready | OrderStatus::Valid => {}
            s => bail!("acme order not ready: {s:?} (challenge failed)"),
        }
    }

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string(), format!("*.{domain}")])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key = rcgen::KeyPair::generate()?;
    let csr = params.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await.context("finalize")?;
    let chain = order.poll_certificate(&RetryPolicy::default()).await.context("fetch certificate")?;
    let dir = certs_dir.join(domain);
    std::fs::create_dir_all(&dir)?;
    crate::install::write_private(&dir.join("key.pem.new"), &key.serialize_pem())?;
    std::fs::write(dir.join("fullchain.pem.new"), &chain)?;
    std::fs::rename(dir.join("key.pem.new"), dir.join("key.pem"))?;
    std::fs::rename(dir.join("fullchain.pem.new"), dir.join("fullchain.pem"))?;
    let not_after = not_after(&chain)?;
    tracing::info!("acme: certificate for {domain} and *.{domain} valid until {not_after}");
    Ok(Issued { not_after })
}

async fn wait_for_txt(zone: &crate::hetzner::Zone, name: &str, expected: &[String]) -> Result<()> {
    let servers = zone.authoritative_nameservers.as_ref().map(|a| a.assigned.clone()).unwrap_or_default();
    let mut addrs = Vec::new();
    for s in &servers {
        if let Ok(a) = dns::resolve_host(s.trim_end_matches('.')).await {
            addrs.extend(a.into_iter().filter(|a| a.is_ipv4()).take(1));
        }
    }
    if addrs.is_empty() {
        tracing::warn!("acme: no authoritative nameservers known for {}, waiting 60s blind", zone.name);
        tokio::time::sleep(Duration::from_secs(60)).await;
        return Ok(());
    }
    for attempt in 0..60 {
        let mut all_ok = true;
        for a in &addrs {
            match dns::query_txt(*a, name).await {
                Ok(vals) if expected.iter().all(|e| vals.contains(e)) => {}
                _ => {
                    all_ok = false;
                    break;
                }
            }
        }
        if all_ok {
            // a little extra for Let's Encrypt's own resolvers
            tokio::time::sleep(Duration::from_secs(5)).await;
            return Ok(());
        }
        if attempt % 10 == 9 {
            tracing::info!("acme: still waiting for {name} on the nameservers");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    bail!("challenge record did not appear on the authoritative nameservers in time")
}

pub fn not_after(pem_chain: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    let first = pem_chain
        .split("-----END CERTIFICATE-----")
        .next()
        .ok_or_else(|| anyhow!("no certificate in chain"))?
        .to_string()
        + "-----END CERTIFICATE-----\n";
    let (_, pem) = x509_parser::pem::parse_x509_pem(first.as_bytes()).map_err(|e| anyhow!("pem: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents).map_err(|e| anyhow!("x509: {e}"))?;
    let ts = cert.validity().not_after.timestamp();
    chrono::DateTime::from_timestamp(ts, 0).ok_or_else(|| anyhow!("bad timestamp"))
}

pub fn not_after_of_file(path: &Path) -> Option<chrono::DateTime<chrono::Utc>> {
    let s = std::fs::read_to_string(path).ok()?;
    not_after(&s).ok()
}
