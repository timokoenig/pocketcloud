//! Wildcard certificates from Let's Encrypt with the DNS-01 challenge answered by the daemon's own nameserver:
//! `_acme-challenge.<domain>` is delegated to the server, so no DNS token is needed.
use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use std::path::Path;
use std::time::Duration;

use crate::server::dns::{self, AcmeTxt};

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
pub async fn issue(domain: &str, acme_dir: &Path, certs_dir: &Path, email: &str, directory: &str, txt: &AcmeTxt, public_ip: Option<std::net::IpAddr>) -> Result<Issued> {
    let account = account(acme_dir, email, directory).await?;
    let identifiers = [Identifier::Dns(domain.to_string()), Identifier::Dns(format!("*.{domain}"))];
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await.context("new order")?;

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
        txt.set(domain, values.clone()).await;
        tracing::info!("acme: challenge values for {domain} are being served");
        self_check(domain, &values, public_ip).await;
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
        txt.clear(domain).await;
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

/// Ask our own public listener once, so a broken delegation shows in the log before Let's Encrypt complains.
async fn self_check(domain: &str, expected: &[String], public_ip: Option<std::net::IpAddr>) {
    let Some(ip) = public_ip else { return };
    let name = format!("_acme-challenge.{domain}");
    for _ in 0..5 {
        match dns::query_txt(std::net::SocketAddr::new(ip, 53), &name).await {
            Ok(vals) if expected.iter().all(|e| vals.contains(e)) => return,
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }
    tracing::warn!("acme: the challenge nameserver on {ip}:53 did not answer for {name}; is port 53 open and the NS delegation in place?");
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
