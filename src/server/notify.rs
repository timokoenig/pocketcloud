//! Where alerts go: e-mail over SMTP, a webhook, and a heartbeat URL. Opened and resolved alerts are
//! collected for a minute and sent as one message, so a storm is one mail.
use anyhow::{Context, Result};
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::config::{EmailConfig, NotifyConfig};
use super::db;
use super::state::Shared;

#[derive(Clone, Debug, serde::Serialize)]
pub struct Change {
    /// opened | resolved
    pub event: String,
    pub key: String,
    pub severity: String,
    pub summary: String,
    pub at: String,
}

fn mailer(c: &EmailConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    let builder = match c.smtp_tls.as_str() {
        "implicit" => AsyncSmtpTransport::<Tokio1Executor>::relay(&c.smtp_host)?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&c.smtp_host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&c.smtp_host)?,
    };
    let mut builder = builder.port(c.smtp_port).timeout(Some(std::time::Duration::from_secs(30)));
    if !c.smtp_user.is_empty() {
        builder = builder.credentials(Credentials::new(c.smtp_user.clone(), c.smtp_password.clone()));
    }
    Ok(builder.build())
}

pub async fn send_mail(c: &EmailConfig, subject: &str, body: &str) -> Result<()> {
    let from: Mailbox = c.from.parse().with_context(|| format!("notify.email.from {:?}", c.from))?;
    let mut m = Message::builder().from(from).subject(one_line(subject, 200)).header(ContentType::TEXT_PLAIN);
    for to in &c.to {
        m = m.to(to.parse::<Mailbox>().with_context(|| format!("notify.email.to {to:?}"))?);
    }
    let message = m.body(body.to_string()).context("build mail")?;
    mailer(c)?.send(message).await.context("send mail")?;
    Ok(())
}

pub async fn send_webhook(url: &str, token: &str, payload: &serde_json::Value) -> Result<()> {
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build()?;
    let mut req = client.post(url).json(payload);
    if !token.is_empty() {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.context("webhook request")?;
    if !resp.status().is_success() {
        anyhow::bail!("webhook answered {}", resp.status());
    }
    Ok(())
}

/// The subject: the worst thing first, then counts.
pub fn subject(name: &str, changes: &[Change]) -> String {
    let opened: Vec<&Change> = changes.iter().filter(|c| c.event == "opened").collect();
    let worst = if opened.iter().any(|c| c.severity == "critical") {
        "[CRITICAL]"
    } else if opened.iter().any(|c| c.severity == "warning") {
        "[WARNING]"
    } else if !opened.is_empty() {
        "[INFO]"
    } else {
        "[RESOLVED]"
    };
    let first = changes.iter().find(|c| c.event == "opened").or(changes.first()).map(|c| c.summary.as_str()).unwrap_or("");
    let rest = changes.len().saturating_sub(1);
    let tail = if rest > 0 { format!(" (+{rest} more)") } else { String::new() };
    format!("{worst} {name}: {}{tail}", one_line(first, 100))
}

pub fn body(name: &str, interface: &str, changes: &[Change]) -> String {
    let mut out = format!("pocketcloud {name}\n\n");
    for c in changes {
        out += &format!("{} {} {}\n    {}\n", c.at.chars().take(16).collect::<String>().replace('T', " "), c.event.to_uppercase(), c.severity, c.summary);
    }
    out += &format!("\nhttps://{interface}/alerts (VPN)\n");
    out
}

/// Deliver one batch to every configured channel; errors are recorded, never fatal.
pub async fn deliver(state: &Shared, changes: &[Change]) {
    let cfg: &NotifyConfig = &state.config.notify;
    let name = &state.config.name;
    let mut errors = Vec::new();
    if let Some(e) = &cfg.email {
        if let Err(err) = send_mail(e, &subject(name, changes), &body(name, &state.config.interface_host, changes)).await {
            errors.push(format!("email: {err:#}"));
        }
    }
    if let Some(w) = &cfg.webhook {
        let payload = serde_json::json!({"installation": name, "changes": changes});
        if let Err(err) = send_webhook(&w.url, &w.token, &payload).await {
            errors.push(format!("webhook: {err:#}"));
        }
    }
    let _ = db::kv_set(&state.db, "notify.last_at", &db::now()).await;
    let _ = db::kv_set(&state.db, "notify.last_error", &errors.join("; ")).await;
    if errors.is_empty() {
        tracing::info!("notified: {} change(s)", changes.len());
    } else {
        tracing::warn!("notification problems: {}", errors.join("; "));
    }
}

/// GET the heartbeat URL; the dead man's switch behind it alerts when the pings stop.
pub async fn heartbeat(state: &Shared) {
    let url = &state.config.notify.heartbeat_url;
    if url.is_empty() {
        return;
    }
    let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).build();
    let res = match client {
        Ok(c) => c.get(url).send().await.map(|r| r.status().is_success()).unwrap_or(false),
        Err(_) => false,
    };
    let _ = db::kv_set(&state.db, "notify.heartbeat_ok", if res { "1" } else { "0" }).await;
    let _ = db::kv_set(&state.db, "notify.heartbeat_at", &db::now()).await;
}

pub fn one_line(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut space = true;
    for c in text.chars() {
        if c.is_control() || c.is_whitespace() {
            if !space {
                out.push(' ');
                space = true;
            }
        } else {
            out.push(c);
            space = false;
        }
    }
    let out = out.trim_end().to_string();
    if out.chars().count() > max {
        format!("{}…", out.chars().take(max - 1).collect::<String>())
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects() {
        let c = |event: &str, sev: &str, s: &str| Change { event: event.into(), key: "k".into(), severity: sev.into(), summary: s.into(), at: "t".into() };
        assert_eq!(subject("test", &[c("opened", "warning", "disk at 90%"), c("opened", "critical", "docker down")]), "[CRITICAL] test: disk at 90% (+1 more)");
        assert_eq!(subject("test", &[c("resolved", "warning", "disk at 90%")]), "[RESOLVED] test: disk at 90%");
        assert_eq!(one_line("a\n\n b\tc", 10), "a b c");
    }
}
