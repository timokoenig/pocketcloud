//! WireGuard keys and config rendering. The hub runs on the server as wg0, every client is a peer.
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const HUB_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);
pub const VPN_CIDR: &str = "10.8.0.0/24";
/// Full scope clients: 10.8.0.2 - 10.8.0.126
pub const VPN_FULL_CIDR: &str = "10.8.0.0/25";
/// Web scope clients: 10.8.0.129 - 10.8.0.254
pub const VPN_WEB_CIDR: &str = "10.8.0.128/25";
pub const DEFAULT_PORT: u16 = 51820;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub enum Scope {
    /// ssh, the interface, every app network
    Full,
    /// the interface and the internal routes only
    Web,
}

impl Scope {
    pub fn parse(s: &str) -> Result<Scope> {
        match s {
            "full" => Ok(Scope::Full),
            "web" => Ok(Scope::Web),
            _ => Err(anyhow!("scope must be full or web")),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Full => "full",
            Scope::Web => "web",
        }
    }
    pub fn range(&self) -> std::ops::RangeInclusive<u8> {
        match self {
            Scope::Full => 2..=126,
            Scope::Web => 129..=254,
        }
    }
    /// What the client routes through the tunnel.
    pub fn allowed_ips(&self, apps_cidr: &str) -> String {
        match self {
            Scope::Full => format!("{VPN_CIDR}, {apps_cidr}"),
            Scope::Web => format!("{HUB_IP}/32"),
        }
    }
}

pub struct KeyPair {
    pub private: String,
    pub public: String,
}

pub fn generate_keypair() -> KeyPair {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    KeyPair { private: B64.encode(secret.to_bytes()), public: B64.encode(public.to_bytes()) }
}

pub fn public_key_of(private: &str) -> Result<String> {
    let bytes = B64.decode(private.trim()).map_err(|_| anyhow!("private key is not base64"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("private key must be 32 bytes"))?;
    let secret = x25519_dalek::StaticSecret::from(arr);
    Ok(B64.encode(x25519_dalek::PublicKey::from(&secret).to_bytes()))
}

pub fn generate_psk() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    B64.encode(b)
}

/// Pick the first free address of the scope.
pub fn next_ip(scope: Scope, used: &[Ipv4Addr]) -> Result<Ipv4Addr> {
    for last in scope.range() {
        let ip = Ipv4Addr::new(10, 8, 0, last);
        if !used.contains(&ip) {
            return Ok(ip);
        }
    }
    Err(anyhow!("no free VPN address for scope {}", scope.as_str()))
}

pub struct Peer {
    pub name: String,
    pub public_key: String,
    pub psk: String,
    pub ip: Ipv4Addr,
}

pub fn hub_config(private_key: &str, port: u16, peers: &[Peer]) -> String {
    let mut s = format!("[Interface]\nAddress = {HUB_IP}/24\nListenPort = {port}\nPrivateKey = {private_key}\n");
    for p in peers {
        s += &format!(
            "\n[Peer]\n# {}\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = {}/32\n",
            p.name, p.public_key, p.psk, p.ip
        );
    }
    s
}

pub struct ClientConfig<'a> {
    pub private_key: &'a str,
    pub ip: Ipv4Addr,
    pub hub_public_key: &'a str,
    pub psk: &'a str,
    pub endpoint_host: &'a str,
    pub endpoint_port: u16,
    pub scope: Scope,
    pub apps_cidr: &'a str,
}

pub fn client_config(c: &ClientConfig) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\nDNS = {HUB_IP}\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = {}:{}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        c.private_key,
        c.ip,
        c.hub_public_key,
        c.psk,
        c.endpoint_host,
        c.endpoint_port,
        c.scope.allowed_ips(c.apps_cidr)
    )
}

pub fn qr(text: &str) -> Result<String> {
    let code = qrcode::QrCode::new(text.as_bytes())?;
    Ok(code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let k = generate_keypair();
        assert_eq!(public_key_of(&k.private).unwrap(), k.public);
    }

    #[test]
    fn ips() {
        assert_eq!(next_ip(Scope::Full, &[]).unwrap(), Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(next_ip(Scope::Web, &[Ipv4Addr::new(10, 8, 0, 129)]).unwrap(), Ipv4Addr::new(10, 8, 0, 130));
    }
}
