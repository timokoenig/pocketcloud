//! The VPN resolver on 10.8.0.1:53: internal names answer with the hub address, everything else is forwarded.
//! Also a tiny client used to watch ACME challenge records.
use anyhow::{anyhow, Context, Result};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{rdata, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::wireguard::HUB_IP;

#[derive(Clone, Default)]
pub struct InternalNames(Arc<RwLock<HashSet<String>>>);

impl InternalNames {
    pub async fn set(&self, names: impl IntoIterator<Item = String>) {
        let mut g = self.0.write().await;
        *g = names.into_iter().map(|n| n.trim_end_matches('.').to_ascii_lowercase()).collect();
    }
    async fn contains(&self, name: &str) -> bool {
        self.0.read().await.contains(&name.trim_end_matches('.').to_ascii_lowercase())
    }
}

pub async fn serve(bind: SocketAddr, upstreams: Vec<SocketAddr>, names: InternalNames) -> Result<()> {
    let sock = Arc::new(UdpSocket::bind(bind).await.with_context(|| format!("bind dns on {bind}"))?);
    tracing::info!("vpn dns listening on {bind}");
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("dns recv: {e}");
                continue;
            }
        };
        let query = buf[..n].to_vec();
        let sock = sock.clone();
        let names = names.clone();
        let upstreams = upstreams.clone();
        tokio::spawn(async move {
            if let Some(resp) = handle(&query, &names, &upstreams).await {
                let _ = sock.send_to(&resp, from).await;
            }
        });
    }
}

async fn handle(query: &[u8], names: &InternalNames, upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let msg = Message::from_bytes(query).ok()?;
    let q = msg.queries().first()?.clone();
    let qname = q.name().to_utf8();
    if names.contains(&qname).await {
        let mut resp = Message::new();
        resp.set_id(msg.id())
            .set_message_type(MessageType::Response)
            .set_op_code(msg.op_code())
            .set_recursion_desired(msg.recursion_desired())
            .set_recursion_available(true)
            .set_authoritative(true)
            .set_response_code(ResponseCode::NoError);
        resp.add_query(q.clone());
        if matches!(q.query_type(), RecordType::A | RecordType::ANY) {
            let rec = Record::from_rdata(q.name().clone(), 60, RData::A(rdata::A(HUB_IP)));
            resp.add_answer(rec);
        }
        return resp.to_bytes().ok();
    }
    forward(query, upstreams).await
}

async fn forward(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for up in upstreams {
        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        if sock.send_to(query, up).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 4096];
        match tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => return Some(buf[..n].to_vec()),
            _ => continue,
        }
    }
    None
}

/// TXT values of `name` as answered by `server`.
pub async fn query_txt(server: SocketAddr, name: &str) -> Result<Vec<String>> {
    let mut msg = Message::new();
    msg.set_id(rand::random())
        .set_message_type(MessageType::Query)
        .set_recursion_desired(false)
        .add_query(hickory_proto::op::Query::query(Name::from_utf8(name)?, RecordType::TXT));
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&msg.to_bytes()?, server).await?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("dns timeout from {server}"))??;
    let resp = Message::from_bytes(&buf[..n])?;
    let mut out = Vec::new();
    for a in resp.answers() {
        if let Some(RData::TXT(t)) = a.data() {
            out.push(t.txt_data().iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join(""));
        }
    }
    Ok(out)
}


// ---------------------------------------------------------------------------------------------------------------
// The public challenge nameserver: `_acme-challenge.<domain>` is delegated to this server (NS acme-ns.<domain>),
// so certificates need no DNS token anywhere. It answers exactly those names and refuses everything else.
// ---------------------------------------------------------------------------------------------------------------

/// Current challenge values per domain, set by the certificate code while an order is open.
#[derive(Clone, Default)]
pub struct AcmeTxt(Arc<RwLock<std::collections::HashMap<String, Vec<String>>>>);

impl AcmeTxt {
    pub async fn set(&self, domain: &str, values: Vec<String>) {
        self.0.write().await.insert(domain.to_ascii_lowercase(), values);
    }
    pub async fn clear(&self, domain: &str) {
        self.0.write().await.remove(&domain.to_ascii_lowercase());
    }
    async fn get(&self, domain: &str) -> Vec<String> {
        self.0.read().await.get(domain).cloned().unwrap_or_default()
    }
}

#[derive(Clone)]
pub struct PublicZone {
    pub domains: Vec<String>,
    pub ips: Vec<std::net::IpAddr>,
    pub txt: AcmeTxt,
}

/// Listen on every public address, UDP and TCP. Never returns while the sockets are fine.
pub async fn serve_public(zone: PublicZone, binds: Vec<SocketAddr>) -> Result<()> {
    let mut tasks = Vec::new();
    for bind in binds {
        let udp = Arc::new(UdpSocket::bind(bind).await.with_context(|| format!("bind challenge dns on {bind}"))?);
        let tcp = tokio::net::TcpListener::bind(bind).await.with_context(|| format!("bind challenge dns tcp on {bind}"))?;
        tracing::info!("challenge nameserver listening on {bind}");
        let z = zone.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 1232];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else { continue };
                let query = buf[..n].to_vec();
                let udp = udp.clone();
                let z = z.clone();
                tokio::spawn(async move {
                    if let Some(resp) = answer_public(&query, &z).await {
                        let _ = udp.send_to(&resp, from).await;
                    }
                });
            }
        }));
        let z = zone.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else { continue };
                let z = z.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut len = [0u8; 2];
                    if tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len)).await.ok().and_then(|r| r.ok()).is_none() {
                        return;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    if n == 0 || n > 4096 {
                        return;
                    }
                    let mut query = vec![0u8; n];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    if let Some(resp) = answer_public(&query, &z).await {
                        let _ = stream.write_all(&(resp.len() as u16).to_be_bytes()).await;
                        let _ = stream.write_all(&resp).await;
                    }
                });
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

fn soa(apex: &Name, domain: &str) -> Result<Record> {
    let mname = Name::from_utf8(format!("acme-ns.{domain}."))?;
    let rname = Name::from_utf8(format!("hostmaster.{domain}."))?;
    let serial = chrono::Utc::now().timestamp() as u32;
    Ok(Record::from_rdata(apex.clone(), 60, RData::SOA(rdata::SOA::new(mname, rname, serial, 3600, 600, 86400, 60))))
}

async fn answer_public(query: &[u8], zone: &PublicZone) -> Option<Vec<u8>> {
    let msg = Message::from_bytes(query).ok()?;
    let q = msg.queries().first()?.clone();
    let qname = q.name().to_utf8().trim_end_matches('.').to_ascii_lowercase();
    let mut resp = Message::new();
    resp.set_id(msg.id())
        .set_message_type(MessageType::Response)
        .set_op_code(msg.op_code())
        .set_recursion_desired(msg.recursion_desired())
        .set_recursion_available(false)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError);
    resp.add_query(q.clone());
    let qt = q.query_type();
    for domain in &zone.domains {
        let challenge = format!("_acme-challenge.{domain}");
        let ns_host = format!("acme-ns.{domain}");
        if qname == challenge {
            let apex = Name::from_utf8(format!("{challenge}."))
                .ok()?;
            match qt {
                RecordType::TXT | RecordType::ANY => {
                    let values = zone.txt.get(domain).await;
                    for v in values {
                        resp.add_answer(Record::from_rdata(apex.clone(), 60, RData::TXT(rdata::TXT::new(vec![v]))));
                    }
                    if resp.answer_count() == 0 {
                        resp.add_name_server(soa(&apex, domain).ok()?);
                    }
                }
                RecordType::NS => {
                    resp.add_answer(Record::from_rdata(apex.clone(), 60, RData::NS(rdata::NS(Name::from_utf8(format!("{ns_host}.")).ok()?))));
                }
                RecordType::SOA => {
                    resp.add_answer(soa(&apex, domain).ok()?);
                }
                _ => {
                    resp.add_name_server(soa(&apex, domain).ok()?);
                }
            }
            return resp.to_bytes().ok();
        }
        if qname == ns_host {
            let name = Name::from_utf8(format!("{ns_host}.")).ok()?;
            for ip in &zone.ips {
                match (ip, qt) {
                    (std::net::IpAddr::V4(a), RecordType::A | RecordType::ANY) => resp.add_answer(Record::from_rdata(name.clone(), 300, RData::A(rdata::A(*a)))),
                    (std::net::IpAddr::V6(a), RecordType::AAAA | RecordType::ANY) => resp.add_answer(Record::from_rdata(name.clone(), 300, RData::AAAA(rdata::AAAA(*a)))),
                    _ => &mut resp,
                };
            }
            return resp.to_bytes().ok();
        }
    }
    resp.set_response_code(ResponseCode::Refused).set_authoritative(false);
    resp.to_bytes().ok()
}

#[cfg(test)]
mod public_tests {
    use super::*;

    async fn ask(zone: &PublicZone, name: &str, rt: RecordType) -> Message {
        let mut q = Message::new();
        q.set_id(7).set_message_type(MessageType::Query).add_query(hickory_proto::op::Query::query(Name::from_utf8(name).unwrap(), rt));
        Message::from_bytes(&answer_public(&q.to_bytes().unwrap(), zone).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn answers_only_the_delegated_names() {
        let txt = AcmeTxt::default();
        txt.set("example.com", vec!["abc".into(), "def".into()]).await;
        let zone = PublicZone { domains: vec!["example.com".into()], ips: vec!["1.2.3.4".parse().unwrap(), "2a01::1".parse().unwrap()], txt };
        let r = ask(&zone, "_acme-challenge.example.com.", RecordType::TXT).await;
        assert_eq!(r.answer_count(), 2);
        assert!(r.authoritative());
        let r = ask(&zone, "_acme-challenge.example.com.", RecordType::NS).await;
        assert!(matches!(r.answers()[0].data(), Some(RData::NS(_))));
        let r = ask(&zone, "acme-ns.example.com.", RecordType::A).await;
        assert!(matches!(r.answers()[0].data(), Some(RData::A(_))));
        let r = ask(&zone, "www.example.com.", RecordType::A).await;
        assert_eq!(r.response_code(), ResponseCode::Refused);
        let r = ask(&zone, "_acme-challenge.other.org.", RecordType::TXT).await;
        assert_eq!(r.response_code(), ResponseCode::Refused);
        zone.txt.clear("example.com").await;
        let r = ask(&zone, "_acme-challenge.example.com.", RecordType::TXT).await;
        assert_eq!(r.answer_count(), 0);
        assert_eq!(r.name_server_count(), 1);
    }
}
