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

pub async fn resolve_host(host: &str) -> Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host(format!("{host}:53")).await?.collect())
}
