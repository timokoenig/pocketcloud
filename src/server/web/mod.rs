//! The interface: server-rendered HTML, no client-side build, reachable through the VPN only.
mod apps;
mod auth;
mod pages;
mod views;

use anyhow::Result;
use askama::Template;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;

use crate::server::state::Shared;

pub struct WebError(anyhow::Error);

impl<E: Into<anyhow::Error>> From<E> for WebError {
    fn from(e: E) -> Self {
        WebError(e.into())
    }
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        tracing::error!("web: {:#}", self.0);
        let body = views::ErrorPage { message: format!("{:#}", self.0) }.render().unwrap_or_else(|_| "error".into());
        (StatusCode::INTERNAL_SERVER_ERROR, Html(body)).into_response()
    }
}

pub type R<T = Response> = std::result::Result<T, WebError>;

pub fn html<T: Template>(t: T) -> R {
    Ok(Html(t.render()?).into_response())
}

/// Redirect carrying a message shown by the layout.
pub fn back(path: &str, msg: Option<&str>, err: Option<&str>) -> Response {
    let mut url = path.to_string();
    if let Some(m) = msg {
        url += &format!("?msg={}", urlenc(m));
    } else if let Some(e) = err {
        url += &format!("?error={}", urlenc(e));
    }
    Redirect::to(&url).into_response()
}

pub fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out += &format!("%{b:02X}"),
        }
    }
    out
}

/// Cross-site writes are refused: modern browsers tell us where a request came from.
async fn csrf_guard(req: Request, next: Next) -> Response {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        let site = req.headers().get("sec-fetch-site").and_then(|v| v.to_str().ok());
        let origin_ok = match req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            Some(origin) => {
                let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
                origin.strip_prefix("https://").or_else(|| origin.strip_prefix("http://")) == Some(host)
            }
            None => true,
        };
        if !origin_ok || matches!(site, Some("cross-site") | Some("same-site")) {
            return (StatusCode::FORBIDDEN, "cross-origin request refused").into_response();
        }
    }
    next.run(req).await
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

async fn health() -> &'static str {
    "ok"
}

async fn css() -> Response {
    let mut r = Response::new(Body::from(include_str!("../../../static/app.css")));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
    r
}

async fn js() -> Response {
    let mut r = Response::new(Body::from(include_str!("../../../static/app.js")));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/javascript"));
    r
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/", get(pages::dashboard))
        .route("/login", get(auth::login_page).post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/apps/new", get(apps::new_page).post(apps::create))
        .route("/apps/{id}", get(apps::show))
        .route("/apps/{id}/edit", get(apps::edit_page).post(apps::update_compose))
        .route("/apps/{id}/deploy", post(apps::deploy))
        .route("/apps/{id}/start", post(apps::start))
        .route("/apps/{id}/stop", post(apps::stop))
        .route("/apps/{id}/remove", post(apps::remove))
        .route("/apps/{id}/routes", post(apps::add_route))
        .route("/apps/{id}/routes/{rid}/delete", post(apps::delete_route))
        .route("/apps/{id}/routes/{rid}/flag", post(apps::set_route_flag))
        .route("/apps/{id}/secrets", post(apps::put_secret))
        .route("/apps/{id}/secrets/delete", post(apps::delete_secret))
        .route("/apps/{id}/egress", post(apps::set_egress))
        .route("/apps/{id}/scan", post(apps::scan))
        .route("/apps/{id}/apply", post(apps::apply))
        .route("/apps/{id}/env", post(apps::put_env))
        .route("/apps/{id}/env/delete", post(apps::delete_env))
        .route("/apps/{id}/logs/{service}", get(apps::logs))
        .route("/jobs/{id}", get(pages::job))
        .route("/vpn", get(pages::vpn).post(pages::vpn_add))
        .route("/vpn/{id}/delete", post(pages::vpn_delete))
        .route("/vpn/download/{token}", get(pages::vpn_download))
        .route("/registries", get(pages::registries).post(pages::registry_put))
        .route("/registries/{id}/delete", post(pages::registry_delete))
        .route("/server", get(pages::server))
        .route("/server/check-updates", post(pages::check_updates))
        .route("/server/upgrade", post(pages::upgrade))
        .route("/server/reboot", post(pages::reboot))
        .route("/server/unban", post(pages::unban))
        .route("/alerts", get(pages::alerts))
        .route("/alerts/thresholds", post(pages::set_thresholds))
        .route("/alerts/test", post(pages::test_notification))
        .route("/alerts/notify", post(pages::save_notify))
        .route("/events", get(pages::events))
        .route("/server/backup", post(pages::backup_now))
        .route("/server/backup-settings", post(pages::save_backup))
        .route("/server/backup-disable", post(pages::disable_backup))
        .route("/server/falco", post(pages::set_falco))
        .route("/server/upgrade-pocketcloud", post(pages::upgrade_pocketcloud))
        .route("/server/upload-build", post(pages::upload_build).layer(axum::extract::DefaultBodyLimit::max(300 * 1024 * 1024)))
        .route("/server/ssh-keys", post(pages::add_ssh_key))
        .route("/server/ssh-keys/{id}/delete", post(pages::delete_ssh_key))
        .route("/account/password", post(pages::change_password))
        .route("/server/snapshots", post(pages::refresh_snapshots))
        .route("/server/restore", post(pages::restore_import))
        .route("/apps/{id}/restore", post(apps::restore))
        .route("/apps/{id}/backup", post(apps::set_backup))
        .route("/server/renew-certificates", post(pages::renew_certificates))
        .route("/audit", get(pages::audit))
        .route("/health", get(health))
        .route("/static/app.css", get(css))
        .route("/static/app.js", get(js))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(csrf_guard))
        .with_state(state)
}

pub async fn serve(state: Shared, listen: &str) -> Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("interface listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}
