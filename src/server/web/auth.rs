use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use super::{back, html, views, R};
use crate::crypto;
use crate::server::db;
use crate::server::state::Shared;

pub const COOKIE: &str = "pc_session";
const SESSION_HOURS: i64 = 12;

/// A logged-in user. Missing or expired session redirects to the login page.
#[derive(Clone, Debug)]
pub struct User {
    pub username: String,
    pub session_id: String,
}

impl FromRequestParts<Shared> for User {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let Some(c) = jar.get(COOKIE) else {
            return Err(Redirect::to("/login").into_response());
        };
        match db::session(&state.db, c.value()).await {
            Ok(Some(s)) => Ok(User { username: s.username, session_id: s.id }),
            _ => Err(Redirect::to("/login").into_response()),
        }
    }
}

#[derive(Deserialize)]
pub struct Flash {
    pub msg: Option<String>,
    pub error: Option<String>,
}

pub async fn login_page(State(state): State<Shared>, Query(f): Query<Flash>) -> R {
    html(views::LoginPage { error: f.error, name: state.config.name.clone() })
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn login(State(state): State<Shared>, headers: axum::http::HeaderMap, Form(f): Form<LoginForm>) -> R {
    // constant-ish time: hash verification runs even for unknown users
    let user = db::user_by_name(&state.db, f.username.trim()).await?;
    let dummy = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let hash = user.as_ref().map(|u| u.password_hash.as_str()).unwrap_or(dummy);
    let ok = crypto::verify_password(&f.password, hash) && user.is_some();
    if !ok {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        db::audit(&state.db, f.username.trim(), "login.failed", "").await?;
        return Ok(back("/login", None, Some("wrong username or password")));
    }
    let user = user.unwrap();
    let remote = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let session = db::create_session(&state.db, user.id, &remote, SESSION_HOURS).await?;
    db::audit(&state.db, &user.username, "login", &remote).await?;
    let secure = if state.config.dev { "" } else { " Secure;" };
    let cookie = format!("{COOKIE}={}; Path=/; HttpOnly;{secure} SameSite=Strict; Max-Age={}", session.id, SESSION_HOURS * 3600);
    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie)?);
    Ok(resp)
}

pub async fn logout(State(state): State<Shared>, user: User) -> R {
    db::delete_session(&state.db, &user.session_id).await?;
    let mut resp = Redirect::to("/login").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_static("pc_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"));
    Ok(resp)
}
