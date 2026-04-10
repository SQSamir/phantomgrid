use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, Json};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm as JwtAlgorithm, Header};
use phantomgrid_types::{AuthResponse, JwtClaims, LoginRequest, RegisterRequest, UserRole};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{middleware::jwt::ValidatedClaims, AppState};

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    id: Uuid,
    email: Option<String>,
    role: String,
    tenant_id: Uuid,
}

fn role_to_str(role: &UserRole) -> &'static str {
    match role {
        UserRole::SuperAdmin => "super_admin",
        UserRole::TenantAdmin => "tenant_admin",
        UserRole::Analyst => "analyst",
        UserRole::Readonly => "readonly",
    }
}

fn role_from_str(s: &str) -> UserRole {
    match s {
        "super_admin" => UserRole::SuperAdmin,
        "tenant_admin" => UserRole::TenantAdmin,
        "analyst" => UserRole::Analyst,
        _ => UserRole::Readonly,
    }
}

fn is_valid_email(email: &str) -> bool {
    let has_at = email.contains('@');
    let has_dot = email.rsplit('@').next().map(|v| v.contains('.')).unwrap_or(false);
    has_at && has_dot && email.len() <= 320
}

fn argon2_hasher() -> Argon2<'static> {
    let params = Params::new(65536, 3, 4, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2_hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash failed: {e}"))?
        .to_string();
    Ok(hash)
}

fn verify_password_constant_time(password: &str, password_hash: &str) -> bool {
    let parsed = match PasswordHash::new(password_hash) {
        Ok(v) => v,
        Err(_) => return false,
    };
    argon2_hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn make_jwt_claims(user_id: Uuid, tenant_id: Uuid, role: UserRole, ttl_seconds: i64) -> JwtClaims {
    let now = Utc::now().timestamp() as usize;
    JwtClaims {
        sub: user_id,
        tenant_id,
        role,
        iat: now,
        exp: (Utc::now() + Duration::seconds(ttl_seconds)).timestamp() as usize,
        jti: Some(Uuid::new_v4().to_string()),
    }
}

fn make_refresh_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

pub async fn register(State(st): State<AppState>, Json(req): Json<RegisterRequest>) -> impl IntoResponse {
    if !is_valid_email(&req.email) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid email"}))).into_response();
    }

    let password_hash = match hash_password(&req.password) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let result = sqlx::query(
        "INSERT INTO users (tenant_id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
    )
    .bind(req.tenant_id)
    .bind(req.email)
    .bind(password_hash)
    .bind(role_to_str(&req.role))
    .execute(&st.pool)
    .await;

    match result {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"user create failed"}))).into_response(),
    }
}

pub async fn login(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let row = match sqlx::query_as::<_, (Uuid, Uuid, String, String, i32, Option<chrono::DateTime<Utc>>)>(
        "SELECT id, tenant_id, password_hash, role, failed_login_attempts, locked_until FROM users WHERE email = $1",
    )
    .bind(&req.email)
    .fetch_optional(&st.pool)
    .await
    {
        Ok(Some(v)) => v,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if row.5.map(|v| v > Utc::now()).unwrap_or(false) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    if !verify_password_constant_time(&req.password, &row.2) {
        let failed = row.4 + 1;
        if failed >= 5 {
            let _ = sqlx::query(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NOW() + INTERVAL '15 minutes' WHERE id = $1",
            )
            .bind(row.0)
            .execute(&st.pool)
            .await;
        } else {
            let _ = sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, locked_until = NULL WHERE id = $2",
            )
            .bind(failed)
            .bind(row.0)
            .execute(&st.pool)
            .await;
        }
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let _ = sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1",
    )
    .bind(row.0)
    .execute(&st.pool)
    .await;

    let role = role_from_str(&row.3);
    let access_claims = make_jwt_claims(row.0, row.1, role.clone(), 900);
    let access_token = match encode(&Header::new(JwtAlgorithm::RS256), &access_claims, &st.enc) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let refresh_token = make_refresh_token();
    let refresh_hash = sha256_hex(&refresh_token);

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let expires_at = Utc::now() + Duration::days(7);
    let _ = sqlx::query(
        "INSERT INTO sessions (user_id, refresh_token_hash, ip_address, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(row.0)
    .bind(refresh_hash)
    .bind(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("").split(",").next().unwrap_or("").trim().to_string())
    .bind(user_agent)
    .bind(expires_at)
    .execute(&st.pool)
    .await;

    Json(AuthResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
    })
    .into_response()
}

pub async fn refresh(State(st): State<AppState>, Json(req): Json<RefreshRequest>) -> impl IntoResponse {
    let refresh_hash = sha256_hex(&req.refresh_token);

    let session = match sqlx::query_as::<_, (Uuid, chrono::DateTime<Utc>)>(
        "SELECT user_id, expires_at FROM sessions WHERE refresh_token_hash = $1",
    )
    .bind(&refresh_hash)
    .fetch_optional(&st.pool)
    .await
    {
        Ok(Some(v)) => v,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if session.1 <= Utc::now() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let user = match sqlx::query_as::<_, (Uuid, String)>("SELECT tenant_id, role FROM users WHERE id = $1")
        .bind(session.0)
        .fetch_optional(&st.pool)
        .await
    {
        Ok(Some(v)) => v,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let _ = sqlx::query("DELETE FROM sessions WHERE refresh_token_hash = $1")
        .bind(&refresh_hash)
        .execute(&st.pool)
        .await;

    let role = role_from_str(&user.1);
    let access_claims = make_jwt_claims(session.0, user.0, role.clone(), 900);
    let access_token = match encode(&Header::new(JwtAlgorithm::RS256), &access_claims, &st.enc) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let new_refresh_token = make_refresh_token();
    let new_refresh_hash = sha256_hex(&new_refresh_token);
    let expires_at = Utc::now() + Duration::days(7);

    let _ = sqlx::query(
        "INSERT INTO sessions (user_id, refresh_token_hash, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(session.0)
    .bind(new_refresh_hash)
    .bind(expires_at)
    .execute(&st.pool)
    .await;

    Json(AuthResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
    })
    .into_response()
}

pub async fn logout(State(st): State<AppState>, Json(req): Json<LogoutRequest>) -> impl IntoResponse {
    let refresh_hash = sha256_hex(&req.refresh_token);
    let _ = sqlx::query("DELETE FROM sessions WHERE refresh_token_hash = $1")
        .bind(refresh_hash)
        .execute(&st.pool)
        .await;
    StatusCode::NO_CONTENT
}

pub async fn me(ValidatedClaims(claims): ValidatedClaims) -> impl IntoResponse {
    Json(MeResponse {
        id: claims.sub,
        email: None,
        role: role_to_str(&claims.role).to_string(),
        tenant_id: claims.tenant_id,
    })
}
