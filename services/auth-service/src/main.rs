use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use phantomgrid_db::{connect, migrate};
use phantomgrid_types::{AuthResponse, HealthResponse, JwtClaims, LoginRequest, RegisterRequest, UserRole};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::{env, fs};
use uuid::Uuid;

#[derive(Clone)]
struct AppState { pool: PgPool, enc: EncodingKey, dec: DecodingKey }

#[derive(Serialize, Deserialize)]
struct RefreshRequest { refresh_token: String }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let database_url = env::var("DATABASE_URL")?;
    let pool = connect(&database_url).await?;
    migrate(&pool).await?;

    let private = fs::read(env::var("JWT_PRIVATE_KEY_PATH")?)?;
    let public = fs::read(env::var("JWT_PUBLIC_KEY_PATH")?)?;

    let state = AppState {
        pool,
        enc: EncodingKey::from_rsa_pem(&private)?,
        dec: DecodingKey::from_rsa_pem(&public)?,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", service: "auth-service", timestamp: Utc::now() })
}

fn role_str(role: &UserRole) -> &'static str {
    match role { UserRole::SuperAdmin => "super_admin", UserRole::TenantAdmin => "tenant_admin", UserRole::Analyst => "analyst", UserRole::Readonly => "readonly" }
}

fn parse_role(s: &str) -> UserRole {
    match s { "super_admin" => UserRole::SuperAdmin, "tenant_admin" => UserRole::TenantAdmin, "analyst" => UserRole::Analyst, _ => UserRole::Readonly }
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt)?.to_string())
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .and_then(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).ok())
        .is_some()
}

fn make_claims(user_id: Uuid, tenant_id: Uuid, role: UserRole, mins: i64) -> JwtClaims {
    let now = Utc::now();
    JwtClaims { sub: user_id, tenant_id, role, iat: now.timestamp() as usize, exp: (now + Duration::minutes(mins)).timestamp() as usize }
}

async fn register(State(st): State<AppState>, Json(req): Json<RegisterRequest>) -> impl IntoResponse {
    let hash = match hash_password(&req.password) { Ok(v) => v, Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response() };
    let q = sqlx::query(
        "INSERT INTO users (tenant_id,email,password_hash,role) VALUES ($1,$2,$3,$4) RETURNING id"
    )
    .bind(req.tenant_id)
    .bind(&req.email)
    .bind(hash)
    .bind(role_str(&req.role));

    match q.fetch_one(&st.pool).await {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn login(State(st): State<AppState>, Json(req): Json<LoginRequest>) -> impl IntoResponse {
    let row = match sqlx::query_as::<_, (Uuid, Uuid, String, String)>("SELECT id, tenant_id, password_hash, role FROM users WHERE email=$1 AND deactivated_at IS NULL")
        .bind(&req.email).fetch_optional(&st.pool).await {
        Ok(Some(v)) => v,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };

    if !verify_password(&req.password, &row.2) { return StatusCode::UNAUTHORIZED.into_response(); }

    let role = parse_role(&row.3);
    let access_claims = make_claims(row.0, row.1, role.clone(), 15);
    let refresh_claims = make_claims(row.0, row.1, role, 60*24*7);

    let access = match encode(&Header::new(jsonwebtoken::Algorithm::RS256), &access_claims, &st.enc) { Ok(t) => t, Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response() };
    let refresh = match encode(&Header::new(jsonwebtoken::Algorithm::RS256), &refresh_claims, &st.enc) { Ok(t) => t, Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response() };

    let refresh_hash = match hash_password(&refresh) { Ok(v) => v, Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response() };
    let _ = sqlx::query("INSERT INTO sessions (user_id, refresh_token_hash, expires_at) VALUES ($1,$2,$3)")
        .bind(row.0).bind(refresh_hash).bind(Utc::now() + Duration::days(7)).execute(&st.pool).await;

    Json(AuthResponse { access_token: access, refresh_token: refresh, token_type: "Bearer".into(), expires_in: 900 }).into_response()
}

async fn refresh(State(st): State<AppState>, Json(req): Json<RefreshRequest>) -> impl IntoResponse {
    let token = match decode::<JwtClaims>(&req.refresh_token, &st.dec, &Validation::new(jsonwebtoken::Algorithm::RS256)) {
        Ok(v) => v.claims,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let sess = sqlx::query_as::<_, (String,)>("SELECT refresh_token_hash FROM sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1")
        .bind(token.sub).fetch_optional(&st.pool).await.ok().flatten();

    let Some((hash,)) = sess else { return StatusCode::UNAUTHORIZED.into_response(); };
    if !verify_password(&req.refresh_token, &hash) { return StatusCode::UNAUTHORIZED.into_response(); }

    let access = match encode(&Header::new(jsonwebtoken::Algorithm::RS256), &make_claims(token.sub, token.tenant_id, token.role, 15), &st.enc) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    Json(serde_json::json!({"access_token": access, "token_type":"Bearer", "expires_in":900})).into_response()
}
