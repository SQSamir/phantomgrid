use axum::{routing::{get, post}, Router};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sqlx::PgPool;
use std::{env, fs};

mod handlers;
mod middleware;

#[cfg(test)]
mod tests;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub enc: EncodingKey,
    pub dec: DecodingKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let database_url = env::var("DATABASE_URL")?;
    let pool = phantomgrid_db::connect(&database_url).await?;
    phantomgrid_db::migrate(&pool).await?;

    let private = fs::read(env::var("JWT_PRIVATE_KEY_PATH")?)?;
    let public = fs::read(env::var("JWT_PUBLIC_KEY_PATH")?)?;

    let state = AppState {
        pool,
        enc: EncodingKey::from_rsa_pem(&private)?,
        dec: DecodingKey::from_rsa_pem(&public)?,
    };

    let app = Router::new()
        .route("/health", get(handlers::health::health))
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/refresh", post(handlers::auth::refresh))
        .route("/auth/logout", post(handlers::auth::logout))
        .route("/auth/me", get(handlers::auth::me))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
