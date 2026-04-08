use axum::{extract::{Path, State}, routing::get, Json, Router};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone)]
struct AppState { pool: sqlx::PgPool }

#[derive(Deserialize)]
struct TenantReq { name: String }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let pool = phantomgrid_db::connect(&std::env::var("DATABASE_URL")?).await?;
    phantomgrid_db::migrate(&pool).await?;

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/tenants", get(list_tenants).post(create_tenant))
        .route("/tenants/{id}", get(get_tenant).delete(suspend_tenant))
        .with_state(AppState { pool });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8088").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn list_tenants(State(st): State<AppState>) -> Json<serde_json::Value> {
    let rows = sqlx::query("SELECT id,name,plan,created_at,suspended_at FROM tenants ORDER BY created_at DESC")
        .fetch_all(&st.pool).await.unwrap_or_default();
    let out: Vec<_> = rows.into_iter().map(|r| serde_json::json!({
        "id": r.get::<Uuid,_>("id"),
        "name": r.get::<String,_>("name"),
        "plan": r.get::<String,_>("plan"),
        "created_at": r.get::<chrono::DateTime<chrono::Utc>,_>("created_at"),
        "suspended_at": r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("suspended_at")
    })).collect();
    Json(serde_json::json!({"items": out}))
}

async fn create_tenant(State(st): State<AppState>, Json(req): Json<TenantReq>) -> Json<serde_json::Value> {
    let id = Uuid::new_v4();
    let _ = sqlx::query("INSERT INTO tenants (id,name) VALUES ($1,$2)").bind(id).bind(req.name).execute(&st.pool).await;
    Json(serde_json::json!({"id": id}))
}

async fn get_tenant(State(st): State<AppState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    let r = sqlx::query("SELECT id,name,plan,max_decoys,max_events_per_day,suspended_at FROM tenants WHERE id=$1")
        .bind(id).fetch_optional(&st.pool).await.ok().flatten();
    match r {
        Some(r) => Json(serde_json::json!({
            "id": r.get::<Uuid,_>("id"), "name": r.get::<String,_>("name"), "plan": r.get::<String,_>("plan"),
            "max_decoys": r.get::<i32,_>("max_decoys"), "max_events_per_day": r.get::<i64,_>("max_events_per_day"),
            "suspended_at": r.get::<Option<chrono::DateTime<chrono::Utc>>,_>("suspended_at")
        })),
        None => Json(serde_json::json!({"error":"not_found"})),
    }
}

async fn suspend_tenant(State(st): State<AppState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE tenants SET suspended_at=NOW() WHERE id=$1").bind(id).execute(&st.pool).await;
    Json(serde_json::json!({"ok":true}))
}
