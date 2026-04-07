use axum::{extract::{Path, State}, routing::{delete, get, post, put}, Json, Router};
use phantomgrid_db::{connect, migrate};
use phantomgrid_types::{Decoy, HealthResponse};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use std::env;
use uuid::Uuid;

#[derive(Clone)]
struct AppState { pool: PgPool }

#[derive(Debug, Deserialize)]
struct NewDecoy {
    tenant_id: Uuid,
    network_id: Option<Uuid>,
    name: String,
    decoy_type: String,
    config: serde_json::Value,
    ip_address: Option<String>,
    port: Option<i32>,
    tags: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();
    let pool = connect(&env::var("DATABASE_URL")?).await?;
    migrate(&pool).await?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/decoys", get(list_decoys).post(create_decoy))
        .route("/decoys/{id}", get(get_decoy).put(update_decoy).delete(delete_decoy))
        .route("/decoys/{id}/deploy", post(deploy_decoy))
        .route("/decoys/{id}/pause", post(pause_decoy))
        .with_state(AppState { pool });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8082").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", service: "decoy-manager", timestamp: chrono::Utc::now() })
}

async fn list_decoys(State(st): State<AppState>) -> Json<Vec<Decoy>> {
    let rows = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>, String, String, serde_json::Value, String, Option<std::net::IpAddr>, Option<i32>, Vec<String>)>(
        "SELECT id,tenant_id,network_id,name,type,config,status,ip_address,port,tags FROM decoys ORDER BY created_at DESC LIMIT 500"
    ).fetch_all(&st.pool).await.unwrap_or_default();

    Json(rows.into_iter().map(|r| Decoy {
        id: r.0, tenant_id: r.1, network_id: r.2, name: r.3, decoy_type: r.4, config: r.5,
        status: r.6, ip_address: r.7.map(|x| x.to_string()), port: r.8, tags: r.9,
    }).collect())
}

async fn create_decoy(State(st): State<AppState>, Json(req): Json<NewDecoy>) -> Json<serde_json::Value> {
    let id = Uuid::new_v4();
    let _ = sqlx::query("INSERT INTO decoys (id,tenant_id,network_id,name,type,config,status,ip_address,port,tags) VALUES ($1,$2,$3,$4,$5,$6,'draft',$7,$8,$9)")
        .bind(id).bind(req.tenant_id).bind(req.network_id).bind(req.name).bind(req.decoy_type)
        .bind(req.config).bind(req.ip_address.and_then(|s| s.parse::<std::net::IpAddr>().ok()))
        .bind(req.port).bind(req.tags.unwrap_or_default())
        .execute(&st.pool).await;
    Json(serde_json::json!({"id": id}))
}

async fn get_decoy(State(st): State<AppState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    let r = sqlx::query("SELECT id,name,type,status,config FROM decoys WHERE id=$1").bind(id).fetch_optional(&st.pool).await.ok().flatten();
    if let Some(row) = r {
        Json(serde_json::json!({"id": row.get::<Uuid,_>("id"), "name": row.get::<String,_>("name"), "type": row.get::<String,_>("type"), "status": row.get::<String,_>("status"), "config": row.get::<serde_json::Value,_>("config")}))
    } else {
        Json(serde_json::json!({"error":"not_found"}))
    }
}

async fn update_decoy(State(st): State<AppState>, Path(id): Path<Uuid>, Json(req): Json<NewDecoy>) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE decoys SET name=$1,type=$2,config=$3,network_id=$4,ip_address=$5,port=$6,tags=$7,updated_at=NOW() WHERE id=$8")
        .bind(req.name).bind(req.decoy_type).bind(req.config).bind(req.network_id)
        .bind(req.ip_address.and_then(|s| s.parse::<std::net::IpAddr>().ok())).bind(req.port).bind(req.tags.unwrap_or_default()).bind(id)
        .execute(&st.pool).await;
    Json(serde_json::json!({"ok":true}))
}

async fn deploy_decoy(State(st): State<AppState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE decoys SET status='active', deployed_at=NOW() WHERE id=$1").bind(id).execute(&st.pool).await;
    Json(serde_json::json!({"ok":true,"status":"active"}))
}

async fn pause_decoy(State(st): State<AppState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE decoys SET status='paused' WHERE id=$1").bind(id).execute(&st.pool).await;
    Json(serde_json::json!({"ok":true,"status":"paused"}))
}

async fn delete_decoy(State(st): State<AppState>, Path(id): Path<Uuid>) -> Json<serde_json::Value> {
    let _ = sqlx::query("UPDATE decoys SET status='destroyed', updated_at=NOW() WHERE id=$1").bind(id).execute(&st.pool).await;
    Json(serde_json::json!({"ok":true,"status":"destroyed"}))
}
