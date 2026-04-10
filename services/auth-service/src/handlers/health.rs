use axum::Json;
use chrono::Utc;
use phantomgrid_types::HealthResponse;

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "auth-service",
        timestamp: Utc::now(),
    })
}
