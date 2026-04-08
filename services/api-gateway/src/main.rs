use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use chrono::Utc;
use jsonwebtoken::{decode, DecodingKey, Validation};
use phantomgrid_types::{HealthResponse, JwtClaims, UserRole};
use redis::AsyncCommands;
use serde_json::Value;
use std::{env, fs, net::IpAddr, str::FromStr, sync::OnceLock, time::Instant};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    dec: DecodingKey,
    auth_base: String,
    decoy_base: String,
    event_base: String,
    alert_base: String,
    analytics_base: String,
    mitre_base: String,
    tenant_base: String,
    integrations_base: String,
    realtime_base: String,
    redis_client: redis::Client,
    started_at: Instant,
}

static DECODING_KEY: OnceLock<DecodingKey> = OnceLock::new();
static REDIS_CLIENT: OnceLock<redis::Client> = OnceLock::new();

#[derive(Clone)]
struct AuthContext {
    tid: String,
    role: String,
    jti: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let pub_key = fs::read(env::var("JWT_PUBLIC_KEY_PATH")?)?;
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".into());

    let dec = DecodingKey::from_rsa_pem(&pub_key)?;
    let _ = DECODING_KEY.set(dec.clone());
    let rcli = redis::Client::open(redis_url)?;
    let _ = REDIS_CLIENT.set(rcli.clone());

    let state = AppState {
        dec,
        auth_base: env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://auth-service:8081".into()),
        decoy_base: env::var("DECOY_MANAGER_URL").unwrap_or_else(|_| "http://decoy-manager:8082".into()),
        event_base: env::var("EVENT_STORE_URL").unwrap_or_else(|_| "http://event-processor:8083".into()),
        alert_base: env::var("ALERT_ENGINE_URL").unwrap_or_else(|_| "http://alert-engine:8083".into()),
        analytics_base: env::var("ANALYTICS_URL").unwrap_or_else(|_| "http://analytics:8086".into()),
        mitre_base: env::var("MITRE_MAPPER_URL").unwrap_or_else(|_| "http://mitre-mapper:8084".into()),
        tenant_base: env::var("TENANT_MANAGER_URL").unwrap_or_else(|_| "http://tenant-manager:8088".into()),
        integrations_base: env::var("INTEGRATIONS_URL").unwrap_or_else(|_| "http://integrations:8089".into()),
        realtime_base: env::var("REALTIME_URL").unwrap_or_else(|_| "http://realtime:8085".into()),
        redis_client: rcli,
        started_at: Instant::now(),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/api/v1/sensors/heartbeat", post(sensor_heartbeat))
        .route("/api/v1/auth/*path", any(proxy_auth))
        .route("/api/v1/decoys/*path", any(proxy_decoys))
        .route("/api/v1/networks/*path", any(proxy_decoys))
        .route("/api/v1/events/*path", any(proxy_events))
        .route("/api/v1/alerts/*path", any(proxy_alerts))
        .route("/api/v1/analytics/*path", any(proxy_analytics))
        .route("/api/v1/mitre/*path", any(proxy_mitre))
        .route("/api/v1/tenants/*path", any(proxy_tenants))
        .route("/api/v1/integrations/*path", any(proxy_integrations))
        .route("/ws/*path", any(proxy_realtime))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", service: "api-gateway", timestamp: Utc::now() })
}

async fn gateway_mw(
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if let Err(err) = validate_request(&req).await {
        return err.into_response();
    }

    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let request_id = Uuid::new_v4().to_string();
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert("x-request-id", v);
    }

    // auth endpoints: 10 req/min per IP
    // other endpoints: 1000 req/min per tenant
    if path.starts_with("/api/v1/auth/") {
        let ip = client_ip(req.headers()).unwrap_or_else(|| "unknown".to_string());
        if let Err(err) = apply_rate_limit("auth", &ip, 10).await {
            return err.into_response();
        }
        return next.run(req).await;
    }

    if path == "/health" || path == "/metrics" || path == "/api/v1/sensors/heartbeat" {
        return next.run(req).await;
    }

    let auth = match verify_token(req.headers()).await {
        Ok(v) => v,
        Err(err) => return err.into_response(),
    };
    if let Err(err) = apply_rate_limit("api", &auth.tid, 1000).await {
        return err.into_response();
    }

    if !rbac_allowed(&auth.role, &method, &path, &auth.tid) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": "forbidden" }))).into_response();
    }

    if let Ok(v) = HeaderValue::from_str(&auth.tid) {
        req.headers_mut().insert("x-tenant-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&auth.role) {
        req.headers_mut().insert("x-user-role", v);
    }

    next.run(req).await
}

async fn verify_token(headers: &HeaderMap) -> Result<AuthContext, (StatusCode, Json<Value>)> {
    let header = headers.get("authorization").and_then(|h| h.to_str().ok()).unwrap_or("");
    let token = match header.strip_prefix("Bearer ") {
        Some(v) => v,
        None => return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"missing bearer"}))))
    };

    let dec = DECODING_KEY
        .get()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"jwt key unavailable"}))))?;

    let decoded = decode::<JwtClaims>(token, dec, &Validation::new(jsonwebtoken::Algorithm::RS256))
        .map_err(|_| (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"invalid token"}))))?;

    let now = Utc::now().timestamp() as usize;
    if decoded.claims.exp <= now {
        return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"token expired"}))));
    }

    // optional jti check (supports both jti and session-jti headers fallback)
    let jti = headers.get("x-jti").and_then(|h| h.to_str().ok()).map(ToOwned::to_owned);
    if let Some(ref jti_val) = jti {
        let client = REDIS_CLIENT
            .get()
            .ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"redis unavailable"}))))?;
        let mut con = client.get_multiplexed_async_connection().await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"redis unavailable"}))))?;
        let key = format!("jwt:blacklist:{jti_val}");
        let blacklisted: bool = con.exists(key).await.unwrap_or(false);
        if blacklisted {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"revoked token"}))));
        }
    }

    Ok(AuthContext {
        tid: decoded.claims.tenant_id.to_string(),
        role: role_to_str(&decoded.claims.role).to_string(),
        jti,
    })
}

async fn apply_rate_limit(t: &str, identifier: &str, max_per_min: i64) -> Result<(), (StatusCode, Json<Value>)> {
    let minute = Utc::now().timestamp() / 60;
    let key = format!("rl:{t}:{identifier}:{minute}");
    let client = REDIS_CLIENT
        .get()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"redis unavailable"}))))?;
    let mut con = client.get_multiplexed_async_connection().await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"redis unavailable"}))))?;

    let cnt: i64 = con.incr(&key, 1).await.unwrap_or(1);
    let _: () = con.expire(&key, 120).await.unwrap_or(());

    if cnt > max_per_min {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"error":"rate limit exceeded","retry_after":60})),
        ));
    }
    Ok(())
}

fn role_to_str(role: &UserRole) -> &'static str {
    match role {
        UserRole::SuperAdmin => "super_admin",
        UserRole::TenantAdmin => "tenant_admin",
        UserRole::Analyst => "analyst",
        UserRole::Readonly => "readonly",
    }
}

fn rbac_allowed(role: &str, method: &str, path: &str, _tenant_id: &str) -> bool {
    if role == "super_admin" {
        return true;
    }
    if role == "readonly" {
        return method.eq_ignore_ascii_case("GET");
    }
    if role == "tenant_admin" {
        return true;
    }
    // analyst
    let is_read = method.eq_ignore_ascii_case("GET");
    if is_read {
        return true;
    }

    if path.starts_with("/api/v1/decoys/") || path == "/api/v1/decoys" {
        return true;
    }
    if path.starts_with("/api/v1/alerts/") && (method == "PATCH" || method == "POST") {
        return true;
    }
    false
}

async fn validate_request(req: &Request<Body>) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(q) = req.uri().query() {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "limit" {
                    if let Ok(limit) = v.parse::<u32>() {
                        if limit > 1000 {
                            return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"limit exceeds 1000"}))));
                        }
                    }
                }
            }
        }
    }

    validate_path_uuid(req.uri())?;
    Ok(())
}

fn validate_path_uuid(uri: &Uri) -> Result<(), (StatusCode, Json<Value>)> {
    for seg in uri.path().split('/') {
        if seg.len() == 36 && seg.contains('-') {
            if Uuid::parse_str(seg).is_err() {
                return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid uuid in path"}))));
            }
        }
    }
    Ok(())
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("cf-connecting-ip").and_then(|h| h.to_str().ok()) {
        return Some(v.to_string());
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        return v.split(',').next().map(|s| s.trim().to_string());
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        if IpAddr::from_str(v).is_ok() {
            return Some(v.to_string());
        }
    }
    None
}

async fn sensor_heartbeat() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

async fn metrics(State(st): State<AppState>) -> impl IntoResponse {
    let uptime = st.started_at.elapsed().as_secs();
    let body = format!(
        "# TYPE api_gateway_uptime_seconds gauge\napi_gateway_uptime_seconds {}\n",
        uptime
    );
    (StatusCode::OK, body)
}

async fn proxy_auth(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.auth_base, req, "/api/v1").await
}

async fn proxy_decoys(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.decoy_base, req, "/api/v1").await
}

async fn proxy_events(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.event_base, req, "/api/v1").await
}

async fn proxy_alerts(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.alert_base, req, "/api/v1").await
}

async fn proxy_analytics(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.analytics_base, req, "/api/v1").await
}

async fn proxy_mitre(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.mitre_base, req, "/api/v1").await
}

async fn proxy_tenants(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.tenant_base, req, "/api/v1").await
}

async fn proxy_integrations(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.integrations_base, req, "/api/v1").await
}

async fn proxy_realtime(State(st): State<AppState>, req: Request<Body>) -> impl IntoResponse {
    proxy(st.realtime_base, req, "").await
}

async fn proxy(base: String, req: Request<Body>, strip_prefix: &str) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let headers = req.headers().clone();
    let uri = req.uri().clone();

    let body = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let mut path = uri.path().to_string();
    if !strip_prefix.is_empty() {
        path = path.replacen(strip_prefix, "", 1);
    }
    let url = match uri.query() {
        Some(q) => format!("{}{}?{}", base, path, q),
        None => format!("{}{}", base, path),
    };

    let mut outbound = client.request(method, url).body(body);
    outbound = copy_headers(headers, outbound);

    match outbound.send().await {
        Ok(r) => {
            let status = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let bytes = match r.bytes().await {
                Ok(v) => v,
                Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
            };
            (status, bytes).into_response()
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

fn copy_headers(headers: HeaderMap, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    for (k, v) in &headers {
        if k.as_str().eq_ignore_ascii_case("host") || k.as_str().eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Ok(vs) = v.to_str() {
            req = req.header(k.as_str(), vs);
        }
    }
    req
}
