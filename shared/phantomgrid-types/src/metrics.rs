use prometheus::{opts, CounterVec, Encoder, HistogramOpts, HistogramVec, Registry, TextEncoder};
use std::sync::OnceLock;

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static HTTP_REQUESTS_TOTAL: OnceLock<CounterVec> = OnceLock::new();
static HTTP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

pub fn init_http_metrics() {
    let reg = registry();

    if HTTP_REQUESTS_TOTAL.get().is_none() {
        if let Ok(counter) = CounterVec::new(
            opts!("http_requests_total", "Total HTTP requests"),
            &["method", "route", "status"],
        ) {
            let _ = reg.register(Box::new(counter.clone()));
            let _ = HTTP_REQUESTS_TOTAL.set(counter);
        }
    }

    if HTTP_REQUEST_DURATION_SECONDS.get().is_none() {
        if let Ok(histogram) = HistogramVec::new(
            HistogramOpts::new("http_request_duration_seconds", "HTTP request duration seconds")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["method", "route"],
        ) {
            let _ = reg.register(Box::new(histogram.clone()));
            let _ = HTTP_REQUEST_DURATION_SECONDS.set(histogram);
        }
    }
}

pub fn record_http_request(method: &str, route: &str, status: &str, duration_seconds: f64) {
    if let Some(c) = HTTP_REQUESTS_TOTAL.get() {
        c.with_label_values(&[method, route, status]).inc();
    }
    if let Some(h) = HTTP_REQUEST_DURATION_SECONDS.get() {
        h.with_label_values(&[method, route]).observe(duration_seconds);
    }
}

pub fn gather_metrics() -> String {
    let encoder = TextEncoder::new();
    let mut out = Vec::new();
    if encoder.encode(&registry().gather(), &mut out).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}
