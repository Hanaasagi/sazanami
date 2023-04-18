use std::net::SocketAddr;
use std::time::Duration;

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio_metrics::TaskMetrics;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing_subscriber::registry;

use crate::metrics::{self, get_metrics_registry};

// FIXME: serde remote is not work?
// https://serde.rs/remote-derive.html
#[derive(Serialize)]
struct TaskMetricsDef {
    pub instrumented_count: u64,
    pub dropped_count: u64,
    pub first_poll_count: u64,
    pub total_first_poll_delay: Duration,
    pub total_idled_count: u64,
    pub total_idle_duration: Duration,
    pub total_scheduled_count: u64,
    pub total_scheduled_duration: Duration,
    pub total_poll_count: u64,
    pub total_poll_duration: Duration,
    pub total_fast_poll_count: u64,
    pub total_fast_poll_duration: Duration,
    pub total_slow_poll_count: u64,
    pub total_slow_poll_duration: Duration,
    pub total_short_delay_count: u64,
    pub total_long_delay_count: u64,
    pub total_short_delay_duration: Duration,
    pub total_long_delay_duration: Duration,
}

impl From<TaskMetrics> for TaskMetricsDef {
    fn from(item: TaskMetrics) -> Self {
        Self {
            instrumented_count: item.instrumented_count,
            dropped_count: item.dropped_count,
            first_poll_count: item.first_poll_count,
            total_first_poll_delay: item.total_first_poll_delay,
            total_idled_count: item.total_idled_count,
            total_idle_duration: item.total_idle_duration,
            total_scheduled_count: item.total_scheduled_count,
            total_scheduled_duration: item.total_scheduled_duration,
            total_poll_count: item.total_poll_count,
            total_poll_duration: item.total_poll_duration,
            total_fast_poll_count: item.total_fast_poll_count,
            total_fast_poll_duration: item.total_fast_poll_duration,
            total_slow_poll_count: item.total_slow_poll_count,
            total_slow_poll_duration: item.total_slow_poll_duration,
            total_short_delay_count: item.total_short_delay_count,
            total_long_delay_count: item.total_long_delay_count,
            total_short_delay_duration: item.total_short_delay_duration,
            total_long_delay_duration: item.total_long_delay_duration,
        }
    }
}

pub struct ApiServer {
    /// Listen address
    listen_at: SocketAddr,
    service: Router,
}

impl ApiServer {
    pub async fn new(listen_at: SocketAddr) -> Self {
        let router = Router::new().route("/metrics", get(metrics));

        Self {
            listen_at,
            service: router,
        }
    }

    pub async fn serve(self) -> anyhow::Result<()> {
        axum::Server::bind(&self.listen_at)
            .serve(self.service.into_make_service())
            .await?;
        Ok(())
    }

    pub fn listen_at(&self) -> SocketAddr {
        self.listen_at
    }
}

async fn metrics() -> Result<Json<TaskMetricsDef>, (StatusCode, &'static str)> {
    let mut registry = metrics::get_metrics_registry().lock().await;

    if let Some(metrics) = registry.get_metrics("proxy").await {
        Ok(Json(metrics.into()))
    } else {
        Err((StatusCode::INTERNAL_SERVER_ERROR, "Could not fetch metrics"))
    }
}
